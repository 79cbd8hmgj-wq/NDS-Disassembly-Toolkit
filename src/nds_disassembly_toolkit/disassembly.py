from __future__ import annotations

import struct
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from difflib import unified_diff
from itertools import pairwise
from pathlib import Path

from nds_disassembly_toolkit.errors import DisassemblyError
from nds_disassembly_toolkit.nds.overlays import OverlayEntry

MODULE_PARAMS_MAGIC = 0xDEC00621
MODULE_PARAMS_TRAILING_MAGIC = 0x2106C0DE
MODULE_PARAMS_SIZE = 36
MODULE_PARAMS_MAGIC_OFFSET = 28


@dataclass(frozen=True)
class ModuleParams:
    offset: int
    address: int
    autoload_list_start: int
    autoload_list_end: int
    autoload_start: int
    static_bss_start: int
    static_bss_end: int
    compressed_static_end: int
    sdk_version: int


def find_module_params(
    data: bytes | bytearray | memoryview,
    *,
    base_address: int = 0,
) -> ModuleParams | None:
    source = bytes(data)
    signature = struct.pack("<II", MODULE_PARAMS_MAGIC, MODULE_PARAMS_TRAILING_MAGIC)
    candidates: list[int] = []
    cursor = 0
    while True:
        magic_offset = source.find(signature, cursor)
        if magic_offset < 0:
            break
        start = magic_offset - MODULE_PARAMS_MAGIC_OFFSET
        if start >= 0 and start % 4 == 0 and start + MODULE_PARAMS_SIZE <= len(source):
            candidates.append(start)
        cursor = magic_offset + 1

    if not candidates:
        return None
    if len(candidates) > 1:
        raise ValueError(f"multiple aligned Nitro module-parameter blocks found: {candidates}")

    start = candidates[0]
    (
        autoload_list_start,
        autoload_list_end,
        autoload_start,
        static_bss_start,
        static_bss_end,
        compressed_static_end,
        sdk_version,
        magic_word,
    ) = struct.unpack_from("<8I", source, start)
    if magic_word != MODULE_PARAMS_MAGIC:
        raise AssertionError("module-parameter magic changed during parsing")
    return ModuleParams(
        offset=start,
        address=base_address + start,
        autoload_list_start=autoload_list_start,
        autoload_list_end=autoload_list_end,
        autoload_start=autoload_start,
        static_bss_start=static_bss_start,
        static_bss_end=static_bss_end,
        compressed_static_end=compressed_static_end,
        sdk_version=sdk_version,
    )


def overlay_layout_report(
    overlays: Sequence[OverlayEntry],
    *,
    static_end: int | None = None,
) -> dict[str, object]:
    ordered = sorted(overlays, key=lambda item: item.overlay_id)
    after_static = [
        item.overlay_id
        for item in ordered
        if static_end is not None and item.ram_address == static_end
    ]

    starts: dict[int, list[int]] = {}
    for item in ordered:
        starts.setdefault(item.ram_address, []).append(item.overlay_id)
    shared_start_groups = [
        {"ram_address": address, "overlay_ids": ids}
        for address, ids in sorted(starts.items())
        if len(ids) > 1
    ]

    relations: list[dict[str, int]] = []
    for current in ordered:
        for predecessor in ordered:
            if current.overlay_id == predecessor.overlay_id:
                continue
            if current.ram_address == predecessor.ram_end:
                relations.append(
                    {
                        "overlay_id": current.overlay_id,
                        "after_overlay_id": predecessor.overlay_id,
                    }
                )

    return {
        "static_end": static_end,
        "after_static": after_static,
        "shared_start_groups": shared_start_groups,
        "load_relations": relations,
        "overlays": [
            {
                "overlay_id": item.overlay_id,
                "ram_address": item.ram_address,
                "ram_size": item.ram_size,
                "bss_size": item.bss_size,
                "ram_end": item.ram_end,
                "static_init_start": item.static_init_start,
                "static_init_end": item.static_init_end,
                "file_id": item.file_id,
                "reserved": item.reserved,
            }
            for item in ordered
        ],
    }


def _format_byte_row(row: bytes) -> str:
    return "\t.byte " + ", ".join(f"0x{byte:02X}" for byte in row)


def render_labelled_bytes(
    data: bytes | bytearray | memoryview,
    *,
    labels: Iterable[int],
    base_address: int,
) -> str:
    source = bytes(data)
    end_address = base_address + len(source)
    requested = sorted(set(labels))
    for address in requested:
        if not base_address <= address < end_address:
            raise ValueError(f"label 0x{address:X} is outside component")

    boundaries = sorted({base_address, *requested, end_address})
    lines: list[str] = []
    for start, end in pairwise(boundaries):
        lines.append(f"_{start:08X}:")
        start_offset = start - base_address
        end_offset = end - base_address
        for cursor in range(start_offset, end_offset, 16):
            lines.append(_format_byte_row(source[cursor : min(cursor + 16, end_offset)]))
    return "\n".join(lines) + "\n"


def build_objdump_command(
    binary: str | Path,
    *,
    base_address: int,
    start_address: int | None = None,
    stop_address: int | None = None,
    thumb: bool = False,
    processor: str = "armv5te",
    executable: str = "arm-none-eabi-objdump",
) -> tuple[str, ...]:
    if base_address < 0:
        raise ValueError("base address must be non-negative")
    if start_address is not None and start_address < base_address:
        raise ValueError("start address is before component base")
    if stop_address is not None and stop_address < base_address:
        raise ValueError("stop address is before component base")
    if stop_address is not None and start_address is not None and stop_address < start_address:
        raise ValueError("stop address is before start address")

    command = [executable, "-D", "-r", "-z", "-b", "binary", "-m", processor]
    if thumb:
        command.append("-Mforce-thumb")
    command.append(f"--adjust-vma=0x{base_address:x}")
    if start_address is not None:
        command.append(f"--start-address=0x{start_address:x}")
    if stop_address is not None:
        command.append(f"--stop-address=0x{stop_address:x}")
    command.append(str(binary))
    return tuple(command)


def disassemble_binary(
    binary: str | Path,
    *,
    base_address: int,
    start_address: int | None = None,
    stop_address: int | None = None,
    thumb: bool = False,
    processor: str = "armv5te",
    executable: str = "arm-none-eabi-objdump",
) -> str:
    command = build_objdump_command(
        binary,
        base_address=base_address,
        start_address=start_address,
        stop_address=stop_address,
        thumb=thumb,
        processor=processor,
        executable=executable,
    )
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise DisassemblyError(f"cannot execute objdump {executable!r}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown objdump error"
        raise DisassemblyError(
            f"objdump failed with exit code {completed.returncode}: {detail}"
        )
    return completed.stdout


def unified_disassembly_diff(
    reference: str,
    candidate: str,
    *,
    reference_name: str = "reference",
    candidate_name: str = "candidate",
) -> str:
    return "".join(
        unified_diff(
            reference.splitlines(keepends=True),
            candidate.splitlines(keepends=True),
            fromfile=reference_name,
            tofile=candidate_name,
            lineterm="\n",
        )
    )
