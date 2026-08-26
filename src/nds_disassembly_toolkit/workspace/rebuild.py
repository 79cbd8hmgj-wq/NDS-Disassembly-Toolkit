from __future__ import annotations

import itertools
import json
import struct
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from nds_disassembly_toolkit.compression.lz10 import compress_lz10
from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.nds.fat import parse_fat
from nds_disassembly_toolkit.nds.fnt import parse_fnt
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.nds.overlays import parse_arm7_overlays, parse_arm9_overlays
from nds_disassembly_toolkit.profile import RomProfile
from nds_disassembly_toolkit.workspace.manifest import sha256_bytes
from nds_disassembly_toolkit.workspace.overrides import OverlayLayoutOverride
from nds_disassembly_toolkit.workspace.validate import ValidatedWorkspace, validate_workspace


@dataclass(frozen=True)
class RebuildOptions:
    output: Path
    force: bool = False


@dataclass(frozen=True)
class BuildChange:
    kind: str
    identifier: str
    original_sha256: str
    modified_sha256: str
    encoding: str


@dataclass(frozen=True)
class BuildReport:
    format_version: int
    profile_id: str | None
    source_sha256: str
    output_sha256: str
    output_size: int
    exact_copy: bool
    changes: tuple[BuildChange, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "profile_id": self.profile_id,
            "source_sha256": self.source_sha256,
            "output_sha256": self.output_sha256,
            "output_size": self.output_size,
            "exact_copy": self.exact_copy,
            "changes": [asdict(item) for item in self.changes],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _read_modified_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise WorkspaceError(f"cannot read modified {label}: {path}") from exc


def _build_payloads(
    validated: ValidatedWorkspace,
) -> tuple[dict[int, bytes], tuple[BuildChange, ...]]:
    layout = validated.layout
    changed = {(item.kind, item.identifier): item for item in validated.changes}
    raw_overrides = {
        item.file_id: item
        for item in (validated.overrides.raw_nitrofs if validated.overrides else ())
    }
    overlay_overrides = {
        item.overlay_id: item
        for item in (validated.overrides.overlays if validated.overrides else ())
    }
    payloads: dict[int, bytes] = {}
    build_changes: list[BuildChange] = []

    for entry in validated.manifest.files:
        key = ("nitrofs", entry.path)
        relative_path = Path(*entry.path.split("/"))
        raw_override = raw_overrides.get(entry.file_id)
        if raw_override is not None:
            payload = _read_modified_bytes(
                layout.modified_raw_nitrofs / relative_path,
                f"raw override NitroFS file {entry.path}",
            )
            change = changed[("nitrofs_raw", entry.path)]
            build_changes.append(
                BuildChange(
                    kind=change.kind,
                    identifier=change.identifier,
                    original_sha256=change.original_sha256,
                    modified_sha256=change.modified_sha256,
                    encoding="raw-override",
                )
            )
        elif key in changed:
            decoded = _read_modified_bytes(layout.modified_nitrofs / relative_path, entry.path)
            if entry.compression == "lz10":
                try:
                    payload = compress_lz10(decoded)
                except ValueError as exc:
                    raise WorkspaceError(f"cannot encode LZ10 file {entry.path}: {exc}") from exc
                encoding = "lz10"
            else:
                payload = decoded
                encoding = "raw"
            change = changed[key]
            build_changes.append(
                BuildChange(
                    kind=change.kind,
                    identifier=change.identifier,
                    original_sha256=change.original_sha256,
                    modified_sha256=change.modified_sha256,
                    encoding=encoding,
                )
            )
        else:
            payload = _read_modified_bytes(
                layout.original_raw_nitrofs / relative_path,
                f"original raw NitroFS file {entry.path}",
            )
        payloads[entry.file_id] = payload

    for overlay_entry in validated.manifest.overlays:
        key = ("overlay", str(overlay_entry.overlay_id))
        filename = f"overlay_{overlay_entry.overlay_id:03d}.bin"
        if key in changed:
            payload = _read_modified_bytes(
                layout.modified_overlays / filename,
                f"overlay {overlay_entry.overlay_id}",
            )
            overlay_override = overlay_overrides.get(overlay_entry.overlay_id)
            expected_size = (
                overlay_override.replacement_ram_size
                if overlay_override is not None
                else overlay_entry.ram_size
            )
            if len(payload) != expected_size:
                raise WorkspaceError(
                    f"modified overlay {overlay_entry.overlay_id} size mismatch: "
                    f"expected {expected_size}, got {len(payload)}"
                )
            change = changed[key]
            build_changes.append(
                BuildChange(
                    kind=change.kind,
                    identifier=change.identifier,
                    original_sha256=change.original_sha256,
                    modified_sha256=change.modified_sha256,
                    encoding="uncompressed-overlay",
                )
            )
        else:
            payload = _read_modified_bytes(
                layout.original_raw_overlays / filename,
                f"original raw overlay {overlay_entry.overlay_id}",
            )
        payloads[overlay_entry.file_id] = payload

    for kind in ("arm9", "arm7"):
        key = (kind, kind)
        if key in changed:
            change = changed[key]
            build_changes.append(
                BuildChange(
                    kind=change.kind,
                    identifier=change.identifier,
                    original_sha256=change.original_sha256,
                    modified_sha256=change.modified_sha256,
                    encoding="raw",
                )
            )

    expected_ids = {entry.file_id for entry in validated.inspection.fat}
    if set(payloads) != expected_ids:
        missing = sorted(expected_ids - set(payloads))
        extra = sorted(set(payloads) - expected_ids)
        raise WorkspaceError(
            f"workspace FAT payload mapping mismatch; missing={missing}, extra={extra}"
        )

    order = {"arm9": 0, "arm7": 1, "nitrofs": 2, "nitrofs_raw": 3, "overlay": 4}
    return payloads, tuple(
        sorted(build_changes, key=lambda item: (order[item.kind], item.identifier))
    )


def _write_overlay_layout_override(
    output: bytearray,
    table_offset: int,
    table_index: int,
    override: OverlayLayoutOverride,
) -> None:
    base = table_offset + table_index * 32
    struct.pack_into("<I", output, base + 0x08, override.replacement_ram_size)
    struct.pack_into("<I", output, base + 0x0C, override.replacement_bss_size)
    struct.pack_into("<I", output, base + 0x1C, override.replacement_flags << 24)


def _apply_changed_overlay_metadata(
    output: bytearray,
    validated: ValidatedWorkspace,
) -> None:
    changed_overlay_ids = {
        int(item.identifier) for item in validated.changes if item.kind == "overlay"
    }
    if not changed_overlay_ids:
        return
    overrides = {
        item.overlay_id: item
        for item in (validated.overrides.overlays if validated.overrides else ())
    }
    tables = (
        (
            validated.inspection.header.arm9_overlay_offset,
            validated.inspection.arm9_overlays,
        ),
        (
            validated.inspection.header.arm7_overlay_offset,
            validated.inspection.arm7_overlays,
        ),
    )
    for table_offset, entries in tables:
        for index, entry in enumerate(entries):
            if entry.overlay_id not in changed_overlay_ids:
                continue
            override = overrides.get(entry.overlay_id)
            if override is not None:
                _write_overlay_layout_override(output, table_offset, index, override)
            else:
                preserved_flags = entry.flags & ~1
                struct.pack_into(
                    "<I",
                    output,
                    table_offset + index * 32 + 28,
                    preserved_flags << 24,
                )


def _verify_structure(output: bytes, validated: ValidatedWorkspace) -> None:
    header = NdsHeader.from_bytes(output)
    source_header = validated.inspection.header
    if (
        header.title,
        header.game_code,
        header.maker_code,
        header.revision,
        len(output),
    ) != (
        source_header.title,
        source_header.game_code,
        source_header.maker_code,
        source_header.revision,
        validated.manifest.rom_size,
    ):
        raise WorkspaceError("rebuilt ROM identity or size changed unexpectedly")

    fat = parse_fat(output, header)
    if len(fat) != len(validated.inspection.fat):
        raise WorkspaceError("rebuilt FAT entry count changed")
    fnt = parse_fnt(output, header, len(fat))
    if {(item.file_id, item.path) for item in fnt.files} != {
        (item.file_id, item.path) for item in validated.inspection.fnt.files
    }:
        raise WorkspaceError("rebuilt FNT mapping changed")
    arm9_overlays = parse_arm9_overlays(output, header)
    arm7_overlays = parse_arm7_overlays(output, header)
    if len(arm9_overlays) != len(validated.inspection.arm9_overlays) or len(arm7_overlays) != len(
        validated.inspection.arm7_overlays
    ):
        raise WorkspaceError("rebuilt overlay count changed")
    rebuilt_overlays = {item.overlay_id: item for item in (*arm9_overlays, *arm7_overlays)}
    for override in validated.overrides.overlays if validated.overrides else ():
        rebuilt = rebuilt_overlays.get(override.overlay_id)
        if rebuilt is None:
            raise WorkspaceError(f"rebuilt overlay override {override.overlay_id} is missing")
        if (
            rebuilt.ram_size,
            rebuilt.bss_size,
            rebuilt.flags,
        ) != (
            override.replacement_ram_size,
            override.replacement_bss_size,
            override.replacement_flags,
        ):
            raise WorkspaceError(f"rebuilt overlay override {override.overlay_id} geometry changed")

    physical = sorted(fat, key=lambda item: (item.start, item.file_id))
    for entry in physical:
        if entry.start % 0x200 != 0:
            raise WorkspaceError(f"rebuilt FAT file {entry.file_id} is not 0x200-aligned")
    for previous, current in itertools.pairwise(physical):
        if current.start < previous.end:
            raise WorkspaceError(
                f"rebuilt FAT files overlap: {previous.file_id} and {current.file_id}"
            )


def _assemble_changed_rom(
    source_data: bytes,
    validated: ValidatedWorkspace,
    payloads: dict[int, bytes],
) -> bytes:
    output = bytearray(source_data)
    header = validated.inspection.header

    modified_arm9 = _read_modified_bytes(validated.layout.modified / "arm9.bin", "ARM9")
    modified_arm7 = _read_modified_bytes(validated.layout.modified / "arm7.bin", "ARM7")
    if len(modified_arm9) != header.arm9_size:
        raise WorkspaceError(
            f"modified ARM9 size mismatch: expected {header.arm9_size}, got {len(modified_arm9)}"
        )
    if len(modified_arm7) != header.arm7_size:
        raise WorkspaceError(
            f"modified ARM7 size mismatch: expected {header.arm7_size}, got {len(modified_arm7)}"
        )
    output[header.arm9_offset : header.arm9_offset + header.arm9_size] = modified_arm9
    output[header.arm7_offset : header.arm7_offset + header.arm7_size] = modified_arm7

    named_ids = {item.file_id for item in validated.inspection.fnt.files}
    named_starts = [entry.start for entry in validated.inspection.fat if entry.file_id in named_ids]
    if not named_starts:
        raise WorkspaceError("source ROM has no named FAT payloads to anchor rebuilding")
    cursor = min(named_starts)

    for entry in validated.inspection.fat:
        output[entry.start : entry.end] = b"\xff" * entry.size

    for entry in sorted(validated.inspection.fat, key=lambda item: (item.start, item.file_id)):
        cursor = _align(cursor, 0x200)
        payload = payloads[entry.file_id]
        end = cursor + len(payload)
        if end > len(output):
            raise WorkspaceError(
                f"rebuilt FAT payloads exceed ROM capacity at file {entry.file_id}: "
                f"need 0x{end:X}, capacity is 0x{len(output):X}"
            )
        output[cursor:end] = payload
        struct.pack_into("<II", output, header.fat_offset + entry.file_id * 8, cursor, end)
        cursor = end

    _apply_changed_overlay_metadata(output, validated)
    rebuilt = bytes(output)
    _verify_structure(rebuilt, validated)
    return rebuilt


def rebuild_rom(
    source_rom: Path,
    workspace: Path,
    options: RebuildOptions,
    *,
    profile: RomProfile | None = None,
    require_supported: bool = False,
) -> BuildReport:
    output_path = options.output.expanduser().resolve()
    report_path = output_path.with_suffix(output_path.suffix + ".build.json")
    if (output_path.exists() or report_path.exists()) and not options.force:
        raise WorkspaceError(f"output already exists: {output_path}")

    validated = validate_workspace(
        source_rom,
        workspace,
        profile=profile,
        require_supported=require_supported,
    )
    try:
        source_data = source_rom.read_bytes()
    except OSError as exc:
        raise WorkspaceError(f"cannot read source ROM {source_rom}: {exc}") from exc

    if validated.has_changes:
        payloads, changes = _build_payloads(validated)
        output_data = _assemble_changed_rom(source_data, validated, payloads)
        exact_copy = False
    else:
        output_data = source_data
        changes = ()
        exact_copy = True

    report = BuildReport(
        format_version=1,
        profile_id=validated.manifest.profile_id,
        source_sha256=validated.manifest.rom_sha256,
        output_sha256=sha256_bytes(output_data),
        output_size=len(output_data),
        exact_copy=exact_copy,
        changes=changes,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        prefix=f".{output_path.name}.tmp-", dir=output_path.parent, delete=False
    )
    output_temp = Path(output_handle.name)
    output_handle.close()
    report_handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        prefix=f".{report_path.name}.tmp-", dir=report_path.parent, delete=False
    )
    report_temp = Path(report_handle.name)
    report_handle.close()
    try:
        output_temp.write_bytes(output_data)
        report_temp.write_text(report.to_json(), encoding="utf-8")
        output_temp.replace(output_path)
        report_temp.replace(report_path)
    except Exception:
        output_temp.unlink(missing_ok=True)
        report_temp.unlink(missing_ok=True)
        raise
    return report
