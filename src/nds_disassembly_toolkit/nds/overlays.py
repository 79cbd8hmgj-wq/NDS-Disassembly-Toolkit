from __future__ import annotations

from dataclasses import dataclass

from nds_disassembly_toolkit.errors import RomFormatError
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.util import Buffer, read_u32_le, require_range

OVERLAY_ENTRY_SIZE = 32


@dataclass(frozen=True)
class OverlayEntry:
    overlay_id: int
    ram_address: int
    ram_size: int
    bss_size: int
    static_init_start: int
    static_init_end: int
    file_id: int
    reserved: int

    @property
    def compressed_size(self) -> int:
        return self.reserved & 0x00FFFFFF

    @property
    def flags(self) -> int:
        return self.reserved >> 24

    @property
    def ram_end(self) -> int:
        return self.ram_address + self.ram_size + self.bss_size


def parse_overlay_table(
    data: Buffer,
    offset: int,
    size: int,
    table_name: str,
) -> tuple[OverlayEntry, ...]:
    if size == 0:
        return ()
    if size % OVERLAY_ENTRY_SIZE != 0:
        raise RomFormatError(
            f"{table_name} size must be a multiple of {OVERLAY_ENTRY_SIZE}, got {size}"
        )
    table = require_range(data, offset, size, table_name)
    entries: list[OverlayEntry] = []
    seen_ids: set[int] = set()
    for index in range(size // OVERLAY_ENTRY_SIZE):
        base = index * OVERLAY_ENTRY_SIZE
        values = tuple(
            read_u32_le(table, base + field * 4, f"{table_name} entry {index} field {field}")
            for field in range(8)
        )
        entry = OverlayEntry(*values)
        if entry.overlay_id in seen_ids:
            raise RomFormatError(f"{table_name} contains duplicate overlay ID {entry.overlay_id}")
        seen_ids.add(entry.overlay_id)
        executable_end = entry.ram_address + entry.ram_size
        has_no_initializer = entry.static_init_start == 0 and entry.static_init_end == 0
        initializer_is_valid = (
            entry.ram_address
            <= entry.static_init_start
            <= entry.static_init_end
            <= executable_end
        )
        if not has_no_initializer and not initializer_is_valid:
            raise RomFormatError(
                f"{table_name} overlay {entry.overlay_id} static initializer range "
                f"0x{entry.static_init_start:X}..0x{entry.static_init_end:X} "
                f"is outside executable RAM range 0x{entry.ram_address:X}..0x{executable_end:X}"
            )
        entries.append(entry)
    return tuple(entries)


def parse_arm9_overlays(data: Buffer, header: NdsHeader) -> tuple[OverlayEntry, ...]:
    return parse_overlay_table(
        data,
        header.arm9_overlay_offset,
        header.arm9_overlay_size,
        "ARM9 overlay table",
    )


def parse_arm7_overlays(data: Buffer, header: NdsHeader) -> tuple[OverlayEntry, ...]:
    return parse_overlay_table(
        data,
        header.arm7_overlay_offset,
        header.arm7_overlay_size,
        "ARM7 overlay table",
    )
