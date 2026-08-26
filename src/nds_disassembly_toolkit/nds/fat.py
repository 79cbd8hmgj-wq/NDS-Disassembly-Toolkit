from __future__ import annotations

from dataclasses import dataclass

from nds_disassembly_toolkit.errors import BoundsError, RomFormatError
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.util import Buffer, read_u32_le, require_range


@dataclass(frozen=True)
class FatEntry:
    file_id: int
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


def parse_fat(data: Buffer, header: NdsHeader) -> tuple[FatEntry, ...]:
    if header.fat_size % 8 != 0:
        raise RomFormatError(f"FAT size must be a multiple of 8, got {header.fat_size}")
    table = require_range(data, header.fat_offset, header.fat_size, "FAT")
    entries: list[FatEntry] = []
    for file_id in range(header.fat_size // 8):
        offset = file_id * 8
        start = read_u32_le(table, offset, f"FAT file {file_id} start")
        end = read_u32_le(table, offset + 4, f"FAT file {file_id} end")
        if end < start:
            raise RomFormatError(
                f"FAT file {file_id} has reversed range 0x{start:X}..0x{end:X}"
            )
        if end > len(data):
            raise BoundsError(
                f"FAT file {file_id} ends at 0x{end:X}, beyond ROM size 0x{len(data):X}"
            )
        entries.append(FatEntry(file_id=file_id, start=start, end=end))
    return tuple(entries)
