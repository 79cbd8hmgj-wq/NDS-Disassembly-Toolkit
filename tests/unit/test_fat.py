from collections.abc import Callable
import struct

import pytest

from nds_disassembly_toolkit.errors import BoundsError, RomFormatError
from nds_disassembly_toolkit.nds.fat import parse_fat
from nds_disassembly_toolkit.nds.header import NdsHeader


def build_rom_with_fat(make_nds_header: Callable[[], bytes], entries: list[tuple[int, int]]) -> bytes:
    header_bytes = bytearray(make_nds_header())
    fat_offset = 0x300
    fat_size = len(entries) * 8
    struct.pack_into("<II", header_bytes, 0x48, fat_offset, fat_size)
    rom = bytearray(0x1000)
    rom[:0x200] = header_bytes
    for index, (start, end) in enumerate(entries):
        struct.pack_into("<II", rom, fat_offset + index * 8, start, end)
    return bytes(rom)


def test_parse_fat_assigns_file_ids_and_sizes(make_nds_header: Callable[[], bytes]) -> None:
    rom = build_rom_with_fat(make_nds_header, [(0x500, 0x510), (0x600, 0x640)])
    entries = parse_fat(rom, NdsHeader.from_bytes(rom))
    assert [(e.file_id, e.start, e.end, e.size) for e in entries] == [
        (0, 0x500, 0x510, 0x10),
        (1, 0x600, 0x640, 0x40),
    ]


def test_parse_fat_rejects_non_multiple_of_eight(make_nds_header: Callable[[], bytes]) -> None:
    rom = bytearray(build_rom_with_fat(make_nds_header, [(0x500, 0x510)]))
    rom[0x4C:0x50] = (9).to_bytes(4, "little")
    with pytest.raises(RomFormatError, match="multiple of 8"):
        parse_fat(rom, NdsHeader.from_bytes(rom))


def test_parse_fat_rejects_reversed_range(make_nds_header: Callable[[], bytes]) -> None:
    rom = build_rom_with_fat(make_nds_header, [(0x600, 0x500)])
    with pytest.raises(RomFormatError, match="file 0"):
        parse_fat(rom, NdsHeader.from_bytes(rom))


def test_parse_fat_rejects_file_outside_rom(make_nds_header: Callable[[], bytes]) -> None:
    rom = build_rom_with_fat(make_nds_header, [(0x500, 0x2000)])
    with pytest.raises(BoundsError, match="file 0"):
        parse_fat(rom, NdsHeader.from_bytes(rom))
