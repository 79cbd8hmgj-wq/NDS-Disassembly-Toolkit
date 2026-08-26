import struct
from collections.abc import Callable

import pytest

from nds_disassembly_toolkit.errors import RomFormatError
from nds_disassembly_toolkit.nds.fnt import parse_fnt
from nds_disassembly_toolkit.nds.header import NdsHeader


def build_rom_with_fnt(make_nds_header: Callable[[], bytes]) -> bytes:
    header_bytes = bytearray(make_nds_header())
    fnt_offset = 0x300

    fnt = bytearray()
    fnt.extend(struct.pack("<IHH", 0x10, 0, 2))
    fnt.extend(struct.pack("<IHH", 0x21, 2, 0xF000))
    fnt.extend(bytes([8]) + b"root.bin")
    fnt.extend(bytes([0x80 | 4]) + b"Game" + struct.pack("<H", 0xF001))
    fnt.extend(b"\x00")
    fnt.extend(bytes([8]) + b"data.bin")
    fnt.extend(bytes([7]) + b"map.bin")
    fnt.extend(b"\x00")

    struct.pack_into("<II", header_bytes, 0x40, fnt_offset, len(fnt))
    rom = bytearray(0x1000)
    rom[:0x200] = header_bytes
    rom[fnt_offset : fnt_offset + len(fnt)] = fnt
    return bytes(rom)


def test_parse_fnt_reconstructs_paths(make_nds_header: Callable[[], bytes]) -> None:
    rom = build_rom_with_fnt(make_nds_header)
    tree = parse_fnt(rom, NdsHeader.from_bytes(rom), fat_entry_count=4)

    assert [directory.path for directory in tree.directories] == ["", "Game"]
    assert [(file.file_id, file.path) for file in tree.files] == [
        (0, "root.bin"),
        (2, "Game/data.bin"),
        (3, "Game/map.bin"),
    ]


def test_parse_fnt_maps_files_by_id(make_nds_header: Callable[[], bytes]) -> None:
    rom = build_rom_with_fnt(make_nds_header)
    tree = parse_fnt(rom, NdsHeader.from_bytes(rom), fat_entry_count=4)
    assert tree.file_by_id()[3].path == "Game/map.bin"


def test_parse_fnt_rejects_file_id_beyond_fat(make_nds_header: Callable[[], bytes]) -> None:
    rom = build_rom_with_fnt(make_nds_header)
    with pytest.raises(RomFormatError, match="FAT contains only 3"):
        parse_fnt(rom, NdsHeader.from_bytes(rom), fat_entry_count=3)


def test_parse_fnt_rejects_invalid_child_directory_id(
    make_nds_header: Callable[[], bytes],
) -> None:
    rom = bytearray(build_rom_with_fnt(make_nds_header))
    child_id_offset = 0x300 + 0x10 + 1 + 8 + 1 + 4
    rom[child_id_offset : child_id_offset + 2] = (0xF00A).to_bytes(2, "little")

    with pytest.raises(RomFormatError, match="directory ID"):
        parse_fnt(rom, NdsHeader.from_bytes(rom), fat_entry_count=4)
