from collections.abc import Callable
import struct

import pytest

from nds_disassembly_toolkit.errors import RomFormatError
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.nds.overlays import parse_arm7_overlays, parse_arm9_overlays


def build_rom_with_overlays(make_nds_header: Callable[[], bytes]) -> bytes:
    header_bytes = bytearray(make_nds_header())
    table_offset = 0x300
    table_size = 2 * 32
    struct.pack_into("<II", header_bytes, 0x50, table_offset, table_size)
    struct.pack_into("<II", header_bytes, 0x58, 0, 0)
    rom = bytearray(0x1000)
    rom[:0x200] = header_bytes
    entries = [
        (0, 0x02219440, 1000, 64, 0x02219480, 0x022194A0, 10, 0x010001F4),
        (7, 0x02219440, 467360, 1600, 0x02285CBC, 0x02285CC4, 70, 0x0103E6FC),
    ]
    for index, values in enumerate(entries):
        struct.pack_into("<8I", rom, table_offset + index * 32, *values)
    return bytes(rom)


def test_parse_arm9_overlays_decodes_fields(make_nds_header: Callable[[], bytes]) -> None:
    rom = build_rom_with_overlays(make_nds_header)
    overlays = parse_arm9_overlays(rom, NdsHeader.from_bytes(rom))
    assert len(overlays) == 2
    assert overlays[1].overlay_id == 7
    assert overlays[1].ram_address == 0x02219440
    assert overlays[1].ram_size == 467360
    assert overlays[1].bss_size == 1600
    assert overlays[1].file_id == 70
    assert overlays[1].compressed_size == 0x03E6FC
    assert overlays[1].flags == 1
    assert overlays[1].ram_end == 0x02219440 + 467360 + 1600


def test_parse_arm7_overlays_handles_empty_table(make_nds_header: Callable[[], bytes]) -> None:
    rom = build_rom_with_overlays(make_nds_header)
    assert parse_arm7_overlays(rom, NdsHeader.from_bytes(rom)) == ()


def test_overlay_table_rejects_duplicate_ids(make_nds_header: Callable[[], bytes]) -> None:
    rom = bytearray(build_rom_with_overlays(make_nds_header))
    rom[0x300 + 32 : 0x300 + 36] = (0).to_bytes(4, "little")
    with pytest.raises(RomFormatError, match="duplicate"):
        parse_arm9_overlays(rom, NdsHeader.from_bytes(rom))


def test_overlay_table_rejects_static_init_outside_ram(
    make_nds_header: Callable[[], bytes],
) -> None:
    rom = bytearray(build_rom_with_overlays(make_nds_header))
    rom[0x300 + 16 : 0x300 + 20] = (0x03000000).to_bytes(4, "little")
    with pytest.raises(RomFormatError, match="static initializer"):
        parse_arm9_overlays(rom, NdsHeader.from_bytes(rom))
