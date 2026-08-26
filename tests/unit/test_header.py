from collections.abc import Callable

import pytest

from nds_disassembly_toolkit.errors import BoundsError, RomFormatError
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.util import read_u16_le, read_u32_le, require_range


def test_require_range_returns_requested_slice() -> None:
    assert bytes(require_range(b"abcdef", 1, 3, "test")) == b"bcd"


def test_require_range_rejects_negative_offset() -> None:
    with pytest.raises(BoundsError, match="test"):
        require_range(b"abc", -1, 1, "test")


def test_integer_readers_use_little_endian() -> None:
    data = bytes.fromhex("341278563412")
    assert read_u16_le(data, 0, "u16") == 0x1234
    assert read_u32_le(data, 2, "u32") == 0x12345678


def test_header_parses_verified_layout(make_nds_header: Callable[[], bytes]) -> None:
    header = NdsHeader.from_bytes(make_nds_header())

    assert header.title == "SYNTH NDS"
    assert header.game_code == "TST0"
    assert header.maker_code == "00"
    assert header.revision == 1
    assert header.arm9_offset == 0x4000
    assert header.arm9_ram_address == 0x02000000
    assert header.arm9_size == 448192
    assert header.fnt_offset == 0x0FFC00
    assert header.fat_size == 88040
    assert header.arm9_overlay_offset == 0x71800
    assert header.arm9_overlay_size == 288
    assert header.arm7_overlay_size == 0


def test_header_rejects_truncated_data() -> None:
    with pytest.raises(BoundsError, match="NDS header"):
        NdsHeader.from_bytes(b"\x00" * 0x100)


def test_header_rejects_non_multiple_overlay_table_size(
    make_nds_header: Callable[[], bytes],
) -> None:
    data = bytearray(make_nds_header())
    data[0x54:0x58] = (33).to_bytes(4, "little")

    with pytest.raises(RomFormatError, match="overlay table size"):
        NdsHeader.from_bytes(data)
