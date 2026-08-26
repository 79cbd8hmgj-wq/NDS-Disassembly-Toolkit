import pytest

from nds_disassembly_toolkit.compression.lz10 import compress_lz10, decompress_lz10


def test_compress_lz10_round_trips_literal_data() -> None:
    source = b"Nintendo DS toolkit"
    encoded = compress_lz10(source)

    assert encoded[:4] == bytes((0x10, len(source), 0, 0))
    assert decompress_lz10(encoded) == source


def test_compress_lz10_uses_deterministic_literal_groups() -> None:
    source = bytes(range(17))

    assert compress_lz10(source) == (
        bytes.fromhex("10 11 00 00")
        + b"\x00"
        + bytes(range(8))
        + b"\x00"
        + bytes(range(8, 16))
        + b"\x00\x10"
    )


def test_compress_lz10_is_deterministic() -> None:
    source = b"A" * 100
    assert compress_lz10(source) == compress_lz10(source)


def test_compress_lz10_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="empty"):
        compress_lz10(b"")


def test_compress_lz10_rejects_size_larger_than_24_bits() -> None:
    class TooLarge(bytes):
        def __len__(self) -> int:
            return 0x1000000

    with pytest.raises(ValueError, match="24-bit"):
        compress_lz10(TooLarge(b"x"))
