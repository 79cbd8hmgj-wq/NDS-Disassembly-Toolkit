import pytest

from nds_disassembly_toolkit.compression.lz10 import decompress_lz10, is_lz10, lz10_declared_size
from nds_disassembly_toolkit.errors import RomFormatError


def test_lz10_decodes_literal_only_stream() -> None:
    encoded = bytes.fromhex("10 03 00 00 00 41 42 43")
    assert decompress_lz10(encoded) == b"ABC"


def test_lz10_decodes_back_reference() -> None:
    encoded = bytes.fromhex("10 09 00 00 10 41 42 43 30 02")
    assert decompress_lz10(encoded) == b"ABCABCABC"


def test_lz10_supports_overlapping_back_reference() -> None:
    encoded = bytes.fromhex("10 0A 00 00 40 41 60 00")
    assert decompress_lz10(encoded) == b"AAAAAAAAAA"


def test_lz10_detection_and_declared_size() -> None:
    encoded = bytes.fromhex("10 03 02 01")
    assert is_lz10(encoded) is True
    assert lz10_declared_size(encoded) == 0x010203
    assert is_lz10(b"\x11\x00\x00\x00") is False


def test_lz10_detection_rejects_zero_declared_size_false_positive() -> None:
    assert is_lz10(bytes.fromhex("10 00 00 00 41 42 43 44")) is False


@pytest.mark.parametrize("encoded", [b"", b"\x10", b"\x10\x01\x00"])
def test_lz10_rejects_truncated_header(encoded: bytes) -> None:
    with pytest.raises(RomFormatError, match="header"):
        decompress_lz10(encoded)


def test_lz10_rejects_truncated_flag_group() -> None:
    with pytest.raises(RomFormatError, match="flags"):
        decompress_lz10(bytes.fromhex("10 01 00 00"))


def test_lz10_rejects_truncated_reference() -> None:
    with pytest.raises(RomFormatError, match="reference"):
        decompress_lz10(bytes.fromhex("10 03 00 00 80 00"))


def test_lz10_rejects_invalid_displacement() -> None:
    with pytest.raises(RomFormatError, match="displacement"):
        decompress_lz10(bytes.fromhex("10 03 00 00 80 00 00"))


def test_lz10_rejects_missing_literal_before_declared_size() -> None:
    with pytest.raises(RomFormatError, match="literal"):
        decompress_lz10(bytes.fromhex("10 02 00 00 00 41"))


def test_lz10_rejects_zero_declared_size() -> None:
    with pytest.raises(RomFormatError, match="declared size"):
        decompress_lz10(bytes.fromhex("10 00 00 00"))
