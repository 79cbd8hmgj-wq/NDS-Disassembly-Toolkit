import random
import struct

import pytest

from nds_disassembly_toolkit.compression.blz import (
    compress_blz,
    decompress_blz,
    decompress_blz_in_place,
    is_blz,
    parse_blz_footer,
)
from nds_disassembly_toolkit.errors import RomFormatError


def make_footer(compressed_length: int, header_length: int, added_length: int) -> bytes:
    return struct.pack("<II", compressed_length | (header_length << 24), added_length)


def test_blz_parses_verified_footer_layout() -> None:
    data = b"x" * (255740 - 11) + b"\xff" * 3 + bytes.fromhex("fc e6 03 0b a4 3a 03 00")
    footer = parse_blz_footer(data)

    assert footer.compressed_length == 255740
    assert footer.header_length == 11
    assert footer.added_length == 211620


def test_blz_decodes_backwards_reference_stream() -> None:
    compressed = bytes.fromhex("00 f0 41 42 43 10") + make_footer(14, 8, 7)
    assert decompress_blz(compressed) == b"ABC" * 7


def test_blz_preserves_uncompressed_prefix() -> None:
    compressed_tail = bytes.fromhex("00 f0 41 42 43 10") + make_footer(14, 8, 7)
    compressed = b"PRE" + compressed_tail
    assert decompress_blz(compressed) == b"PRE" + b"ABC" * 7


def test_blz_detection_accepts_valid_stream() -> None:
    compressed = bytes.fromhex("00 f0 41 42 43 10") + make_footer(14, 8, 7)
    assert is_blz(compressed) is True
    assert is_blz(b"not compressed") is False


def test_blz_rejects_short_header_length() -> None:
    data = b"x" * 8 + make_footer(8, 7, 1)
    with pytest.raises(RomFormatError, match="header length"):
        parse_blz_footer(data)


def test_blz_rejects_compressed_length_larger_than_payload() -> None:
    data = b"x" * 8 + make_footer(100, 8, 1)
    with pytest.raises(RomFormatError, match="compressed length"):
        parse_blz_footer(data)


def test_blz_rejects_non_ff_padding() -> None:
    data = b"payload" + b"\x00" + make_footer(16, 9, 1)
    with pytest.raises(RomFormatError, match="padding"):
        parse_blz_footer(data)


def test_blz_rejects_missing_flags() -> None:
    data = make_footer(8, 8, 1)
    with pytest.raises(RomFormatError, match="flags"):
        decompress_blz(data)


def test_blz_rejects_truncated_reference() -> None:
    data = b"\x80" + make_footer(9, 8, 10)
    with pytest.raises(RomFormatError, match="reference"):
        decompress_blz(data)


def test_blz_rejects_invalid_displacement() -> None:
    data = bytes.fromhex("00 f0 41 40") + make_footer(12, 8, 7)
    with pytest.raises(RomFormatError, match="displacement"):
        decompress_blz(data)


def test_blz_encoder_round_trips_repeated_suffix() -> None:
    decoded = b"PRE" + b"ABC" * 200
    encoded = compress_blz(decoded, passthrough_length=3)
    assert is_blz(encoded) is True
    assert decompress_blz(encoded) == decoded
    assert decompress_blz_in_place(encoded) == decoded
    assert encoded == compress_blz(decoded, passthrough_length=3)


def test_blz_encoder_can_pad_to_exact_target_size() -> None:
    decoded = b"HEAD" + b"0123456789ABCDEF" * 100
    minimal = compress_blz(decoded, passthrough_length=4)
    target = len(minimal) + 37
    encoded = compress_blz(decoded, passthrough_length=4, target_size=target)
    assert len(encoded) == target
    assert decompress_blz(encoded) == decoded


def test_blz_encoder_rejects_target_smaller_than_compressed_stream() -> None:
    decoded = b"A" * 200
    minimal = compress_blz(decoded)
    with pytest.raises(ValueError, match="target size"):
        compress_blz(decoded, target_size=len(minimal) - 1)


def _moderately_redundant_payload(seed: int = 3) -> bytes:
    randomizer = random.Random(seed)
    blocks = [
        bytes(randomizer.randrange(32) for _ in range(randomizer.randrange(3, 20)))
        for _ in range(40)
    ]
    data = bytearray(b"HEAD" * 4)
    for _ in range(300):
        if randomizer.random() < 0.55:
            data.extend(randomizer.choice(blocks))
        else:
            data.extend(randomizer.randrange(256) for _ in range(randomizer.randrange(1, 16)))
    return bytes(data)


def test_blz_encoder_rejects_stream_unsafe_for_in_place_runtime_decode() -> None:
    decoded = _moderately_redundant_payload()
    with pytest.raises(ValueError, match="in-place"):
        compress_blz(decoded, passthrough_length=16)
