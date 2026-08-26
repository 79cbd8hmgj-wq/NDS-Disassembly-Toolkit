from __future__ import annotations

import struct
from dataclasses import dataclass

from nds_disassembly_toolkit.errors import RomFormatError
from nds_disassembly_toolkit.util import Buffer


@dataclass(frozen=True)
class BlzFooter:
    compressed_length: int
    header_length: int
    added_length: int


def parse_blz_footer(data: Buffer) -> BlzFooter:
    if len(data) < 8:
        raise RomFormatError("BLZ footer is truncated")
    compressed_and_header, added_length = struct.unpack_from("<II", data, len(data) - 8)
    header_length = compressed_and_header >> 24
    compressed_length = compressed_and_header & 0x00FFFFFF
    if header_length < 8:
        raise RomFormatError(f"BLZ header length must be at least 8, got {header_length}")
    if header_length > len(data):
        raise RomFormatError(f"BLZ header length {header_length} exceeds payload size {len(data)}")
    if compressed_length < header_length:
        raise RomFormatError(
            f"BLZ compressed length {compressed_length} is smaller than header {header_length}"
        )
    if compressed_length > len(data):
        raise RomFormatError(
            f"BLZ compressed length {compressed_length} exceeds payload size {len(data)}"
        )
    padding = memoryview(data)[len(data) - header_length : len(data) - 8]
    if any(byte != 0xFF for byte in padding):
        raise RomFormatError("BLZ header padding is not entirely 0xFF")
    return BlzFooter(
        compressed_length=compressed_length,
        header_length=header_length,
        added_length=added_length,
    )


def is_blz(data: Buffer) -> bool:
    try:
        footer = parse_blz_footer(data)
    except RomFormatError:
        return False
    return footer.added_length > 0


def decompress_blz(data: Buffer) -> bytes:
    footer = parse_blz_footer(data)
    if footer.added_length == 0:
        raise RomFormatError("BLZ added length is zero; payload is not compressed")

    source = memoryview(data)
    passthrough_length = len(source) - footer.compressed_length
    compressed_end = len(source) - footer.header_length
    compressed = source[passthrough_length:compressed_end]
    decoded_length = len(source) + footer.added_length - passthrough_length
    decoded = bytearray(decoded_length)

    read_count = 0
    written = 0
    flags = 0
    mask = 0

    while written < decoded_length:
        if mask == 0:
            if read_count >= len(compressed):
                raise RomFormatError("BLZ flags byte is missing")
            flags = int(compressed[len(compressed) - 1 - read_count])
            read_count += 1
            mask = 0x80

        if flags & mask:
            if read_count + 2 > len(compressed):
                raise RomFormatError("BLZ reference token is truncated")
            first = int(compressed[len(compressed) - 1 - read_count])
            read_count += 1
            second = int(compressed[len(compressed) - 1 - read_count])
            read_count += 1
            length = (first >> 4) + 3
            displacement = (((first & 0x0F) << 8) | second) + 3
            if displacement > written:
                raise RomFormatError(
                    f"BLZ displacement {displacement} exceeds decoded suffix size {written}"
                )
            source_index = written - displacement
            for _ in range(length):
                if written >= decoded_length:
                    break
                decoded[len(decoded) - 1 - written] = decoded[len(decoded) - 1 - source_index]
                written += 1
                source_index += 1
        else:
            if read_count >= len(compressed):
                raise RomFormatError("BLZ literal byte is missing")
            decoded[len(decoded) - 1 - written] = compressed[len(compressed) - 1 - read_count]
            read_count += 1
            written += 1

        mask >>= 1

    return bytes(source[:passthrough_length]) + bytes(decoded)


def decompress_blz_in_place(data: Buffer) -> bytes:
    """Model the Nintendo DS in-place backward BLZ decompressor exactly."""

    footer = parse_blz_footer(data)
    if footer.added_length == 0:
        raise RomFormatError("BLZ added length is zero; payload is not compressed")

    source = bytes(data)
    stop = len(source) - footer.compressed_length
    source_cursor = len(source) - footer.header_length
    destination_cursor = len(source) + footer.added_length
    buffer = bytearray(destination_cursor)
    buffer[: len(source)] = source

    while destination_cursor > stop:
        if source_cursor <= stop:
            raise RomFormatError("BLZ flags byte overlaps the decoded output")
        source_cursor -= 1
        flags = buffer[source_cursor]
        for bit in range(8):
            if destination_cursor <= stop:
                break
            if flags & (0x80 >> bit):
                if source_cursor - 2 < stop:
                    raise RomFormatError("BLZ reference overlaps the decoded output")
                source_cursor -= 2
                first = buffer[source_cursor + 1]
                second = buffer[source_cursor]
                length = (first >> 4) + 3
                displacement = (((first & 0x0F) << 8) | second) + 3
                if destination_cursor + displacement > len(buffer):
                    raise RomFormatError("BLZ displacement exceeds the decoded output boundary")
                for _ in range(length):
                    if destination_cursor <= stop:
                        break
                    destination_cursor -= 1
                    buffer[destination_cursor] = buffer[destination_cursor + displacement]
            else:
                if source_cursor <= stop:
                    raise RomFormatError("BLZ literal overlaps the decoded output")
                source_cursor -= 1
                destination_cursor -= 1
                buffer[destination_cursor] = buffer[source_cursor]

    return bytes(buffer)


def _encode_blz_suffix(data: bytes) -> bytes:
    reversed_data = data[::-1]
    positions: dict[bytes, list[int]] = {}
    logical = bytearray()
    group: list[tuple[bool, bytes]] = []

    def add_position(index: int) -> None:
        if index + 3 > len(reversed_data):
            return
        key = reversed_data[index : index + 3]
        candidates = positions.setdefault(key, [])
        candidates.append(index)
        minimum = index - 4098
        while candidates and candidates[0] < minimum:
            candidates.pop(0)

    def best_match(index: int) -> tuple[int, int]:
        if index + 3 > len(reversed_data):
            return 0, 0
        best_length = 0
        best_displacement = 0
        key = reversed_data[index : index + 3]
        for candidate in reversed(positions.get(key, ())):
            displacement = index - candidate
            if displacement < 3:
                continue
            if displacement > 4098:
                break
            length = 3
            maximum = min(18, len(reversed_data) - index)
            while (
                length < maximum
                and reversed_data[index + length] == reversed_data[index - displacement + length]
            ):
                length += 1
            if length > best_length:
                best_length = length
                best_displacement = displacement
                if length == maximum:
                    break
        return best_length, best_displacement

    def flush_group() -> None:
        if not group:
            return
        flags = 0
        payload = bytearray()
        for index, (is_reference, token) in enumerate(group):
            if is_reference:
                flags |= 0x80 >> index
            payload.extend(token)
        logical.append(flags)
        logical.extend(payload)
        group.clear()

    cursor = 0
    while cursor < len(reversed_data):
        best_length, best_displacement = best_match(cursor)

        if best_length >= 3 and cursor + 1 < len(reversed_data):
            next_length, _ = best_match(cursor + 1)
            use_reference = next_length < best_length + 1
        else:
            use_reference = best_length >= 3

        if use_reference:
            encoded_displacement = best_displacement - 3
            token = bytes(
                (
                    ((best_length - 3) << 4) | (encoded_displacement >> 8),
                    encoded_displacement & 0xFF,
                )
            )
            group.append((True, token))
            consumed = best_length
        else:
            group.append((False, bytes((reversed_data[cursor],))))
            consumed = 1

        for index in range(cursor, cursor + consumed):
            add_position(index)
        cursor += consumed
        if len(group) == 8:
            flush_group()

    flush_group()
    return bytes(reversed(logical))


def compress_blz(
    data: Buffer,
    *,
    passthrough_length: int = 0,
    target_size: int | None = None,
) -> bytes:
    """Deterministically BLZ-compress data, optionally padding to an exact size."""

    source = bytes(data)
    if not 0 <= passthrough_length < len(source):
        raise ValueError("BLZ passthrough length is outside the source")
    encoded_suffix = _encode_blz_suffix(source[passthrough_length:])
    minimum_size = passthrough_length + len(encoded_suffix) + 8
    if target_size is None:
        target_size = minimum_size
    if target_size < minimum_size:
        raise ValueError(f"BLZ target size {target_size} is smaller than minimum {minimum_size}")
    if target_size >= len(source):
        raise ValueError("BLZ target size must be smaller than decoded size")
    filler_length = target_size - minimum_size
    if filler_length > 0xF7:
        raise ValueError("BLZ target padding exceeds the 247-byte header capacity")
    header_length = 8 + filler_length
    compressed_length = len(encoded_suffix) + header_length
    if compressed_length > 0x00FFFFFF:
        raise ValueError("BLZ compressed region exceeds 24-bit footer capacity")
    added_length = len(source) - target_size
    footer = struct.pack(
        "<II",
        compressed_length | (header_length << 24),
        added_length,
    )
    result = source[:passthrough_length] + encoded_suffix + (b"\xff" * filler_length) + footer
    if decompress_blz(result) != source:
        raise AssertionError("BLZ encoder produced a non-round-tripping stream")
    try:
        in_place = decompress_blz_in_place(result)
    except RomFormatError as exc:
        raise ValueError(f"BLZ stream is not safe for in-place decoding: {exc}") from exc
    if in_place != source:
        raise AssertionError("BLZ in-place decoder produced different output")
    return result
