from __future__ import annotations

from nds_disassembly_toolkit.errors import RomFormatError
from nds_disassembly_toolkit.util import Buffer


def is_lz10(data: Buffer) -> bool:
    if len(data) < 5 or data[0] != 0x10:
        return False

    declared_size = int(data[1]) | (int(data[2]) << 8) | (int(data[3]) << 16)
    if declared_size == 0:
        return False

    source = memoryview(data)
    source_position = 4
    output_size = 0

    while output_size < declared_size:
        if source_position >= len(source):
            return False
        flags = int(source[source_position])
        source_position += 1

        for bit in range(7, -1, -1):
            if output_size >= declared_size:
                break
            if flags & (1 << bit):
                if source_position + 2 > len(source):
                    return False
                first = int(source[source_position])
                second = int(source[source_position + 1])
                source_position += 2
                length = (first >> 4) + 3
                displacement = (((first & 0x0F) << 8) | second) + 1
                if displacement > output_size:
                    return False
                output_size += min(length, declared_size - output_size)
            else:
                if source_position >= len(source):
                    return False
                source_position += 1
                output_size += 1

    return True


def lz10_declared_size(data: Buffer) -> int:
    if len(data) < 4:
        raise RomFormatError("LZ10 header is truncated")
    if data[0] != 0x10:
        raise RomFormatError(f"invalid LZ10 type byte: 0x{data[0]:02X}")
    size = int(data[1]) | (int(data[2]) << 8) | (int(data[3]) << 16)
    if size == 0:
        raise RomFormatError("LZ10 declared size must be greater than zero")
    return size


def decompress_lz10(data: Buffer) -> bytes:
    declared_size = lz10_declared_size(data)
    source = memoryview(data)
    source_position = 4
    output = bytearray()

    while len(output) < declared_size:
        if source_position >= len(source):
            raise RomFormatError("LZ10 flags byte is missing")
        flags = int(source[source_position])
        source_position += 1

        for bit in range(7, -1, -1):
            if len(output) >= declared_size:
                break
            if flags & (1 << bit):
                if source_position + 2 > len(source):
                    raise RomFormatError("LZ10 reference token is truncated")
                first = int(source[source_position])
                second = int(source[source_position + 1])
                source_position += 2
                length = (first >> 4) + 3
                displacement = (((first & 0x0F) << 8) | second) + 1
                if displacement > len(output):
                    raise RomFormatError(
                        f"LZ10 displacement {displacement} exceeds output size {len(output)}"
                    )
                for _ in range(length):
                    if len(output) >= declared_size:
                        break
                    output.append(output[-displacement])
            else:
                if source_position >= len(source):
                    raise RomFormatError("LZ10 literal byte is missing")
                output.append(int(source[source_position]))
                source_position += 1

    if len(output) != declared_size:
        raise RomFormatError(
            f"LZ10 decoded size mismatch: expected {declared_size}, got {len(output)}"
        )
    return bytes(output)


def compress_lz10(data: bytes) -> bytes:
    size = len(data)
    if size == 0:
        raise ValueError("cannot LZ10-compress empty input")
    if size > 0xFFFFFF:
        raise ValueError("LZ10 input size exceeds the 24-bit header limit")

    output = bytearray((0x10, size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF))
    position = 0
    while position < size:
        output.append(0)
        chunk_end = min(position + 8, size)
        output.extend(data[position:chunk_end])
        position = chunk_end
    return bytes(output)
