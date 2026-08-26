from __future__ import annotations

import struct
from typing import TypeAlias

from nds_disassembly_toolkit.errors import BoundsError

Buffer: TypeAlias = bytes | bytearray | memoryview


def require_range(data: Buffer, offset: int, size: int, label: str) -> memoryview:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise BoundsError(
            f"{label} range 0x{offset:X}..0x{offset + size:X} exceeds buffer size 0x{len(data):X}"
        )
    return memoryview(data)[offset : offset + size]


def read_u16_le(data: Buffer, offset: int, label: str) -> int:
    return int(struct.unpack_from("<H", require_range(data, offset, 2, label))[0])


def read_u32_le(data: Buffer, offset: int, label: str) -> int:
    return int(struct.unpack_from("<I", require_range(data, offset, 4, label))[0])
