from collections.abc import Callable
import struct

import pytest


@pytest.fixture
def make_nds_header() -> Callable[[], bytes]:
    def factory() -> bytes:
        data = bytearray(0x200)
        data[0x00:0x0C] = b"SYNTH NDS\x00\x00\x00"
        data[0x0C:0x10] = b"TST0"
        data[0x10:0x12] = b"00"
        data[0x1E] = 1
        struct.pack_into("<III", data, 0x20, 0x4000, 0x02000000, 0x02000000)
        struct.pack_into("<I", data, 0x2C, 448192)
        struct.pack_into("<III", data, 0x30, 0x0D8A00, 0x02380000, 0x02380000)
        struct.pack_into("<I", data, 0x3C, 160048)
        struct.pack_into("<II", data, 0x40, 0x0FFC00, 212348)
        struct.pack_into("<II", data, 0x48, 0x133A00, 88040)
        struct.pack_into("<II", data, 0x50, 0x071800, 9 * 32)
        struct.pack_into("<II", data, 0x58, 0, 0)
        struct.pack_into("<I", data, 0x80, 134217728)
        return bytes(data)

    return factory
