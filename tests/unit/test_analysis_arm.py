from pathlib import Path
import struct

import pytest

from nds_disassembly_toolkit.analysis.arm import (
    arm_function_starts,
    function_address_for_reference,
    nearest_function_start,
)
from nds_disassembly_toolkit.analysis.model import Component


def make_component() -> Component:
    data = bytearray(0x40)
    struct.pack_into("<I", data, 0x08, 0xE92D4010)
    struct.pack_into("<I", data, 0x20, 0xE92D40F8)
    return Component("overlay", Path("overlay.bin"), 0x02200000, bytes(data))


def test_arm_function_start_detection() -> None:
    item = make_component()

    assert arm_function_starts(item) == (0x08, 0x20)
    assert nearest_function_start(item, 0x30) == 0x20
    assert function_address_for_reference(item, 0x30) == 0x02200020


def test_nearest_function_rejects_out_of_range_offset() -> None:
    with pytest.raises(ValueError, match="outside"):
        nearest_function_start(make_component(), 0x100)
