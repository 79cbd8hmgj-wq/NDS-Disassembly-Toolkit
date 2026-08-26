from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.model import Component


def test_component_converts_offsets_and_addresses() -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, b"ABCD")

    assert component.end_address == 0x02000004
    assert component.address_for_offset(2) == 0x02000002
    assert component.offset_for_address(0x02000003) == 3


def test_component_rejects_out_of_range_conversion() -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, b"ABCD")

    with pytest.raises(ValueError, match="outside"):
        component.address_for_offset(4)
    with pytest.raises(ValueError, match="outside"):
        component.offset_for_address(0x01FFFFFF)
