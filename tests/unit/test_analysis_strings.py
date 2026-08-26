from pathlib import Path
import struct

from nds_disassembly_toolkit.analysis.model import Component
from nds_disassembly_toolkit.analysis.strings import (
    extract_ascii_strings,
    filter_strings,
    find_pointer_references,
)


def component(data: bytes, base: int = 0x02000000) -> Component:
    return Component("test", Path("test.bin"), base, data)


def test_extract_ascii_strings_and_filter() -> None:
    item = component(b"\x00abc\x00engine_state\x00Menu Label\x00")
    strings = extract_ascii_strings(item)

    assert [record.text for record in strings] == ["engine_state", "Menu Label"]
    assert [record.text for record in filter_strings(strings, ("engine",))] == ["engine_state"]


def test_find_pointer_references_uses_little_endian_addresses() -> None:
    target = 0x0228A210
    item = component(b"ABCD" + struct.pack("<I", target) + b"EFGH", 0x02200000)

    references = find_pointer_references((item,), target)

    assert len(references) == 1
    assert references[0].offset == 4
    assert references[0].address == 0x02200004


def test_extract_rejects_non_positive_minimum() -> None:
    try:
        extract_ascii_strings(component(b""), minimum_length=0)
    except ValueError as exc:
        assert "positive" in str(exc)
    else:
        raise AssertionError("expected ValueError")
