import struct
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.model import Component
from nds_disassembly_toolkit.analysis.report import analyze_components


def test_generic_report_collects_strings_references_and_numeric_matches() -> None:
    base = 0x02200000
    data = bytearray(0x100)
    data[0x80:0x8D] = b"engine_state\x00"
    struct.pack_into("<I", data, 0x20, base + 0x80)
    data[0x40:0x43] = bytes([8, 16, 7])
    component = Component("overlay", Path("overlay.bin"), base, bytes(data))

    report = analyze_components(
        (component,),
        keywords=("engine",),
        numeric_records=({"name": "row", "values": [80, 160, 70]},),
        numeric_values_key="values",
        numeric_divisor=10,
    )

    assert report["components"][0]["file_name"] == "overlay.bin"
    assert report["string_records"][0]["text"] == "engine_state"
    assert report["string_records"][0]["references"][0]["address"] == base + 0x20
    assert report["numeric_matches"][0]["record_name"] == "row"
    assert report["numeric_clusters"][0]["match_count"] == 1


def test_generic_report_without_keywords_includes_all_strings() -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, b"first\x00second\x00")

    report = analyze_components((component,))

    assert [row["text"] for row in report["string_records"]] == ["first", "second"]


def test_generic_report_rejects_duplicate_component_names() -> None:
    components = (
        Component("same", Path("a.bin"), 0x02000000, b"AAAA"),
        Component("same", Path("b.bin"), 0x02001000, b"BBBB"),
    )

    with pytest.raises(ValueError, match="unique"):
        analyze_components(components)


def test_generic_report_requires_complete_numeric_configuration() -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, b"AAAA")

    with pytest.raises(ValueError, match="numeric"):
        analyze_components(
            (component,),
            numeric_records=({"name": "row", "values": [10]},),
            numeric_values_key="values",
        )
