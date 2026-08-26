from pathlib import Path

from nds_disassembly_toolkit.analysis.model import Component
from nds_disassembly_toolkit.analysis.numeric import cluster_numeric_matches, scan_scaled_byte_rows


def test_scaled_rows_and_clustering_are_schema_agnostic() -> None:
    values = bytes([8, 16, 7, 10, 7, 4])
    component = Component(
        "arm9", Path("arm9.bin"), 0x02000000, b"A" * 4 + values + b"B" * 10 + values
    )
    records = [{"name": "Example Record", "values": [80, 160, 70, 100, 70, 40]}]

    matches = scan_scaled_byte_rows((component,), records, values_key="values", divisor=10)
    clusters = cluster_numeric_matches(matches, max_gap=0x20)

    assert [match.address for match in matches] == [0x02000004, 0x02000014]
    assert clusters[0]["match_count"] == 2
    assert clusters[0]["record_names"] == ["Example Record"]
