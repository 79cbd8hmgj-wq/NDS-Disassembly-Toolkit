from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path

from nds_disassembly_toolkit.analysis.model import Component
from nds_disassembly_toolkit.analysis.numeric import cluster_numeric_matches, scan_scaled_byte_rows
from nds_disassembly_toolkit.analysis.strings import (
    extract_ascii_strings,
    filter_strings,
    find_pointer_references,
)


def analyze_components(
    components: tuple[Component, ...],
    *,
    keywords: tuple[str, ...] = (),
    minimum_string_length: int = 4,
    numeric_records: Iterable[dict[str, object]] = (),
    numeric_values_key: str | None = None,
    numeric_divisor: int | None = None,
) -> dict[str, object]:
    """Build a deterministic, schema-neutral analysis report for flat components."""
    if not components:
        raise ValueError("at least one component is required")
    by_name = {component.name: component for component in components}
    if len(by_name) != len(components):
        raise ValueError("component names must be unique")

    strings = tuple(
        record
        for component in components
        for record in extract_ascii_strings(component, minimum_length=minimum_string_length)
    )
    if keywords:
        strings = filter_strings(strings, keywords)

    string_rows = [
        asdict(record)
        | {
            "references": [
                asdict(reference)
                for reference in find_pointer_references(components, record.address)
            ]
        }
        for record in strings
    ]

    records = tuple(numeric_records)
    numeric_configured = numeric_values_key is not None or numeric_divisor is not None
    if numeric_configured and (numeric_values_key is None or numeric_divisor is None):
        raise ValueError("numeric_values_key and numeric_divisor must be provided together")
    if records and not numeric_configured:
        raise ValueError("numeric records require numeric_values_key and numeric_divisor")
    numeric_matches = (
        scan_scaled_byte_rows(
            components,
            records,
            values_key=numeric_values_key,
            divisor=numeric_divisor,
        )
        if numeric_values_key is not None and numeric_divisor is not None
        else ()
    )

    return {
        "format_version": 1,
        "components": [
            {
                "name": component.name,
                "file_name": component.path.name,
                "sha256": hashlib.sha256(component.data).hexdigest(),
                "base_address": component.base_address,
                "size": len(component.data),
                "end_address": component.end_address,
            }
            for component in components
        ],
        "string_records": string_rows,
        "numeric_matches": [asdict(match) for match in numeric_matches],
        "numeric_clusters": list(cluster_numeric_matches(numeric_matches)),
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
