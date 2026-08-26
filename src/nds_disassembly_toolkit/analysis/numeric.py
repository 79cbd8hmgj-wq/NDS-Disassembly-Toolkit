from __future__ import annotations

from collections.abc import Iterable

from nds_disassembly_toolkit.analysis.model import Component, NumericMatch


def scan_scaled_byte_rows(
    components: tuple[Component, ...],
    records: Iterable[dict[str, object]],
    *,
    values_key: str,
    divisor: int,
) -> tuple[NumericMatch, ...]:
    """Find exact rows after dividing source values into an unsigned-byte encoding."""
    if divisor <= 0:
        raise ValueError("divisor must be positive")
    matches: list[NumericMatch] = []
    for record_index, record in enumerate(records):
        raw_values = record.get(values_key)
        if not isinstance(raw_values, list) or not all(
            isinstance(value, int) and not isinstance(value, bool) for value in raw_values
        ):
            raise ValueError(f"record {record_index} has invalid {values_key}")
        if any(value % divisor for value in raw_values):
            continue
        values = tuple(value // divisor for value in raw_values)
        if not values or any(not 0 <= value <= 255 for value in values):
            continue
        needle = bytes(values)
        for component in components:
            cursor = 0
            while True:
                offset = component.data.find(needle, cursor)
                if offset < 0:
                    break
                matches.append(
                    NumericMatch(
                        component=component.name,
                        offset=offset,
                        address=component.base_address + offset,
                        record_index=record_index,
                        record_name=str(record.get("name", f"record_{record_index}")),
                        values=values,
                        encoding=f"u8_div_{divisor}",
                    )
                )
                cursor = offset + 1
    return tuple(matches)


def cluster_numeric_matches(
    matches: tuple[NumericMatch, ...],
    *,
    max_gap: int = 0x80,
) -> tuple[dict[str, object], ...]:
    """Group nearby matches without claiming that surrounding bytes share a schema."""
    if max_gap < 0:
        raise ValueError("max_gap must be non-negative")
    clusters: list[dict[str, object]] = []
    for component in sorted({match.component for match in matches}):
        ordered = sorted(
            (match for match in matches if match.component == component),
            key=lambda match: (match.address, match.record_index),
        )
        current: list[NumericMatch] = []
        for match in ordered:
            if current and match.address - current[-1].address > max_gap:
                clusters.append(_cluster_row(component, current))
                current = []
            current.append(match)
        if current:
            clusters.append(_cluster_row(component, current))
    return tuple(clusters)


def _cluster_row(component: str, matches: list[NumericMatch]) -> dict[str, object]:
    unique_addresses = sorted({match.address for match in matches})
    return {
        "component": component,
        "start_address": unique_addresses[0],
        "end_address": unique_addresses[-1] + len(matches[-1].values),
        "match_count": len(matches),
        "unique_address_count": len(unique_addresses),
        "record_names": sorted({match.record_name for match in matches}),
    }
