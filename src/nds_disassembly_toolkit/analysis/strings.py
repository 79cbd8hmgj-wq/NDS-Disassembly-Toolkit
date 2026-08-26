from __future__ import annotations

import re
import struct

from nds_disassembly_toolkit.analysis.model import Component, PointerReference, StringRecord


def extract_ascii_strings(
    component: Component,
    *,
    minimum_length: int = 4,
) -> tuple[StringRecord, ...]:
    if minimum_length < 1:
        raise ValueError("minimum_length must be positive")
    pattern = re.compile(rb"[ -~]{" + str(minimum_length).encode("ascii") + rb",}\x00")
    return tuple(
        StringRecord(
            component=component.name,
            offset=match.start(),
            address=component.base_address + match.start(),
            text=match.group()[:-1].decode("ascii"),
        )
        for match in pattern.finditer(component.data)
    )


def filter_strings(
    records: tuple[StringRecord, ...],
    keywords: tuple[str, ...],
) -> tuple[StringRecord, ...]:
    lowered = tuple(keyword.lower() for keyword in keywords)
    return tuple(
        record
        for record in records
        if any(word in record.text.lower() for word in lowered)
    )


def find_pointer_references(
    components: tuple[Component, ...],
    target_address: int,
) -> tuple[PointerReference, ...]:
    if not 0 <= target_address <= 0xFFFFFFFF:
        raise ValueError("target_address must fit in an unsigned 32-bit value")
    needle = struct.pack("<I", target_address)
    references: list[PointerReference] = []
    for component in components:
        cursor = 0
        while True:
            offset = component.data.find(needle, cursor)
            if offset < 0:
                break
            references.append(
                PointerReference(
                    component=component.name,
                    offset=offset,
                    address=component.base_address + offset,
                    target_address=target_address,
                )
            )
            cursor = offset + 1
    return tuple(references)
