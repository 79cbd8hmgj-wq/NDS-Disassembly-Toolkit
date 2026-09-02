from __future__ import annotations

from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    AlignedMemoryValueChange,
    MemoryChange,
    MemorySnapshot,
    MemorySnapshotPhase,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore
from nds_disassembly_toolkit.errors import RuntimeTraceFormatError


def _aligned_values(
    before: MemorySnapshot,
    after: MemorySnapshot,
    *,
    width: int,
    changed_start: int,
    changed_end: int,
    emitted: set[int],
) -> tuple[AlignedMemoryValueChange, ...]:
    region_start = before.region.address
    region_end = region_start + before.region.length
    first = ((region_start + width - 1) // width) * width
    values: list[AlignedMemoryValueChange] = []
    for address in range(first, region_end - width + 1, width):
        word_end = address + width
        if word_end <= changed_start or address >= changed_end or address in emitted:
            continue
        offset = address - region_start
        before_bytes = before.data[offset : offset + width]
        after_bytes = after.data[offset : offset + width]
        if before_bytes == after_bytes:
            continue
        values.append(
            AlignedMemoryValueChange(
                address=address,
                width=width,
                before=int.from_bytes(before_bytes, "little"),
                after=int.from_bytes(after_bytes, "little"),
            )
        )
        emitted.add(address)
    return tuple(values)


def diff_memory_snapshots(
    before: MemorySnapshot,
    after: MemorySnapshot,
) -> tuple[MemoryChange, ...]:
    if before.region != after.region:
        raise ValueError("memory snapshots must describe the same memory region")
    if (
        before.phase is not MemorySnapshotPhase.BEFORE
        or after.phase is not MemorySnapshotPhase.AFTER
    ):
        raise ValueError("memory snapshots must be ordered BEFORE then AFTER")
    if len(before.data) != len(after.data):
        raise ValueError("memory snapshot byte lengths must match")

    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(before.data):
        if before.data[index] == after.data[index]:
            index += 1
            continue
        start = index
        index += 1
        while index < len(before.data) and before.data[index] != after.data[index]:
            index += 1
        spans.append((start, index))

    emitted16: set[int] = set()
    emitted32: set[int] = set()
    changes: list[MemoryChange] = []
    for start, end in spans:
        absolute_start = before.region.address + start
        absolute_end = before.region.address + end
        changes.append(
            MemoryChange(
                region_ordinal=before.region.ordinal,
                address=absolute_start,
                before=before.data[start:end],
                after=after.data[start:end],
                values16=_aligned_values(
                    before,
                    after,
                    width=2,
                    changed_start=absolute_start,
                    changed_end=absolute_end,
                    emitted=emitted16,
                ),
                values32=_aligned_values(
                    before,
                    after,
                    width=4,
                    changed_start=absolute_start,
                    changed_end=absolute_end,
                    emitted=emitted32,
                ),
            )
        )
    return tuple(changes)


def diff_trace_memory(store: TraceStore) -> tuple[MemoryChange, ...]:
    changes: list[MemoryChange] = []
    for region in store.config.memory_regions:
        before = store.memory_snapshot(region.ordinal, MemorySnapshotPhase.BEFORE)
        after = store.memory_snapshot(region.ordinal, MemorySnapshotPhase.AFTER)
        if before is None or after is None:
            raise RuntimeTraceFormatError("runtime trace memory snapshots are incomplete")
        changes.extend(diff_memory_snapshots(before, after))
    return tuple(changes)
