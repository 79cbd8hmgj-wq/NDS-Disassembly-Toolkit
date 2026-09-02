from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    MemorySnapshot,
    MemorySnapshotPhase,
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceMemoryRegion,
    TraceSummary,
    TraceTermination,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore

BASE = 0x02100000


def _snapshot(
    data: bytes,
    phase: MemorySnapshotPhase,
    *,
    address: int = BASE,
    ordinal: int = 0,
) -> MemorySnapshot:
    region = TraceMemoryRegion(ordinal, address, len(data))
    return MemorySnapshot.from_bytes(region, phase, data)


def test_memory_diff_coalesces_maximal_contiguous_byte_ranges() -> None:
    from nds_disassembly_toolkit.analysis.runtime.memory_diff import diff_memory_snapshots

    before = _snapshot(bytes.fromhex("0001020304050607"), MemorySnapshotPhase.BEFORE)
    after = _snapshot(bytes.fromhex("0001aabb0405cc07"), MemorySnapshotPhase.AFTER)

    changes = diff_memory_snapshots(before, after)

    assert [(change.address, change.before.hex(), change.after.hex()) for change in changes] == [
        (BASE + 2, "0203", "aabb"),
        (BASE + 6, "06", "cc"),
    ]


def test_memory_diff_reports_aligned_little_endian_values() -> None:
    from nds_disassembly_toolkit.analysis.runtime.memory_diff import diff_memory_snapshots

    before = _snapshot(bytes.fromhex("0011223344556677"), MemorySnapshotPhase.BEFORE)
    after = _snapshot(bytes.fromhex("00aa223344556677"), MemorySnapshotPhase.AFTER)

    changes = diff_memory_snapshots(before, after)

    assert len(changes) == 1
    change = changes[0]
    assert change.address == BASE + 1
    assert change.before == b"\x11"
    assert change.after == b"\xaa"
    assert [
        (value.address, value.width, value.before, value.after)
        for value in change.values16
    ] == [(BASE, 2, 0x1100, 0xAA00)]
    assert [
        (value.address, value.width, value.before, value.after)
        for value in change.values32
    ] == [(BASE, 4, 0x33221100, 0x3322AA00)]


def test_memory_diff_omits_incomplete_aligned_words_at_region_tail() -> None:
    from nds_disassembly_toolkit.analysis.runtime.memory_diff import diff_memory_snapshots

    before = _snapshot(bytes.fromhex("000102030405"), MemorySnapshotPhase.BEFORE)
    after = _snapshot(bytes.fromhex("0001020304ff"), MemorySnapshotPhase.AFTER)

    changes = diff_memory_snapshots(before, after)

    assert len(changes) == 1
    assert [(value.address, value.width) for value in changes[0].values16] == [
        (BASE + 4, 2)
    ]
    assert changes[0].values32 == ()


def test_memory_diff_requires_same_region_and_before_after_order() -> None:
    from nds_disassembly_toolkit.analysis.runtime.memory_diff import diff_memory_snapshots

    before = _snapshot(b"AAAA", MemorySnapshotPhase.BEFORE)
    wrong_region = _snapshot(
        b"BBBB", MemorySnapshotPhase.AFTER, address=BASE + 4
    )
    after = _snapshot(b"BBBB", MemorySnapshotPhase.AFTER)

    with pytest.raises(ValueError, match="same memory region"):
        diff_memory_snapshots(before, wrong_region)
    with pytest.raises(ValueError, match="BEFORE.*AFTER"):
        diff_memory_snapshots(after, before)


def test_identical_memory_snapshots_have_no_changes() -> None:
    from nds_disassembly_toolkit.analysis.runtime.memory_diff import diff_memory_snapshots

    before = _snapshot(b"ABCD", MemorySnapshotPhase.BEFORE)
    after = _snapshot(b"ABCD", MemorySnapshotPhase.AFTER)

    assert diff_memory_snapshots(before, after) == ()


def test_diff_trace_memory_reads_all_persisted_region_pairs(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.memory_diff import diff_trace_memory

    destination = tmp_path / "memory.ndstrace"
    regions = (
        TraceMemoryRegion(0, BASE, 4),
        TraceMemoryRegion(1, BASE + 0x10, 4),
    )
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=1,
        timeout=5.0,
        memory_regions=regions,
    )
    with TraceStore.create_atomic(destination, config) as store:
        store.store_memory_snapshot(
            MemorySnapshot.from_bytes(regions[0], MemorySnapshotPhase.BEFORE, b"AAAA")
        )
        store.store_memory_snapshot(
            MemorySnapshot.from_bytes(regions[0], MemorySnapshotPhase.AFTER, b"AABA")
        )
        store.store_memory_snapshot(
            MemorySnapshot.from_bytes(regions[1], MemorySnapshotPhase.BEFORE, b"CCCC")
        )
        store.store_memory_snapshot(
            MemorySnapshot.from_bytes(regions[1], MemorySnapshotPhase.AFTER, b"CCCC")
        )
        store.finalize(
            TraceSummary(
                trace=destination,
                cpu=RuntimeCpu.ARM9,
                capture_mode=TraceCaptureMode.STEP,
                evidence_events=0,
                control_events=0,
                memory_regions=2,
                terminated_by=TraceTermination.LIMIT,
                project_fingerprint=None,
            )
        )

    store = TraceStore.open(destination)
    try:
        changes = diff_trace_memory(store)
    finally:
        store.close()

    assert [(change.region_ordinal, change.address) for change in changes] == [
        (0, BASE + 2)
    ]
