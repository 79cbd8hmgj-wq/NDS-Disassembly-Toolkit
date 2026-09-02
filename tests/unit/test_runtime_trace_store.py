from __future__ import annotations

import importlib
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from nds_disassembly_toolkit.analysis.runtime import (
    MemorySnapshot,
    MemorySnapshotPhase,
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceEvent,
    TraceEventRole,
    TraceMemoryRegion,
    TraceSummary,
    TraceTermination,
)
from nds_disassembly_toolkit.errors import RuntimeTraceFormatError


def _trace_store_class() -> Any:
    module = importlib.import_module(
        "nds_disassembly_toolkit.analysis.runtime.trace_store"
    )
    return module.TraceStore


def _snapshot(
    *,
    cpu: RuntimeCpu = RuntimeCpu.ARM9,
    pc: int = 0x02000004,
    stop_kind: StopReasonKind = StopReasonKind.STEP,
) -> RuntimeSnapshot:
    return RuntimeSnapshot(
        cpu=cpu,
        registers=RegisterSnapshot.from_mapping(
            {"r0": 1, "pc": pc, "cpsr": 0x1F}
        ),
        stop=RuntimeStop(stop_kind, signal=5, address=pc, raw="S05"),
    )


def _event(
    ordinal: int,
    *,
    cpu: RuntimeCpu = RuntimeCpu.ARM9,
    role: TraceEventRole = TraceEventRole.EVIDENCE,
) -> TraceEvent:
    return TraceEvent.from_snapshot(ordinal, role, _snapshot(cpu=cpu))


def _step_config(
    *, memory_regions: tuple[TraceMemoryRegion, ...] = ()
) -> TraceCaptureConfig:
    return TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=4,
        timeout=5.0,
        memory_regions=memory_regions,
        label="unit trace",
        project_fingerprint="1" * 64,
        toolkit_version="0.1.0",
    )


def _summary(
    trace: Path,
    *,
    evidence_events: int = 1,
    control_events: int = 0,
    memory_regions: int = 0,
) -> TraceSummary:
    return TraceSummary(
        trace=trace,
        cpu=RuntimeCpu.ARM9,
        capture_mode=TraceCaptureMode.STEP,
        evidence_events=evidence_events,
        control_events=control_events,
        memory_regions=memory_regions,
        terminated_by=TraceTermination.LIMIT,
        project_fingerprint="1" * 64,
    )


def test_trace_store_round_trips_complete_trace(tmp_path: Path) -> None:
    TraceStore = _trace_store_class()
    destination = tmp_path / "capture.ndstrace"
    region = TraceMemoryRegion(0, 0x02100000, 4, "value")
    config = _step_config(memory_regions=(region,))
    before = MemorySnapshot.from_bytes(
        region, MemorySnapshotPhase.BEFORE, b"\x00\x01\x02\x03"
    )
    after = MemorySnapshot.from_bytes(
        region, MemorySnapshotPhase.AFTER, b"\x00\x01\x05\x03"
    )
    event = _event(0)
    summary = _summary(destination, memory_regions=1)

    with TraceStore.create_atomic(destination, config) as store:
        store.append_event(event)
        store.store_memory_snapshot(before)
        store.store_memory_snapshot(after)
        store.finalize(summary)

    assert destination.is_file()
    assert not destination.with_suffix(".ndstrace.tmp").exists()

    reopened = TraceStore.open(destination)
    try:
        assert reopened.config == config
        assert reopened.summary == summary
        assert reopened.events() == (event,)
        assert reopened.memory_regions() == (region,)
        assert reopened.memory_snapshot(0, MemorySnapshotPhase.BEFORE) == before
        assert reopened.memory_snapshot(0, MemorySnapshotPhase.AFTER) == after
    finally:
        reopened.close()


def test_failed_atomic_trace_preserves_existing_destination(tmp_path: Path) -> None:
    TraceStore = _trace_store_class()
    destination = tmp_path / "capture.ndstrace"
    destination.write_bytes(b"known-good")

    with pytest.raises(RuntimeError, match="capture failed"):
        with TraceStore.create_atomic(destination, _step_config()) as store:
            store.append_event(_event(0))
            raise RuntimeError("capture failed")

    assert destination.read_bytes() == b"known-good"
    assert not destination.with_suffix(".ndstrace.tmp").exists()


def test_trace_store_open_rejects_incomplete_trace(tmp_path: Path) -> None:
    TraceStore = _trace_store_class()
    destination = tmp_path / "capture.ndstrace"
    temporary = destination.with_suffix(".ndstrace.tmp")

    with TraceStore.create_atomic(destination, _step_config()):
        with pytest.raises(RuntimeTraceFormatError, match="incomplete"):
            TraceStore.open(temporary)


def test_trace_store_open_rejects_future_schema(tmp_path: Path) -> None:
    TraceStore = _trace_store_class()
    destination = tmp_path / "capture.ndstrace"
    with TraceStore.create_atomic(destination, _step_config()) as store:
        store.append_event(_event(0))
        store.finalize(_summary(destination))

    with sqlite3.connect(destination) as connection:
        connection.execute(
            "UPDATE metadata SET value = '2' WHERE key = 'trace_schema_version'"
        )
        connection.commit()

    with pytest.raises(RuntimeTraceFormatError, match="schema version"):
        TraceStore.open(destination)


def test_trace_store_finalize_rejects_event_ordinal_gap(tmp_path: Path) -> None:
    TraceStore = _trace_store_class()
    destination = tmp_path / "capture.ndstrace"

    with TraceStore.create_atomic(destination, _step_config()) as store:
        store.append_event(_event(0))
        store.append_event(_event(2))
        with pytest.raises(RuntimeTraceFormatError, match="event ordinals"):
            store.finalize(_summary(destination, evidence_events=2))

    assert not destination.exists()


def test_trace_store_finalize_requires_memory_snapshot_pair(tmp_path: Path) -> None:
    TraceStore = _trace_store_class()
    destination = tmp_path / "capture.ndstrace"
    region = TraceMemoryRegion(0, 0x02100000, 4)

    with TraceStore.create_atomic(
        destination, _step_config(memory_regions=(region,))
    ) as store:
        store.append_event(_event(0))
        store.store_memory_snapshot(
            MemorySnapshot.from_bytes(
                region, MemorySnapshotPhase.BEFORE, b"\x00\x00\x00\x00"
            )
        )
        with pytest.raises(RuntimeTraceFormatError, match="memory snapshots"):
            store.finalize(_summary(destination, memory_regions=1))


def test_trace_store_finalize_rejects_summary_count_mismatch(tmp_path: Path) -> None:
    TraceStore = _trace_store_class()
    destination = tmp_path / "capture.ndstrace"

    with TraceStore.create_atomic(destination, _step_config()) as store:
        store.append_event(_event(0))
        with pytest.raises(RuntimeTraceFormatError, match="summary counts"):
            store.finalize(_summary(destination, evidence_events=2))
