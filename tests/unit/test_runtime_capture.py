from __future__ import annotations

from collections import deque
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.runtime import (
    BreakpointKind,
    RegisterSnapshot,
    RuntimeConnectionError,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceEventRole,
    TraceMemoryRegion,
    TraceTermination,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore


def _snapshot(
    pc: int,
    *,
    kind: StopReasonKind = StopReasonKind.STEP,
    address: int | None = None,
) -> RuntimeSnapshot:
    return RuntimeSnapshot(
        cpu=RuntimeCpu.ARM9,
        registers=RegisterSnapshot.from_mapping({"pc": pc, "cpsr": 0x13}),
        stop=RuntimeStop(kind, signal=5, address=address, raw="S05"),
    )


class FakeSession:
    cpu = RuntimeCpu.ARM9

    def __init__(
        self,
        *,
        steps: tuple[RuntimeSnapshot, ...] = (),
        breakpoints: tuple[RuntimeSnapshot, ...] = (),
        watchpoints: tuple[RuntimeSnapshot, ...] = (),
        memory: dict[tuple[int, int], deque[bytes | Exception]] | None = None,
    ) -> None:
        self.steps = deque(steps)
        self.breakpoints = deque(breakpoints)
        self.watchpoints = deque(watchpoints)
        self.memory = memory or {}
        self.calls: list[tuple[object, ...]] = []

    def read_memory(self, address: int, length: int) -> bytes:
        self.calls.append(("read_memory", address, length))
        value = self.memory[(address, length)].popleft()
        if isinstance(value, Exception):
            raise value
        return value

    def step(self) -> RuntimeSnapshot:
        self.calls.append(("step",))
        return self.steps.popleft()

    def run_until_breakpoint(
        self,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        self.calls.append(("run_until_breakpoint", address, length))
        return self.breakpoints.popleft()

    def run_until_watchpoint(
        self,
        kind: BreakpointKind,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        self.calls.append(("run_until_watchpoint", kind, address, length))
        return self.watchpoints.popleft()


def test_step_capture_persists_bounded_evidence_events(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.capture import capture_trace

    destination = tmp_path / "steps.ndstrace"
    session = FakeSession(
        steps=(
            _snapshot(0x02000004),
            _snapshot(0x02000008),
            _snapshot(0x0200000C),
        )
    )
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=3,
        timeout=5.0,
    )

    summary = capture_trace(session, config, destination)

    assert summary.terminated_by is TraceTermination.LIMIT
    assert summary.evidence_events == 3
    assert summary.control_events == 0
    assert session.calls == [("step",), ("step",), ("step",)]
    with TraceStore.open(destination) as store:
        assert [
            (event.ordinal, event.role, event.pc) for event in store.events()
        ] == [
            (0, TraceEventRole.EVIDENCE, 0x02000004),
            (1, TraceEventRole.EVIDENCE, 0x02000008),
            (2, TraceEventRole.EVIDENCE, 0x0200000C),
        ]


def test_step_capture_stops_on_target_exit(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.capture import capture_trace

    destination = tmp_path / "exit.ndstrace"
    session = FakeSession(
        steps=(
            _snapshot(0x02000004),
            _snapshot(0x02000008, kind=StopReasonKind.EXITED),
        )
    )
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=10,
        timeout=5.0,
    )

    summary = capture_trace(session, config, destination)

    assert summary.terminated_by is TraceTermination.TARGET_EXIT
    assert summary.evidence_events == 2


def test_repeated_breakpoint_capture_advances_before_rearming(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.capture import capture_trace

    destination = tmp_path / "break.ndstrace"
    session = FakeSession(
        steps=(_snapshot(0x0200000C),),
        breakpoints=(
            _snapshot(
                0x02000008,
                kind=StopReasonKind.BREAKPOINT,
                address=0x02000008,
            ),
            _snapshot(
                0x02000008,
                kind=StopReasonKind.BREAKPOINT,
                address=0x02000008,
            ),
        ),
    )
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.BREAKPOINT,
        limit=2,
        timeout=5.0,
        condition_kind=BreakpointKind.CODE,
        condition_address=0x02000008,
        condition_length=4,
    )

    capture_trace(session, config, destination)

    assert session.calls == [
        ("run_until_breakpoint", 0x02000008, 4),
        ("step",),
        ("run_until_breakpoint", 0x02000008, 4),
    ]
    with TraceStore.open(destination) as store:
        assert [
            (event.ordinal, event.role, event.pc) for event in store.events()
        ] == [
            (0, TraceEventRole.EVIDENCE, 0x02000008),
            (1, TraceEventRole.CONTROL_ADVANCE, 0x0200000C),
            (2, TraceEventRole.EVIDENCE, 0x02000008),
        ]


def test_watchpoint_capture_forwards_kind_address_and_length(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.capture import capture_trace

    destination = tmp_path / "watch.ndstrace"
    session = FakeSession(
        watchpoints=(
            _snapshot(
                0x02000100,
                kind=StopReasonKind.WATCHPOINT,
                address=0x02100000,
            ),
        )
    )
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.WATCHPOINT,
        limit=1,
        timeout=5.0,
        condition_kind=BreakpointKind.WRITE,
        condition_address=0x02100000,
        condition_length=8,
    )

    capture_trace(session, config, destination)

    assert session.calls == [
        ("run_until_watchpoint", BreakpointKind.WRITE, 0x02100000, 8),
    ]


def test_capture_reads_memory_before_execution_and_after_final_stop(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.capture import capture_trace

    destination = tmp_path / "memory.ndstrace"
    region = TraceMemoryRegion(0, 0x02100000, 4)
    session = FakeSession(
        steps=(_snapshot(0x02000004),),
        memory={(region.address, region.length): deque((b"AAAA", b"BBBB"))},
    )
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=1,
        timeout=5.0,
        memory_regions=(region,),
    )

    capture_trace(session, config, destination)

    assert session.calls == [
        ("read_memory", region.address, region.length),
        ("step",),
        ("read_memory", region.address, region.length),
    ]
    with TraceStore.open(destination) as store:
        before = store.memory_snapshot(0, store.config.memory_regions and __import__(
            "nds_disassembly_toolkit.analysis.runtime.trace_model",
            fromlist=["MemorySnapshotPhase"],
        ).MemorySnapshotPhase.BEFORE)
        after = store.memory_snapshot(0, __import__(
            "nds_disassembly_toolkit.analysis.runtime.trace_model",
            fromlist=["MemorySnapshotPhase"],
        ).MemorySnapshotPhase.AFTER)
        assert before is not None and before.data == b"AAAA"
        assert after is not None and after.data == b"BBBB"


def test_failed_after_read_preserves_existing_destination(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.capture import capture_trace

    destination = tmp_path / "capture.ndstrace"
    destination.write_bytes(b"known-good")
    region = TraceMemoryRegion(0, 0x02100000, 4)
    session = FakeSession(
        steps=(_snapshot(0x02000004),),
        memory={
            (region.address, region.length): deque(
                (b"AAAA", RuntimeConnectionError("peer exited"))
            )
        },
    )
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=1,
        timeout=5.0,
        memory_regions=(region,),
    )

    with pytest.raises(RuntimeConnectionError, match="peer exited"):
        capture_trace(session, config, destination)

    assert destination.read_bytes() == b"known-good"
    assert not destination.with_suffix(".ndstrace.tmp").exists()
