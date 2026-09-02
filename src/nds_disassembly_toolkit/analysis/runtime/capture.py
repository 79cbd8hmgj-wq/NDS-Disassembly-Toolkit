from __future__ import annotations

from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.runtime.model import (
    BreakpointKind,
    RuntimeCpu,
    RuntimeSnapshot,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    MemorySnapshot,
    MemorySnapshotPhase,
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceEvent,
    TraceEventRole,
    TraceSummary,
    TraceTermination,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore
from nds_disassembly_toolkit.errors import RuntimeTargetStateError


class RuntimeCaptureSession(Protocol):
    @property
    def cpu(self) -> RuntimeCpu: ...

    def read_memory(self, address: int, length: int) -> bytes: ...

    def step(self) -> RuntimeSnapshot: ...

    def run_until_breakpoint(
        self,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot: ...

    def run_until_watchpoint(
        self,
        kind: BreakpointKind,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot: ...


def _capture_memory(
    session: RuntimeCaptureSession,
    config: TraceCaptureConfig,
    store: TraceStore,
    phase: MemorySnapshotPhase,
) -> None:
    for region in config.memory_regions:
        data = session.read_memory(region.address, region.length)
        store.store_memory_snapshot(MemorySnapshot.from_bytes(region, phase, data))


def _condition_snapshot(
    session: RuntimeCaptureSession,
    config: TraceCaptureConfig,
) -> RuntimeSnapshot:
    address = config.condition_address
    length = config.condition_length
    kind = config.condition_kind
    if address is None or length is None or kind is None:
        raise RuntimeTargetStateError("runtime trace condition is incomplete")
    if config.mode is TraceCaptureMode.BREAKPOINT:
        return session.run_until_breakpoint(address, length=length)
    return session.run_until_watchpoint(kind, address, length=length)


def capture_trace(
    session: RuntimeCaptureSession,
    config: TraceCaptureConfig,
    destination: Path,
) -> TraceSummary:
    if session.cpu is not config.cpu:
        raise RuntimeTargetStateError("runtime capture CPU does not match trace config")

    evidence_count = 0
    control_count = 0
    ordinal = 0
    termination = TraceTermination.LIMIT

    with TraceStore.create_atomic(destination, config) as store:
        _capture_memory(session, config, store, MemorySnapshotPhase.BEFORE)

        if config.mode is TraceCaptureMode.STEP:
            while evidence_count < config.limit:
                snapshot = session.step()
                store.append_event(
                    TraceEvent.from_snapshot(ordinal, TraceEventRole.EVIDENCE, snapshot)
                )
                ordinal += 1
                evidence_count += 1
                if snapshot.stop.kind is StopReasonKind.EXITED:
                    termination = TraceTermination.TARGET_EXIT
                    break
        else:
            expected_kind = (
                StopReasonKind.BREAKPOINT
                if config.mode is TraceCaptureMode.BREAKPOINT
                else StopReasonKind.WATCHPOINT
            )
            while evidence_count < config.limit:
                snapshot = _condition_snapshot(session, config)
                if snapshot.stop.kind not in {expected_kind, StopReasonKind.EXITED}:
                    raise RuntimeTargetStateError(
                        "runtime trace stopped for an unexpected reason"
                    )
                store.append_event(
                    TraceEvent.from_snapshot(ordinal, TraceEventRole.EVIDENCE, snapshot)
                )
                ordinal += 1
                evidence_count += 1
                if snapshot.stop.kind is StopReasonKind.EXITED:
                    termination = TraceTermination.TARGET_EXIT
                    break
                if evidence_count == config.limit:
                    break

                advance = session.step()
                store.append_event(
                    TraceEvent.from_snapshot(
                        ordinal,
                        TraceEventRole.CONTROL_ADVANCE,
                        advance,
                    )
                )
                ordinal += 1
                control_count += 1
                if advance.stop.kind is StopReasonKind.EXITED:
                    termination = TraceTermination.TARGET_EXIT
                    break

        _capture_memory(session, config, store, MemorySnapshotPhase.AFTER)
        summary = TraceSummary(
            trace=Path(destination),
            cpu=config.cpu,
            capture_mode=config.mode,
            evidence_events=evidence_count,
            control_events=control_count,
            memory_regions=len(config.memory_regions),
            terminated_by=termination,
            project_fingerprint=config.project_fingerprint,
        )
        store.finalize(summary)
        return summary
