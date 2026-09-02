from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis import InstructionSet
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.analysis.runtime.model import (
    RegisterSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceEvent,
    TraceEventRole,
    TraceSummary,
    TraceTermination,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore
from nds_disassembly_toolkit.errors import RuntimeTraceMismatchError

A = 0x02000100
B = 0x02000200
C = 0x02000300
CONTROL = 0x02000400


def _event(ordinal: int, pc: int, role: TraceEventRole) -> TraceEvent:
    registers = RegisterSnapshot.from_mapping({"pc": pc, "cpsr": 0x13})
    return TraceEvent(
        ordinal=ordinal,
        role=role,
        cpu=RuntimeCpu.ARM9,
        pc=pc,
        cpsr=0x13,
        instruction_set=InstructionSet.ARM,
        stop=RuntimeStop(StopReasonKind.STEP, address=pc),
        registers=registers,
    )


def _write_trace(
    path: Path,
    evidence_pcs: tuple[int, ...],
    *,
    fingerprint: str | None = None,
    control_pcs: tuple[int, ...] = (),
) -> None:
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=max(1, len(evidence_pcs) + len(control_pcs)),
        timeout=5.0,
        project_fingerprint=fingerprint,
    )
    events = [
        *(_event(index, pc, TraceEventRole.EVIDENCE) for index, pc in enumerate(evidence_pcs)),
        *(
            _event(
                len(evidence_pcs) + index,
                pc,
                TraceEventRole.CONTROL_ADVANCE,
            )
            for index, pc in enumerate(control_pcs)
        ),
    ]
    with TraceStore.create_atomic(path, config) as store:
        for event in events:
            store.append_event(event)
        store.finalize(
            TraceSummary(
                trace=path,
                cpu=RuntimeCpu.ARM9,
                capture_mode=TraceCaptureMode.STEP,
                evidence_events=len(evidence_pcs),
                control_events=len(control_pcs),
                memory_regions=0,
                terminated_by=TraceTermination.LIMIT,
                project_fingerprint=fingerprint,
            )
        )


def test_compare_traces_uses_evidence_only_for_counts_and_frequencies(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces

    baseline = tmp_path / "baseline.ndstrace"
    target = tmp_path / "target.ndstrace"
    _write_trace(baseline, (A, A, B), control_pcs=(CONTROL,))
    _write_trace(target, (A, C, C, C), control_pcs=(CONTROL, CONTROL))

    report = compare_traces(baseline, target)

    assert [
        (
            item.pc,
            item.baseline_hits,
            item.target_hits,
            item.baseline_frequency,
            item.target_frequency,
            item.frequency_delta,
            item.classification,
        )
        for item in report.address_deltas
    ] == [
        (
            A,
            2,
            1,
            pytest.approx(2 / 3),
            pytest.approx(1 / 4),
            pytest.approx(1 / 4 - 2 / 3),
            "shared",
        ),
        (B, 1, 0, pytest.approx(1 / 3), 0.0, pytest.approx(-1 / 3), "baseline_only"),
        (C, 0, 3, 0.0, pytest.approx(3 / 4), pytest.approx(3 / 4), "target_only"),
    ]
    assert all(item.cpu is RuntimeCpu.ARM9 for item in report.address_deltas)
    assert all(item.instruction_set is InstructionSet.ARM for item in report.address_deltas)


def test_compare_traces_verifies_matching_project_fingerprints(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces

    fingerprint = "a" * 64
    baseline = tmp_path / "baseline.ndstrace"
    target = tmp_path / "target.ndstrace"
    _write_trace(baseline, (A,), fingerprint=fingerprint)
    _write_trace(target, (A,), fingerprint=fingerprint)

    report = compare_traces(baseline, target)

    assert report.target_identity_verified is True


def test_compare_traces_rejects_different_known_project_fingerprints(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces

    baseline = tmp_path / "baseline.ndstrace"
    target = tmp_path / "target.ndstrace"
    _write_trace(baseline, (A,), fingerprint="a" * 64)
    _write_trace(target, (A,), fingerprint="b" * 64)

    with pytest.raises(RuntimeTraceMismatchError, match="fingerprint"):
        compare_traces(baseline, target)


def test_compare_traces_allows_missing_project_fingerprint_as_unverified(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces

    baseline = tmp_path / "baseline.ndstrace"
    target = tmp_path / "target.ndstrace"
    _write_trace(baseline, (A,), fingerprint="a" * 64)
    _write_trace(target, (A,))

    report = compare_traces(baseline, target)

    assert report.target_identity_verified is False
