from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis import (
    BasicBlock,
    Component,
    ControlFlowKind,
    CrossReference,
    CrossReferenceKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.analysis.runtime.model import (
    RegisterSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    MemorySnapshot,
    MemorySnapshotPhase,
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceEvent,
    TraceEventRole,
    TraceMemoryRegion,
    TraceSummary,
    TraceTermination,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore

BASE = 0x02000000
MEMORY = 0x02100000
OVERLAY_BASE = 0x02200000


def _function(component: str, address: int, component_base: int) -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=address,
        offset=address - component_base,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )


def _instruction(address: int) -> DecodedInstruction:
    return DecodedInstruction(
        address=address,
        size=4,
        data=b"\x00\x00\xa0\xe1",
        mnemonic="mov",
        operands="r0, r0",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
    )


def _cfg(function: FunctionCandidate) -> FunctionControlFlowGraph:
    return FunctionControlFlowGraph(
        function=function,
        blocks=(
            BasicBlock(
                component=function.component,
                address=function.address,
                offset=function.offset,
                instruction_set=InstructionSet.ARM,
                instructions=(
                    _instruction(function.address),
                    _instruction(function.address + 4),
                ),
            ),
        ),
        edges=(),
        unresolved_transfers=(),
        decode_failures=(),
    )


def _event(ordinal: int, pc: int, stop_kind: StopReasonKind) -> TraceEvent:
    registers = RegisterSnapshot.from_mapping({"pc": pc, "cpsr": 0x13})
    return TraceEvent(
        ordinal=ordinal,
        role=TraceEventRole.EVIDENCE,
        cpu=RuntimeCpu.ARM9,
        pc=pc,
        cpsr=0x13,
        instruction_set=InstructionSet.ARM,
        stop=RuntimeStop(stop_kind, address=pc),
        registers=registers,
    )


def _write_trace(
    path: Path,
    events: tuple[TraceEvent, ...],
    *,
    memory_before: bytes | None = None,
    memory_after: bytes | None = None,
) -> None:
    regions: tuple[TraceMemoryRegion, ...] = ()
    if memory_before is not None or memory_after is not None:
        assert memory_before is not None and memory_after is not None
        assert len(memory_before) == len(memory_after)
        regions = (TraceMemoryRegion(0, MEMORY, len(memory_before)),)
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=max(1, len(events)),
        timeout=5.0,
        memory_regions=regions,
    )
    with TraceStore.create_atomic(path, config) as store:
        for event in events:
            store.append_event(event)
        if regions:
            store.store_memory_snapshot(
                MemorySnapshot.from_bytes(
                    regions[0],
                    MemorySnapshotPhase.BEFORE,
                    memory_before or b"",
                )
            )
            store.store_memory_snapshot(
                MemorySnapshot.from_bytes(
                    regions[0],
                    MemorySnapshotPhase.AFTER,
                    memory_after or b"",
                )
            )
        store.finalize(
            TraceSummary(
                trace=path,
                cpu=RuntimeCpu.ARM9,
                capture_mode=TraceCaptureMode.STEP,
                evidence_events=len(events),
                control_events=0,
                memory_regions=len(regions),
                terminated_by=TraceTermination.LIMIT,
                project_fingerprint=None,
            )
        )


def test_compare_traces_ranks_unambiguous_function_with_transparent_evidence(
    tmp_path: Path,
) -> None:
    from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces

    f1 = _function("arm9", BASE, BASE)
    f2 = _function("arm9", BASE + 0x40, BASE)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x200))
    symbol = Symbol(
        component="arm9",
        address=f1.address,
        offset=0,
        name="target_function",
        kind=SymbolKind.FUNCTION,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )
    memory_xref = CrossReference(
        kind=CrossReferenceKind.DATA_POINTER,
        source_component="arm9",
        source_address=f1.address + 4,
        source_function_address=f1.address,
        source_instruction_set=InstructionSet.ARM,
        target_address=MEMORY + 1,
        target_instruction_set=None,
    )
    neighbor_call = CrossReference(
        kind=CrossReferenceKind.CALL,
        source_component="arm9",
        source_address=f1.address + 4,
        source_function_address=f1.address,
        source_instruction_set=InstructionSet.ARM,
        target_address=f2.address,
        target_instruction_set=InstructionSet.ARM,
    )
    annotation = LocationAnnotation(
        "arm9",
        f1.address,
        name_override="TargetFunction",
        comment="rank me",
        tags=("runtime",),
        bookmarked=True,
    )

    project_root = tmp_path / "game.ndsre"
    with AnalysisProject.create(project_root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(f1, f2),
                cfgs=(_cfg(f1), _cfg(f2)),
                xrefs=(memory_xref, neighbor_call),
                symbols=SymbolTable((symbol,)),
            )
        )
        project.set_annotation(annotation)

    baseline = tmp_path / "baseline.ndstrace"
    target = tmp_path / "target.ndstrace"
    _write_trace(baseline, (_event(0, BASE + 0x100, StopReasonKind.STEP),))
    _write_trace(
        target,
        (
            _event(0, f1.address, StopReasonKind.BREAKPOINT),
            _event(1, f2.address, StopReasonKind.STEP),
        ),
        memory_before=b"AAAA",
        memory_after=b"ABAA",
    )

    with AnalysisProject.open(project_root, read_only=True) as project:
        report = compare_traces(baseline, target, project=project)

    f1_delta = next(item for item in report.function_deltas if item.address == f1.address)
    assert f1_delta.target_hits == 1
    assert f1_delta.baseline_hits == 0
    assert f1_delta.target_frequency == pytest.approx(0.5)
    assert f1_delta.symbols == (symbol,)
    assert f1_delta.annotation == annotation
    assert f1_delta.condition_hit is True
    assert f1_delta.condition_stop_pcs == (f1.address,)
    assert f1_delta.changed_memory_references == (memory_xref,)

    ranked = report.rankings[0]
    assert ranked.address == f1.address
    assert ranked.score == pytest.approx(
        0.30 * 1.0
        + 0.25 * 0.5
        + 0.20 * 1.0
        + 0.15 * 1.0
        + 0.10 * 1.0
    )
    assert [item.name for item in ranked.evidence] == [
        "target_exclusive",
        "positive_frequency_delta",
        "condition_hit",
        "changed_memory_reference",
        "dynamic_neighbor",
    ]
    wording = " ".join(
        reason for evidence in ranked.evidence for reason in evidence.reasons
    ).lower()
    assert "static reference to changed memory" in wording
    assert "runtime writer" not in wording
    assert "probability" not in wording


def test_compare_traces_excludes_ambiguous_overlay_hits_from_function_ranking(
    tmp_path: Path,
) -> None:
    from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces

    overlay_3 = Component(
        "overlay_3", Path("overlay_3.bin"), OVERLAY_BASE, bytes(0x80)
    )
    overlay_7 = Component(
        "overlay_7", Path("overlay_7.bin"), OVERLAY_BASE, bytes(0x80)
    )
    function_3 = _function("overlay_3", OVERLAY_BASE, OVERLAY_BASE)
    function_7 = _function("overlay_7", OVERLAY_BASE, OVERLAY_BASE)
    project_root = tmp_path / "game.ndsre"
    with AnalysisProject.create(project_root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                overlay_3,
                functions=(function_3,),
                cfgs=(_cfg(function_3),),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                overlay_7,
                functions=(function_7,),
                cfgs=(_cfg(function_7),),
            )
        )

    baseline = tmp_path / "baseline.ndstrace"
    target = tmp_path / "target.ndstrace"
    _write_trace(baseline, (_event(0, BASE, StopReasonKind.STEP),))
    _write_trace(target, (_event(0, OVERLAY_BASE + 4, StopReasonKind.STEP),))

    with AnalysisProject.open(project_root, read_only=True) as project:
        report = compare_traces(baseline, target, project=project)

    assert report.function_deltas == ()
    assert report.rankings == ()
    assert len(report.ambiguous_correlations) == 1
    assert report.ambiguous_correlations[0].pc == OVERLAY_BASE + 4
    assert report.ambiguous_correlations[0].ambiguous is True


def test_rankings_break_equal_scores_by_component_address_and_mode(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces

    f1 = _function("arm9", BASE, BASE)
    f2 = _function("arm9", BASE + 0x40, BASE)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    project_root = tmp_path / "game.ndsre"
    with AnalysisProject.create(project_root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(f2, f1),
                cfgs=(_cfg(f2), _cfg(f1)),
            )
        )

    baseline = tmp_path / "baseline.ndstrace"
    target = tmp_path / "target.ndstrace"
    _write_trace(baseline, (_event(0, BASE + 0x80, StopReasonKind.STEP),))
    _write_trace(
        target,
        (
            _event(0, f2.address, StopReasonKind.STEP),
            _event(1, f1.address, StopReasonKind.STEP),
        ),
    )

    with AnalysisProject.open(project_root, read_only=True) as project:
        report = compare_traces(baseline, target, project=project)

    assert [item.address for item in report.rankings] == [f1.address, f2.address]
    assert report.rankings[0].score == pytest.approx(report.rankings[1].score)
