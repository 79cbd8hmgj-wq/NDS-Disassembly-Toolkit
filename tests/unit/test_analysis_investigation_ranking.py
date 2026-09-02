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
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    OperandAccess,
    OperandKind,
)
from nds_disassembly_toolkit.analysis.investigation import (
    InvestigationEvidenceKind,
    InvestigationRequest,
    investigate_project,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject, ComponentAnalysisBundle
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.analysis.runtime.model import RegisterSnapshot, RuntimeStop, StopReasonKind
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceEvent,
    TraceEventRole,
    TraceSummary,
    TraceTermination,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore

BASE = 0x02000000


def _function(address: int, *, component: str = "arm9", base: int = BASE) -> FunctionCandidate:
    return FunctionCandidate(
        component,
        address,
        address - base,
        InstructionSet.ARM,
        "high",
        ("test",),
    )


def _cfg(function: FunctionCandidate, immediate: int | None = None) -> FunctionControlFlowGraph:
    operands: tuple[InstructionOperand, ...] = ()
    if immediate is not None:
        operands = (
            InstructionOperand(
                OperandKind.IMMEDIATE,
                OperandAccess.READ,
                immediate=immediate,
            ),
        )
    instruction = DecodedInstruction(
        function.address,
        4,
        bytes(4),
        "mov",
        "r0, r0",
        InstructionSet.ARM,
        ControlFlowKind.ORDINARY,
        semantics=InstructionSemantics(operands=operands),
    )
    return FunctionControlFlowGraph(
        function,
        (BasicBlock(function.component, function.address, function.offset, InstructionSet.ARM, (instruction,)),),
        (),
        (),
        (),
    )


def _call(source: FunctionCandidate, target: FunctionCandidate | tuple[int, InstructionSet]) -> CrossReference:
    if isinstance(target, FunctionCandidate):
        target_address = target.address
        target_mode = target.instruction_set
    else:
        target_address, target_mode = target
    return CrossReference(
        CrossReferenceKind.CALL,
        source.component,
        source.address,
        source.address,
        source.instruction_set,
        target_address,
        target_mode,
    )


def _write_trace(path: Path, pcs: tuple[int, ...]) -> None:
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=max(1, len(pcs)),
        timeout=5.0,
    )
    with TraceStore.create_atomic(path, config) as store:
        for ordinal, pc in enumerate(pcs):
            registers = RegisterSnapshot.from_mapping({"pc": pc, "cpsr": 0x13})
            store.append_event(
                TraceEvent(
                    ordinal=ordinal,
                    role=TraceEventRole.EVIDENCE,
                    cpu=RuntimeCpu.ARM9,
                    pc=pc,
                    cpsr=0x13,
                    instruction_set=InstructionSet.ARM,
                    stop=RuntimeStop(StopReasonKind.STEP, address=pc),
                    registers=registers,
                )
            )
        store.finalize(
            TraceSummary(
                trace=path,
                cpu=RuntimeCpu.ARM9,
                capture_mode=TraceCaptureMode.STEP,
                evidence_events=len(pcs),
                control_events=0,
                memory_regions=0,
                terminated_by=TraceTermination.LIMIT,
                project_fingerprint=None,
            )
        )


def test_call_neighbor_is_one_hop_in_both_directions(tmp_path: Path) -> None:
    direct = _function(BASE)
    caller = _function(BASE + 0x40)
    callee = _function(BASE + 0x80)
    second_hop = _function(BASE + 0xC0)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x200))
    calls = (
        _call(caller, direct),
        _call(direct, callee),
        _call(callee, second_hop),
    )
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(direct, caller, callee, second_hop),
                cfgs=(_cfg(direct, 123), _cfg(caller), _cfg(callee), _cfg(second_hop)),
                xrefs=calls,
            )
        )

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(project, InvestigationRequest(constants=(123,)))

    by_address = {item.function.address: item for item in report.candidates}
    assert by_address[direct.address].score == pytest.approx(0.20)
    assert by_address[caller.address].score == pytest.approx(0.05)
    assert by_address[callee.address].score == pytest.approx(0.05)
    assert second_hop.address not in by_address
    assert by_address[caller.address].evidence[0].kind is InvestigationEvidenceKind.CALL_NEIGHBOR


def test_ambiguous_overlapping_callee_is_not_guessed(tmp_path: Path) -> None:
    direct = _function(BASE)
    overlap = 0x02200000
    overlay_3 = _function(overlap, component="overlay_3", base=overlap)
    overlay_7 = _function(overlap, component="overlay_7", base=overlap)
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("arm9", Path("arm9.bin"), BASE, bytes(0x80)),
                functions=(direct,),
                cfgs=(_cfg(direct, 55),),
                xrefs=(_call(direct, (overlap, InstructionSet.ARM)),),
            )
        )
        for name, function in (("overlay_3", overlay_3), ("overlay_7", overlay_7)):
            project.store_component_analysis(
                ComponentAnalysisBundle(
                    Component(name, Path(f"{name}.bin"), overlap, bytes(0x40)),
                    functions=(function,),
                    cfgs=(_cfg(function),),
                )
            )

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(project, InvestigationRequest(constants=(55,)))

    assert [(item.function.component, item.function.address) for item in report.candidates] == [
        ("arm9", direct.address)
    ]


def test_runtime_differential_is_fused_without_reimplementing_trace_ranking(tmp_path: Path) -> None:
    target_function = _function(BASE)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(target_function,),
                cfgs=(_cfg(target_function),),
            )
        )

    baseline = tmp_path / "baseline.ndstrace"
    target = tmp_path / "target.ndstrace"
    _write_trace(baseline, (BASE + 0x80,))
    _write_trace(target, (target_function.address,))

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(
            project,
            InvestigationRequest(baseline_trace=baseline, target_trace=target),
        )

    assert len(report.candidates) == 1
    candidate = report.candidates[0]
    runtime = next(
        item
        for item in candidate.evidence
        if item.kind is InvestigationEvidenceKind.RUNTIME_DIFFERENTIAL
    )
    assert 0.0 < runtime.value <= 1.0
    assert runtime.weight == pytest.approx(0.35)
    assert runtime.contribution == pytest.approx(runtime.value * 0.35)
    assert any("runtime" in reason.lower() for reason in runtime.reasons)


def test_equal_scores_sort_by_component_address_and_mode(tmp_path: Path) -> None:
    first = _function(BASE)
    second = _function(BASE + 0x40)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(second, first),
                cfgs=(_cfg(second, 9), _cfg(first, 9)),
            )
        )

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(project, InvestigationRequest(constants=(9,)))

    assert [item.function.address for item in report.candidates] == [first.address, second.address]
    assert report.candidates[0].score == pytest.approx(report.candidates[1].score)
