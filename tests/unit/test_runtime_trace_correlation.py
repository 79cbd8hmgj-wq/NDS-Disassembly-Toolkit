from __future__ import annotations

from pathlib import Path

from nds_disassembly_toolkit.analysis import (
    BasicBlock,
    Component,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject, ComponentAnalysisBundle
from nds_disassembly_toolkit.analysis.runtime import (
    RegisterSnapshot,
    RuntimeCpu,
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


def _function(component: str, base: int) -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=base,
        offset=0,
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


def _cfg(function: FunctionCandidate, base: int) -> FunctionControlFlowGraph:
    return FunctionControlFlowGraph(
        function=function,
        blocks=(
            BasicBlock(
                component=function.component,
                address=base,
                offset=0,
                instruction_set=InstructionSet.ARM,
                instructions=(_instruction(base), _instruction(base + 4)),
            ),
        ),
        edges=(),
        unresolved_transfers=(),
        decode_failures=(),
    )


def _event(
    ordinal: int,
    pc: int,
    *,
    role: TraceEventRole = TraceEventRole.EVIDENCE,
) -> TraceEvent:
    registers = RegisterSnapshot.from_mapping({"pc": pc, "cpsr": 0x13})
    return TraceEvent(
        ordinal=ordinal,
        role=role,
        cpu=RuntimeCpu.ARM9,
        pc=pc,
        cpsr=0x13,
        instruction_set=InstructionSet.ARM,
        stop=RuntimeStop(StopReasonKind.STEP, signal=5, raw="S05"),
        registers=registers,
    )


def test_trace_event_correlation_resolves_pc_inside_function(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.correlation import correlate_trace_event

    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    function = _function("arm9", BASE)
    with AnalysisProject.create(tmp_path / "game.ndsre") as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(function,),
                cfgs=(_cfg(function, BASE),),
            )
        )
        correlation = correlate_trace_event(project, _event(0, BASE + 4))

    assert correlation.ambiguous is False
    assert correlation.resolved_function == function
    assert correlation.candidates[0].functions == (function,)


def test_trace_event_correlation_preserves_overlapping_overlay_ambiguity(
    tmp_path: Path,
) -> None:
    from nds_disassembly_toolkit.analysis.runtime.correlation import correlate_trace_event

    overlay_base = 0x02200000
    overlay_3 = Component("overlay_3", Path("overlay_3.bin"), overlay_base, bytes(0x80))
    overlay_7 = Component("overlay_7", Path("overlay_7.bin"), overlay_base, bytes(0x80))
    function_3 = _function("overlay_3", overlay_base)
    function_7 = _function("overlay_7", overlay_base)

    with AnalysisProject.create(tmp_path / "game.ndsre") as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                overlay_7,
                functions=(function_7,),
                cfgs=(_cfg(function_7, overlay_base),),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                overlay_3,
                functions=(function_3,),
                cfgs=(_cfg(function_3, overlay_base),),
            )
        )
        correlation = correlate_trace_event(project, _event(0, overlay_base + 4))

    assert tuple(item.component for item in correlation.candidates) == (
        "overlay_3",
        "overlay_7",
    )
    assert correlation.ambiguous is True
    assert correlation.resolved_function is None


def test_inspect_trace_counts_evidence_only_and_summarizes_memory(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.trace_diff import inspect_trace

    destination = tmp_path / "inspect.ndstrace"
    region = TraceMemoryRegion(0, 0x02100000, 4)
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=2,
        timeout=5.0,
        memory_regions=(region,),
    )
    with TraceStore.create_atomic(destination, config) as store:
        store.append_event(_event(0, BASE + 4))
        store.append_event(_event(1, BASE + 4))
        store.append_event(
            _event(2, BASE + 8, role=TraceEventRole.CONTROL_ADVANCE)
        )
        store.store_memory_snapshot(
            MemorySnapshot.from_bytes(region, MemorySnapshotPhase.BEFORE, b"AAAA")
        )
        store.store_memory_snapshot(
            MemorySnapshot.from_bytes(region, MemorySnapshotPhase.AFTER, b"AABA")
        )
        store.finalize(
            TraceSummary(
                trace=destination,
                cpu=RuntimeCpu.ARM9,
                capture_mode=TraceCaptureMode.STEP,
                evidence_events=2,
                control_events=1,
                memory_regions=1,
                terminated_by=TraceTermination.LIMIT,
                project_fingerprint=None,
            )
        )

    before_bytes = destination.read_bytes()
    report = inspect_trace(destination)

    assert report.trace_schema_version == 1
    assert report.capture_status == "complete"
    assert report.evidence_events == 2
    assert report.control_events == 1
    assert report.integrity_ok is True
    assert len(report.addresses) == 1
    assert report.addresses[0].hit.pc == BASE + 4
    assert report.addresses[0].hit.count == 2
    assert report.addresses[0].hit.frequency == 1.0
    assert report.addresses[0].correlation is None
    assert report.memory_regions[0].changed_bytes == 1
    assert destination.read_bytes() == before_bytes


def test_inspect_trace_optionally_correlates_with_read_only_project(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.runtime.trace_diff import inspect_trace

    project_root = tmp_path / "game.ndsre"
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    function = _function("arm9", BASE)
    with AnalysisProject.create(project_root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(function,),
                cfgs=(_cfg(function, BASE),),
            )
        )

    destination = tmp_path / "inspect.ndstrace"
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=1,
        timeout=5.0,
    )
    with TraceStore.create_atomic(destination, config) as store:
        store.append_event(_event(0, BASE + 4))
        store.finalize(
            TraceSummary(
                trace=destination,
                cpu=RuntimeCpu.ARM9,
                capture_mode=TraceCaptureMode.STEP,
                evidence_events=1,
                control_events=0,
                memory_regions=0,
                terminated_by=TraceTermination.LIMIT,
                project_fingerprint=None,
            )
        )

    with AnalysisProject.open(project_root, read_only=True) as project:
        report = inspect_trace(destination, project=project)

    assert report.addresses[0].correlation is not None
    assert report.addresses[0].correlation.resolved_function == function
