from pathlib import Path

from nds_disassembly_toolkit.analysis import (
    AnalysisProject,
    BasicBlock,
    Component,
    ComponentAnalysisBundle,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    InvestigationEvidenceKind,
    InvestigationRequest,
    OperandAccess,
    OperandKind,
    investigate_project,
)
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


def _function(address: int) -> FunctionCandidate:
    return FunctionCandidate(
        "arm9",
        address,
        address - BASE,
        InstructionSet.ARM,
        "high",
        ("integration",),
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
        (
            BasicBlock(
                "arm9",
                function.address,
                function.offset,
                InstructionSet.ARM,
                (instruction,),
            ),
        ),
        (),
        (),
        (),
    )


def _trace(path: Path, pc: int) -> None:
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=1,
        timeout=5.0,
    )
    registers = RegisterSnapshot.from_mapping({"pc": pc, "cpsr": 0x13})
    with TraceStore.create_atomic(path, config) as store:
        store.append_event(
            TraceEvent(
                ordinal=0,
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
                evidence_events=1,
                control_events=0,
                memory_regions=0,
                terminated_by=TraceTermination.LIMIT,
                project_fingerprint=None,
            )
        )


def test_static_and_runtime_evidence_rank_persisted_target_function(tmp_path: Path) -> None:
    target = _function(BASE)
    unrelated = _function(BASE + 0x40)
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("arm9", Path("arm9.bin"), BASE, bytes(0x100)),
                functions=(target, unrelated),
                cfgs=(_cfg(target, 500), _cfg(unrelated, 7)),
            )
        )

    baseline = tmp_path / "idle.ndstrace"
    action = tmp_path / "action.ndstrace"
    _trace(baseline, unrelated.address)
    _trace(action, target.address)

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(
            project,
            InvestigationRequest(
                constants=(500,),
                baseline_trace=baseline,
                target_trace=action,
            ),
        )

    assert report.candidates[0].function == target
    assert report.candidates[0].score > 0.20
    kinds = {item.kind for item in report.candidates[0].evidence}
    assert InvestigationEvidenceKind.CONSTANT in kinds
    assert InvestigationEvidenceKind.RUNTIME_DIFFERENTIAL in kinds
    assert all(candidate.function != unrelated for candidate in report.candidates)
