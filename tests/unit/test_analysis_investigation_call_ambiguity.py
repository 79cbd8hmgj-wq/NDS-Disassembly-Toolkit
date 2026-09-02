from pathlib import Path

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
from nds_disassembly_toolkit.analysis.investigation import InvestigationRequest, investigate_project
from nds_disassembly_toolkit.analysis.project import AnalysisProject, ComponentAnalysisBundle

BASE = 0x02000000
OVERLAY = 0x02200000


def _function(component: str, address: int, base: int) -> FunctionCandidate:
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
        (
            BasicBlock(
                function.component,
                function.address,
                function.offset,
                function.instruction_set,
                (instruction,),
            ),
        ),
        (),
        (),
        (),
    )


def test_incoming_call_neighbor_does_not_guess_between_overlapping_overlays(
    tmp_path: Path,
) -> None:
    caller = _function("arm9", BASE, BASE)
    overlay_3 = _function("overlay_3", OVERLAY, OVERLAY)
    overlay_7 = _function("overlay_7", OVERLAY, OVERLAY)
    ambiguous_call = CrossReference(
        CrossReferenceKind.CALL,
        caller.component,
        caller.address,
        caller.address,
        caller.instruction_set,
        OVERLAY,
        InstructionSet.ARM,
    )
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("arm9", Path("arm9.bin"), BASE, bytes(0x40)),
                functions=(caller,),
                cfgs=(_cfg(caller),),
                xrefs=(ambiguous_call,),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("overlay_3", Path("overlay_3.bin"), OVERLAY, bytes(0x40)),
                functions=(overlay_3,),
                cfgs=(_cfg(overlay_3, 77),),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("overlay_7", Path("overlay_7.bin"), OVERLAY, bytes(0x40)),
                functions=(overlay_7,),
                cfgs=(_cfg(overlay_7),),
            )
        )

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(project, InvestigationRequest(constants=(77,)))

    assert [(item.function.component, item.function.address) for item in report.candidates] == [
        ("overlay_3", OVERLAY)
    ]
