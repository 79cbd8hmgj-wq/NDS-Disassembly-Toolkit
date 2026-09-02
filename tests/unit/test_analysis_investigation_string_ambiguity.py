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
    InstructionSet,
    StringRecord,
)
from nds_disassembly_toolkit.analysis.investigation import (
    InvestigationRequest,
    investigate_project,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject, ComponentAnalysisBundle

ARM9_BASE = 0x02000000
OVERLAY_BASE = 0x02200000


def _function(component: str, address: int, base: int) -> FunctionCandidate:
    return FunctionCandidate(
        component,
        address,
        address - base,
        InstructionSet.ARM,
        "high",
        ("test",),
    )


def _cfg(function: FunctionCandidate) -> FunctionControlFlowGraph:
    instruction = DecodedInstruction(
        function.address,
        4,
        bytes(4),
        "mov",
        "r0, r0",
        InstructionSet.ARM,
        ControlFlowKind.ORDINARY,
    )
    return FunctionControlFlowGraph(
        function,
        (
            BasicBlock(
                function.component,
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


def test_text_xref_does_not_guess_between_overlapping_string_records(tmp_path: Path) -> None:
    caller = _function("arm9", ARM9_BASE, ARM9_BASE)
    xref = CrossReference(
        CrossReferenceKind.DATA_POINTER,
        "arm9",
        caller.address,
        caller.address,
        InstructionSet.ARM,
        OVERLAY_BASE,
        None,
    )
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("arm9", Path("arm9.bin"), ARM9_BASE, bytes(0x40)),
                functions=(caller,),
                cfgs=(_cfg(caller),),
                xrefs=(xref,),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("overlay_3", Path("overlay_3.bin"), OVERLAY_BASE, bytes(0x40)),
                strings=(StringRecord("overlay_3", 0, OVERLAY_BASE, "Power gained"),),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component("overlay_7", Path("overlay_7.bin"), OVERLAY_BASE, bytes(0x40)),
                strings=(StringRecord("overlay_7", 0, OVERLAY_BASE, "Menu state"),),
            )
        )

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(project, InvestigationRequest(text="power"))

    assert report.candidates == ()
