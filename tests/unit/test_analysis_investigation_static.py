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
    StringRecord,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from nds_disassembly_toolkit.analysis.investigation import (
    InvestigationEvidenceKind,
    InvestigationRequest,
    investigate_project,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)
from nds_disassembly_toolkit.errors import InvestigationError

BASE = 0x02000000


def _function(
    address: int,
    *,
    component: str = "arm9",
    base: int = BASE,
    mode: InstructionSet = InstructionSet.ARM,
) -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=address,
        offset=address - base,
        instruction_set=mode,
        confidence="high",
        evidence=("test",),
    )


def _instruction(
    address: int,
    *,
    mode: InstructionSet = InstructionSet.ARM,
    immediate: int | None = None,
) -> DecodedInstruction:
    operands: tuple[InstructionOperand, ...] = ()
    if immediate is not None:
        operands = (
            InstructionOperand(
                kind=OperandKind.IMMEDIATE,
                access=OperandAccess.READ,
                immediate=immediate,
            ),
        )
    size = 4 if mode is InstructionSet.ARM else 2
    return DecodedInstruction(
        address=address,
        size=size,
        data=bytes(size),
        mnemonic="mov",
        operands=f"#0x{immediate:x}" if immediate is not None else "r0, r0",
        instruction_set=mode,
        control_flow=ControlFlowKind.ORDINARY,
        semantics=InstructionSemantics(operands=operands),
    )


def _cfg(
    function: FunctionCandidate,
    *immediates: int,
) -> FunctionControlFlowGraph:
    size = 4 if function.instruction_set is InstructionSet.ARM else 2
    instructions = tuple(
        _instruction(
            function.address + index * size,
            mode=function.instruction_set,
            immediate=value,
        )
        for index, value in enumerate(immediates)
    ) or (_instruction(function.address, mode=function.instruction_set),)
    return FunctionControlFlowGraph(
        function=function,
        blocks=(
            BasicBlock(
                component=function.component,
                address=function.address,
                offset=function.offset,
                instruction_set=function.instruction_set,
                instructions=instructions,
            ),
        ),
        edges=(),
        unresolved_transfers=(),
        decode_failures=(),
    )


def _kind(candidate: object, kind: InvestigationEvidenceKind):
    return next(item for item in candidate.evidence if item.kind is kind)  # type: ignore[attr-defined]


def test_static_investigation_fuses_string_constant_address_and_annotation_evidence(
    tmp_path: Path,
) -> None:
    f1 = _function(BASE)
    f2 = _function(BASE + 0x40)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x200))
    string = StringRecord("arm9", 0x100, BASE + 0x100, "Gain G-Power")
    string_xref = CrossReference(
        CrossReferenceKind.DATA_POINTER,
        "arm9",
        f1.address,
        f1.address,
        InstructionSet.ARM,
        string.address,
        None,
    )
    external_xref = CrossReference(
        CrossReferenceKind.DATA_POINTER,
        "arm9",
        f1.address + 4,
        f1.address,
        InstructionSet.ARM,
        0x04000208,
        None,
    )
    symbol = Symbol(
        component="arm9",
        address=f1.address,
        offset=f1.offset,
        name="gain_power",
        kind=SymbolKind.FUNCTION,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )
    project_root = tmp_path / "game.ndsre"
    with AnalysisProject.create(project_root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(f1, f2),
                cfgs=(_cfg(f1, 500, 500), _cfg(f2, 7)),
                strings=(string,),
                xrefs=(string_xref, external_xref),
                symbols=SymbolTable((symbol,)),
            )
        )
        project.set_annotation(
            LocationAnnotation(
                "arm9",
                f1.address,
                name_override="GainPower",
                comment="updates G-Power score",
                tags=("gameplay",),
            )
        )

    with AnalysisProject.open(project_root, read_only=True) as project:
        report = investigate_project(
            project,
            InvestigationRequest(
                text="power",
                constants=(500,),
                addresses=(0x04000208,),
                top=10,
            ),
        )

    assert [item.function.address for item in report.candidates] == [f1.address]
    candidate = report.candidates[0]
    assert candidate.name == "GainPower"
    assert candidate.score == pytest.approx(0.25 + 0.20 + 0.15)
    assert [item.kind for item in candidate.evidence] == [
        InvestigationEvidenceKind.TEXT,
        InvestigationEvidenceKind.CONSTANT,
        InvestigationEvidenceKind.ADDRESS_XREF,
    ]
    assert _kind(candidate, InvestigationEvidenceKind.CONSTANT).contribution == pytest.approx(
        0.20
    )
    assert _kind(candidate, InvestigationEvidenceKind.CONSTANT).addresses == (
        f1.address,
        f1.address + 4,
    )
    assert "500" in " ".join(
        _kind(candidate, InvestigationEvidenceKind.CONSTANT).reasons
    )


def test_text_selector_matches_annotation_on_containing_function(tmp_path: Path) -> None:
    function = _function(BASE)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x80))
    project_root = tmp_path / "game.ndsre"
    with AnalysisProject.create(project_root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(function,),
                cfgs=(_cfg(function, 1, 2, 3),),
            )
        )
        project.set_annotation(
            LocationAnnotation(
                "arm9",
                BASE + 4,
                comment="damage calculation",
                tags=("combat",),
            )
        )

    with AnalysisProject.open(project_root, read_only=True) as project:
        report = investigate_project(
            project,
            InvestigationRequest(text="damage"),
        )

    assert [item.function.address for item in report.candidates] == [BASE]
    assert report.candidates[0].score == pytest.approx(0.25)


def test_constant_matching_uses_typed_immediate_not_display_operands(tmp_path: Path) -> None:
    arm = _function(BASE)
    thumb = _function(BASE + 0x40, mode=InstructionSet.THUMB)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    misleading = DecodedInstruction(
        address=arm.address,
        size=4,
        data=bytes(4),
        mnemonic="mov",
        operands="#500",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
        semantics=InstructionSemantics(),
    )
    arm_cfg = FunctionControlFlowGraph(
        function=arm,
        blocks=(
            BasicBlock(
                "arm9",
                arm.address,
                arm.offset,
                InstructionSet.ARM,
                (misleading,),
            ),
        ),
        edges=(),
        unresolved_transfers=(),
        decode_failures=(),
    )
    project_root = tmp_path / "game.ndsre"
    with AnalysisProject.create(project_root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(arm, thumb),
                cfgs=(arm_cfg, _cfg(thumb, 500)),
            )
        )

    with AnalysisProject.open(project_root, read_only=True) as project:
        report = investigate_project(project, InvestigationRequest(constants=(500,)))

    identities = [
        (item.function.address, item.function.instruction_set)
        for item in report.candidates
    ]
    assert identities == [(thumb.address, InstructionSet.THUMB)]


def test_component_filter_preserves_overlapping_overlay_identity(tmp_path: Path) -> None:
    overlay_base = 0x02200000
    f3 = _function(overlay_base, component="overlay_3", base=overlay_base)
    f7 = _function(overlay_base, component="overlay_7", base=overlay_base)
    project_root = tmp_path / "game.ndsre"
    with AnalysisProject.create(project_root) as project:
        for component_name, function in (("overlay_3", f3), ("overlay_7", f7)):
            component = Component(
                component_name,
                Path(f"{component_name}.bin"),
                overlay_base,
                bytes(0x40),
            )
            project.store_component_analysis(
                ComponentAnalysisBundle(
                    component,
                    functions=(function,),
                    cfgs=(_cfg(function, 99),),
                )
            )

    with AnalysisProject.open(project_root, read_only=True) as project:
        report = investigate_project(
            project,
            InvestigationRequest(constants=(99,), component="overlay_7"),
        )

    assert [(item.function.component, item.function.address) for item in report.candidates] == [
        ("overlay_7", overlay_base)
    ]


def test_unknown_component_is_rejected_without_guessing(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root):
        pass
    with (
        AnalysisProject.open(root, read_only=True) as project,
        pytest.raises(InvestigationError, match=r"component.*missing"),
    ):
        investigate_project(
            project,
            InvestigationRequest(text="x", component="missing"),
        )
