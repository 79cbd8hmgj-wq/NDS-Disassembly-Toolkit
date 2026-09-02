from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from nds_disassembly_toolkit.analysis import (
    BasicBlock,
    Component,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    OperandAccess,
    OperandKind,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from nds_disassembly_toolkit.analysis.investigation import InvestigationRequest, investigate_project
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)
from nds_disassembly_toolkit.errors import DecompilerError

BASE = 0x02000000


def _function(address: int) -> FunctionCandidate:
    return FunctionCandidate("arm9", address, address - BASE, InstructionSet.ARM, "high", ("test",))


def _cfg(function: FunctionCandidate, immediate: int) -> FunctionControlFlowGraph:
    instruction = DecodedInstruction(
        address=function.address,
        size=4,
        data=bytes(4),
        mnemonic="mov",
        operands=f"#{immediate}",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
        semantics=InstructionSemantics(
            operands=(
                InstructionOperand(
                    OperandKind.IMMEDIATE,
                    OperandAccess.READ,
                    immediate=immediate,
                ),
            )
        ),
    )
    return FunctionControlFlowGraph(
        function,
        (BasicBlock("arm9", function.address, function.offset, InstructionSet.ARM, (instruction,)),),
        (),
        (),
        (),
    )


def test_annotation_name_precedes_generated_symbol_and_fallback(tmp_path: Path) -> None:
    annotated = _function(BASE)
    symbolic = _function(BASE + 0x40)
    fallback = _function(BASE + 0x80)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    symbol = Symbol(
        component="arm9",
        address=symbolic.address,
        offset=symbolic.offset,
        name="symbolic_function",
        kind=SymbolKind.FUNCTION,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(annotated, symbolic, fallback),
                cfgs=(_cfg(annotated, 1), _cfg(symbolic, 1), _cfg(fallback, 1)),
                symbols=SymbolTable((symbol,)),
            )
        )
        project.set_annotation(
            LocationAnnotation("arm9", annotated.address, name_override="AnnotatedName")
        )

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(project, InvestigationRequest(constants=(1,)))

    by_address = {item.function.address: item.name for item in report.candidates}
    assert by_address[annotated.address] == "AnnotatedName"
    assert by_address[symbolic.address] == "symbolic_function"
    assert by_address[fallback.address] == f"sub_{fallback.address:08X}"


def test_pseudo_c_runs_only_after_top_truncation(monkeypatch, tmp_path: Path) -> None:
    first = _function(BASE)
    second = _function(BASE + 0x40)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(first, second),
                cfgs=(_cfg(first, 77), _cfg(second, 77)),
            )
        )

    calls: list[int] = []

    def fake_decompile(project, component_name, address, instruction_set):
        calls.append(address)
        return SimpleNamespace(pseudo_c=f"int sub_{address:08X}(void) {{ return 0; }}")

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.investigation.service.decompile_function",
        fake_decompile,
    )

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(
            project,
            InvestigationRequest(constants=(77,), top=1, include_pseudo_c=True),
        )

    assert calls == [first.address]
    assert len(report.candidates) == 1
    assert report.candidates[0].pseudo_c is not None


def test_decompiler_error_is_retained_without_discarding_candidate(
    monkeypatch,
    tmp_path: Path,
) -> None:
    function = _function(BASE)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x40))
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(function,),
                cfgs=(_cfg(function, 88),),
            )
        )

    def fail_decompile(project, component_name, address, instruction_set):
        raise DecompilerError("missing persisted data flow")

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.investigation.service.decompile_function",
        fail_decompile,
    )

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(
            project,
            InvestigationRequest(constants=(88,), include_pseudo_c=True),
        )

    assert len(report.candidates) == 1
    assert report.candidates[0].pseudo_c is None
    assert report.candidates[0].pseudo_c_error == "missing persisted data flow"
