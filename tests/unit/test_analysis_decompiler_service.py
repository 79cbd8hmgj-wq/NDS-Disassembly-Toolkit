from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.decompiler import DecompilerError
from nds_disassembly_toolkit.analysis.decompiler.service import decompile_function
from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    BlockFlowState,
    Component,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    FunctionSummary,
    InstructionSet,
    RegisterState,
    StackFrame,
    StackState,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)

BASE = 0x02000000


def _function() -> FunctionCandidate:
    return FunctionCandidate(
        "arm9",
        BASE,
        0,
        InstructionSet.ARM,
        "high",
        ("test",),
    )


def _cfg(function: FunctionCandidate) -> FunctionControlFlowGraph:
    block = BasicBlock("arm9", BASE, 0, InstructionSet.ARM, ())
    return FunctionControlFlowGraph(function, (block,), (), (), ())


def _flow(function: FunctionCandidate) -> FunctionDataFlow:
    return FunctionDataFlow(
        function,
        (
            BlockFlowState(
                BASE,
                InstructionSet.ARM,
                RegisterState(),
                RegisterState(),
                StackState(0),
                StackState(0),
            ),
        ),
        (),
        (),
        FunctionSummary((), (), StackFrame(0, None, True), ()),
    )


def _component() -> Component:
    return Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))


def _store_project(
    root: Path,
    *,
    include_function: bool = True,
    include_cfg: bool = True,
    include_flow: bool = True,
) -> None:
    function = _function()
    cfg = _cfg(function)
    flow = _flow(function)
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                _component(),
                functions=(function,) if include_function else (),
                cfgs=(cfg,) if include_function and include_cfg else (),
                data_flows=(
                    (flow,) if include_function and include_cfg and include_flow else ()
                ),
            )
        )
        if include_function:
            project.set_annotation(
                LocationAnnotation("arm9", BASE, name_override="UserEntry")
            )


def test_decompile_function_works_with_read_only_project(tmp_path: Path) -> None:
    root = tmp_path / "complete.ndsre"
    _store_project(root)

    with AnalysisProject.open(root, read_only=True) as project:
        result = decompile_function(project, "arm9", BASE, InstructionSet.ARM)

    assert result.ir.name == "UserEntry"
    assert result.structured.function is result.ir
    assert result.pseudo_c == "void UserEntry(void) {\n}\n"


@pytest.mark.parametrize(
    ("include_function", "include_cfg", "include_flow", "expected"),
    (
        (False, False, False, "no persisted function for arm9 0x02000000 (arm)"),
        (True, False, False, "no persisted CFG for arm9 0x02000000 (arm)"),
        (True, True, False, "no persisted data flow for arm9 0x02000000 (arm)"),
    ),
)
def test_decompile_function_reports_exact_missing_evidence(
    tmp_path: Path,
    include_function: bool,
    include_cfg: bool,
    include_flow: bool,
    expected: str,
) -> None:
    root = tmp_path / f"missing-{include_function}-{include_cfg}-{include_flow}.ndsre"
    _store_project(
        root,
        include_function=include_function,
        include_cfg=include_cfg,
        include_flow=include_flow,
    )

    with (
        AnalysisProject.open(root, read_only=True) as project,
        pytest.raises(DecompilerError) as captured,
    ):
        decompile_function(project, "arm9", BASE, InstructionSet.ARM)

    assert str(captured.value) == expected


def test_renderer_and_service_are_public_analysis_exports() -> None:
    from nds_disassembly_toolkit.analysis import decompile_function as public_decompile
    from nds_disassembly_toolkit.analysis import render_pseudo_c as public_render

    assert public_decompile is decompile_function
    assert callable(public_render)



def test_decompile_service_runs_ssa_cleanup_before_rendering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nds_disassembly_toolkit.analysis.decompiler.service as service_module
    from nds_disassembly_toolkit.analysis.decompiler.model import (
        AssignmentStatement,
        BinaryExpression,
        BinaryOperator,
        ConstantExpression,
        DecompiledBlock,
        DecompiledFunction,
        DecompilerVariable,
        DecompilerVariableKind,
        RegisterExpression,
        ReturnStatement,
        SourceRef,
        VariableExpression,
    )
    from nds_disassembly_toolkit.analysis.model import Register

    root = tmp_path / "ssa-cleanup.ndsre"
    _store_project(root)

    arg0 = DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )
    source0 = (SourceRef(BASE, InstructionSet.ARM),)
    source1 = (SourceRef(BASE + 4, InstructionSet.ARM),)
    source2 = (SourceRef(BASE + 8, InstructionSet.ARM),)
    lifted = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "UserEntry",
        (arg0,),
        (),
        (
            DecompiledBlock(
                BASE,
                InstructionSet.ARM,
                (
                    AssignmentStatement(
                        RegisterExpression(Register.R1, source0),
                        VariableExpression(arg0, source0),
                        source0,
                    ),
                    AssignmentStatement(
                        RegisterExpression(Register.R2, source1),
                        BinaryExpression(
                            BinaryOperator.ADD,
                            RegisterExpression(Register.R1, source1),
                            ConstantExpression(4, source1),
                            source1,
                        ),
                        source1,
                    ),
                    ReturnStatement(
                        RegisterExpression(Register.R2, source2),
                        source2,
                    ),
                ),
                (),
            ),
        ),
    )

    monkeypatch.setattr(
        service_module,
        "lift_function",
        lambda project, function, cfg, flow, names: lifted,
    )

    with AnalysisProject.open(root, read_only=True) as project:
        result = service_module.decompile_function(
            project,
            "arm9",
            BASE,
            InstructionSet.ARM,
        )

    assert len(result.ir.blocks[0].statements) == 1
    returned = result.ir.blocks[0].statements[0]
    assert isinstance(returned, ReturnStatement)
    assert isinstance(returned.value, BinaryExpression)
    assert isinstance(returned.value.left, VariableExpression)
    assert returned.value.left.variable.name == "arg0"
    assert isinstance(returned.value.right, ConstantExpression)
    assert returned.value.right.value == 4
    assert result.pseudo_c == (
        "uint32_t UserEntry(uint32_t arg0) {\n"
        "    return (arg0 + 4);\n"
        "}\n"
    )
