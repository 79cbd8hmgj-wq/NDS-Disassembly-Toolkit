from __future__ import annotations

from pathlib import Path

from nds_disassembly_toolkit.analysis.decompiler.names import (
    TemporaryAllocator,
    build_name_context,
    resolve_call_target,
    sanitize_identifier,
)
from nds_disassembly_toolkit.analysis.model import (
    ArgumentEvidence,
    ArgumentLocationKind,
    BasicBlock,
    BlockFlowState,
    Component,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    FunctionSummary,
    InstructionSet,
    Register,
    RegisterState,
    StackFrame,
    StackSlot,
    StackSlotKind,
    StackState,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)

BASE = 0x02000000
OVERLAY_BASE = 0x02200000


def _function(
    component: str = "arm9",
    address: int = BASE,
    instruction_set: InstructionSet = InstructionSet.ARM,
) -> FunctionCandidate:
    base = BASE if component == "arm9" else OVERLAY_BASE
    return FunctionCandidate(
        component,
        address,
        address - base,
        instruction_set,
        "high",
        ("test",),
    )


def _flow(function: FunctionCandidate) -> FunctionDataFlow:
    return FunctionDataFlow(
        function,
        (),
        (),
        (),
        FunctionSummary(
            (
                ArgumentEvidence(
                    0,
                    ArgumentLocationKind.REGISTER,
                    Register.R0,
                    None,
                    (function.address,),
                ),
                ArgumentEvidence(
                    1,
                    ArgumentLocationKind.REGISTER,
                    Register.R1,
                    None,
                    (function.address + 4,),
                ),
                ArgumentEvidence(
                    None,
                    ArgumentLocationKind.STACK,
                    None,
                    0,
                    (function.address + 8,),
                ),
            ),
            (),
            StackFrame(8, None, True),
            (
                StackSlot(-4, StackSlotKind.LOCAL),
                StackSlot(-8, StackSlotKind.LOCAL),
            ),
        ),
    )


def _persisted_flow(
    function: FunctionCandidate,
) -> tuple[FunctionControlFlowGraph, FunctionDataFlow]:
    block = BasicBlock(
        function.component,
        function.address,
        function.offset,
        function.instruction_set,
        (),
    )
    cfg = FunctionControlFlowGraph(function, (block,), (), (), ())
    flow = FunctionDataFlow(
        function,
        (
            BlockFlowState(
                function.address,
                function.instruction_set,
                RegisterState(),
                RegisterState(),
                StackState(0),
                StackState(0),
            ),
        ),
        (),
        (),
        FunctionSummary(
            (
                ArgumentEvidence(
                    0,
                    ArgumentLocationKind.REGISTER,
                    Register.R0,
                    None,
                    (function.address,),
                ),
                ArgumentEvidence(
                    1,
                    ArgumentLocationKind.REGISTER,
                    Register.R1,
                    None,
                    (function.address,),
                ),
            ),
            (),
            StackFrame(0, None, True),
            (),
        ),
    )
    return cfg, flow


def _named_project(root: Path) -> AnalysisProject:
    entry = _function()
    callee = _function(address=BASE + 0x40)
    callee_cfg, callee_flow = _persisted_flow(callee)
    project = AnalysisProject.create(root)
    project.store_component_analysis(
        ComponentAnalysisBundle(
            Component("arm9", Path("arm9.bin"), BASE, bytes(0x100)),
            functions=(entry, callee),
            cfgs=(callee_cfg,),
            symbols=SymbolTable(
                (
                    Symbol(
                        "arm9",
                        BASE,
                        0,
                        "Generated Entry",
                        SymbolKind.FUNCTION,
                        InstructionSet.ARM,
                        "high",
                        ("test",),
                    ),
                    Symbol(
                        "arm9",
                        BASE + 0x40,
                        0x40,
                        "Callee Symbol",
                        SymbolKind.FUNCTION,
                        InstructionSet.ARM,
                        "high",
                        ("test",),
                    ),
                )
            ),
            data_flows=(callee_flow,),
        )
    )
    project.set_annotation(LocationAnnotation("arm9", BASE, name_override="UserEntry"))
    return project


def _overlapping_project(root: Path) -> AnalysisProject:
    project = AnalysisProject.create(root)
    for component_name in ("overlay_3", "overlay_7"):
        function = _function(
            component_name,
            OVERLAY_BASE,
            InstructionSet.THUMB,
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component(
                    component_name,
                    Path(f"{component_name}.bin"),
                    OVERLAY_BASE,
                    bytes(0x100),
                ),
                functions=(function,),
                symbols=SymbolTable(
                    (
                        Symbol(
                            component_name,
                            OVERLAY_BASE,
                            0,
                            f"{component_name}_target",
                            SymbolKind.FUNCTION,
                            InstructionSet.THUMB,
                            "high",
                            ("test",),
                        ),
                    )
                ),
            )
        )
    return project


def test_function_name_prefers_user_annotation_and_recovers_variables(tmp_path: Path) -> None:
    function = _function()
    with _named_project(tmp_path / "named.ndsre") as project:
        context = build_name_context(project, function, _flow(function))

    assert context.function_name == "UserEntry"
    assert [variable.name for variable in context.parameters] == [
        "arg0",
        "arg1",
        "arg_stack_00",
    ]
    assert context.register_arguments[0][0] is Register.R0
    assert context.register_arguments[0][1].name == "arg0"
    assert context.stack_arguments[0][0] == 0
    assert context.stack_arguments[0][1].name == "arg_stack_00"
    assert [variable.name for variable in context.locals] == ["local_04", "local_08"]


def test_unique_call_target_uses_component_symbol_and_register_signature(tmp_path: Path) -> None:
    with _named_project(tmp_path / "named.ndsre") as project:
        target = resolve_call_target(
            project,
            current_component="arm9",
            address=BASE + 0x40,
            instruction_set=InstructionSet.ARM,
        )

    assert target.component == "arm9"
    assert target.name == "Callee_Symbol"
    assert target.parameter_registers == (Register.R0, Register.R1)


def test_ambiguous_overlay_call_target_is_not_guessed(tmp_path: Path) -> None:
    with _overlapping_project(tmp_path / "overlays.ndsre") as project:
        target = resolve_call_target(
            project,
            current_component="arm9",
            address=OVERLAY_BASE,
            instruction_set=InstructionSet.THUMB,
        )

    assert target.component is None
    assert target.name == "sub_02200000"
    assert target.parameter_registers == ()


def test_temporary_allocator_is_definition_stable() -> None:
    allocator = TemporaryAllocator()

    first = allocator.for_definition(BASE, Register.R2)
    repeated = allocator.for_definition(BASE, Register.R2)
    second = allocator.for_definition(BASE + 4, Register.R2)

    assert first is repeated
    assert first.name == "tmp_0"
    assert second.name == "tmp_1"
    assert allocator.variables() == (first, second)


def test_identifier_sanitization_is_deterministic_and_keyword_safe() -> None:
    assert sanitize_identifier(" 123 bad-name ") == "_123_bad_name"
    assert sanitize_identifier("return") == "return_"
    assert sanitize_identifier("***") == "___"
    assert sanitize_identifier("   ") == "unnamed"
