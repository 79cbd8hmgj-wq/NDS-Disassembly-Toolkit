from __future__ import annotations

from pathlib import Path

from nds_disassembly_toolkit.analysis.decompiler.lift import lift_function
from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    CallStatement,
    ConstantExpression,
    DecompilerVariable,
    DecompilerVariableKind,
    ReturnStatement,
    UnknownStatement,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.names import NameContext
from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    ArgumentEvidence,
    ArgumentLocationKind,
    BasicBlock,
    BlockFlowState,
    Component,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    FunctionSummary,
    InstructionFlowState,
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    MemoryOperand,
    OperandAccess,
    OperandKind,
    Register,
    RegisterState,
    ReturnEvidence,
    StackFrame,
    StackSlot,
    StackSlotKind,
    StackState,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject, ComponentAnalysisBundle

BASE = 0x02000000
CALLEE = BASE + 0x40
OVERLAY_BASE = 0x02200000


def _value(value: int) -> AbstractValue:
    return AbstractValue(AbstractValueKind.CONSTANT, value)


def _function(
    address: int = BASE,
    *,
    component: str = "arm9",
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


def _instruction(
    address: int,
    mnemonic: str,
    semantics: InstructionSemantics,
    *,
    control_flow: ControlFlowKind = ControlFlowKind.ORDINARY,
    direct_target: int | None = None,
    target_instruction_set: InstructionSet | None = None,
) -> DecodedInstruction:
    return DecodedInstruction(
        address,
        4,
        b"\x00" * 4,
        mnemonic,
        "misleading display text",
        InstructionSet.ARM,
        control_flow,
        direct_target,
        target_instruction_set,
        False,
        semantics,
    )


def _cfg(function: FunctionCandidate, *instructions: DecodedInstruction) -> FunctionControlFlowGraph:
    block = BasicBlock(
        function.component,
        function.address,
        function.offset,
        function.instruction_set,
        tuple(instructions),
    )
    return FunctionControlFlowGraph(function, (block,), (), (), ())


def _empty_names() -> NameContext:
    return NameContext("entry", (), (), (), (), ())


def _persist_callee(project: AnalysisProject) -> None:
    function = _function(CALLEE)
    block = BasicBlock("arm9", CALLEE, CALLEE - BASE, InstructionSet.ARM, ())
    cfg = FunctionControlFlowGraph(function, (block,), (), (), ())
    summary = FunctionSummary(
        (
            ArgumentEvidence(0, ArgumentLocationKind.REGISTER, Register.R0, None, (CALLEE,)),
            ArgumentEvidence(1, ArgumentLocationKind.REGISTER, Register.R1, None, (CALLEE,)),
        ),
        (),
        StackFrame(0, None, True),
        (),
    )
    flow = FunctionDataFlow(
        function,
        (
            BlockFlowState(
                CALLEE,
                InstructionSet.ARM,
                RegisterState(),
                RegisterState(),
                StackState(0),
                StackState(0),
            ),
        ),
        (),
        (),
        summary,
    )
    project.store_component_analysis(
        ComponentAnalysisBundle(
            Component("arm9", Path("arm9.bin"), BASE, bytes(0x100)),
            functions=(function,),
            cfgs=(cfg,),
            symbols=SymbolTable(
                (
                    Symbol(
                        "arm9",
                        CALLEE,
                        CALLEE - BASE,
                        "callee_func",
                        SymbolKind.FUNCTION,
                        InstructionSet.ARM,
                        "high",
                        ("test",),
                    ),
                )
            ),
            data_flows=(flow,),
        )
    )


def test_stack_local_load_store_uses_recovered_local_name(tmp_path: Path) -> None:
    function = _function()
    memory = InstructionOperand(
        OperandKind.MEMORY,
        OperandAccess.READ,
        memory=MemoryOperand(Register.SP, None, 1, -4),
        access_width=4,
    )
    load = _instruction(
        BASE,
        "ldr",
        InstructionSemantics(
            (
                InstructionOperand(OperandKind.REGISTER, OperandAccess.WRITE, register=Register.R2),
                memory,
            ),
            (Register.SP,),
            (Register.R2,),
        ),
    )
    store_memory = InstructionOperand(
        OperandKind.MEMORY,
        OperandAccess.WRITE,
        memory=MemoryOperand(Register.SP, None, 1, -4),
        access_width=4,
    )
    store = _instruction(
        BASE + 4,
        "str",
        InstructionSemantics(
            (
                InstructionOperand(OperandKind.REGISTER, OperandAccess.READ, register=Register.R0),
                store_memory,
            ),
            (Register.R0, Register.SP),
            (),
        ),
    )
    local = DecompilerVariable("local_04", DecompilerVariableKind.LOCAL, stack_offset=-4)
    names = NameContext("entry", (), (local,), (), (), ((-4, local),))
    summary = FunctionSummary((), (), StackFrame(4, None, True), (StackSlot(-4, StackSlotKind.LOCAL),))
    flow = FunctionDataFlow(
        function,
        (),
        (
            InstructionFlowState(load, RegisterState(), RegisterState(), StackState(0), StackState(0)),
            InstructionFlowState(
                store,
                RegisterState(((Register.R0, _value(7)),)),
                RegisterState(((Register.R0, _value(7)),)),
                StackState(0),
                StackState(0),
            ),
        ),
        (),
        summary,
    )
    with AnalysisProject.create(tmp_path / "stack.ndsre") as project:
        lifted = lift_function(project, function, _cfg(function, load, store), flow, names)

    first = lifted.blocks[0].statements[0]
    assert isinstance(first, AssignmentStatement)
    assert isinstance(first.value, VariableExpression)
    assert first.value.variable.name == "local_04"
    second = lifted.blocks[0].statements[1]
    assert isinstance(second, AssignmentStatement)
    assert isinstance(second.target, VariableExpression)
    assert second.target.variable.name == "local_04"


def test_direct_call_uses_unique_target_symbol_and_proven_register_args(tmp_path: Path) -> None:
    function = _function()
    call = _instruction(
        BASE,
        "bl",
        InstructionSemantics(registers_read=(Register.R0, Register.R1)),
        control_flow=ControlFlowKind.CALL,
        direct_target=CALLEE,
        target_instruction_set=InstructionSet.ARM,
    )
    flow = FunctionDataFlow(
        function,
        (),
        (
            InstructionFlowState(
                call,
                RegisterState(((Register.R0, _value(7)), (Register.R1, _value(8)))),
                RegisterState(),
            ),
        ),
    )
    with AnalysisProject.create(tmp_path / "call.ndsre") as project:
        _persist_callee(project)
        lifted = lift_function(project, function, _cfg(function, call), flow, _empty_names())

    statement = lifted.blocks[0].statements[0]
    assert isinstance(statement, CallStatement)
    assert statement.call.name == "callee_func"
    assert statement.call.target_component == "arm9"
    assert [argument.value for argument in statement.call.arguments if isinstance(argument, ConstantExpression)] == [7, 8]


def test_ambiguous_overlay_call_keeps_structural_fallback_name(tmp_path: Path) -> None:
    function = _function()
    call = _instruction(
        BASE,
        "blx",
        InstructionSemantics(),
        control_flow=ControlFlowKind.CALL,
        direct_target=OVERLAY_BASE,
        target_instruction_set=InstructionSet.THUMB,
    )
    flow = FunctionDataFlow(function, (), (InstructionFlowState(call, RegisterState(), RegisterState()),))
    with AnalysisProject.create(tmp_path / "overlay.ndsre") as project:
        for component_name in ("overlay_3", "overlay_7"):
            target = _function(
                OVERLAY_BASE,
                component=component_name,
                instruction_set=InstructionSet.THUMB,
            )
            project.store_component_analysis(
                ComponentAnalysisBundle(
                    Component(component_name, Path(f"{component_name}.bin"), OVERLAY_BASE, bytes(0x20)),
                    functions=(target,),
                )
            )
        lifted = lift_function(project, function, _cfg(function, call), flow, _empty_names())

    statement = lifted.blocks[0].statements[0]
    assert isinstance(statement, CallStatement)
    assert statement.call.name == "sub_02200000"
    assert statement.call.target_component is None


def test_return_uses_persisted_return_evidence(tmp_path: Path) -> None:
    function = _function()
    ret = _instruction(
        BASE,
        "bx",
        InstructionSemantics(registers_read=(Register.LR,)),
        control_flow=ControlFlowKind.RETURN,
    )
    summary = FunctionSummary(
        (),
        (ReturnEvidence(BASE, _value(9)),),
        StackFrame(0, None, True),
        (),
    )
    flow = FunctionDataFlow(
        function,
        (),
        (InstructionFlowState(ret, RegisterState(((Register.R0, _value(9)),)), RegisterState()),),
        (),
        summary,
    )
    with AnalysisProject.create(tmp_path / "return.ndsre") as project:
        lifted = lift_function(project, function, _cfg(function, ret), flow, _empty_names())

    statement = lifted.blocks[0].statements[0]
    assert isinstance(statement, ReturnStatement)
    assert isinstance(statement.value, ConstantExpression)
    assert statement.value.value == 9


def test_unsupported_instruction_remains_visible(tmp_path: Path) -> None:
    function = _function()
    unknown = _instruction(BASE, "udf", InstructionSemantics())
    flow = FunctionDataFlow(
        function,
        (),
        (InstructionFlowState(unknown, RegisterState(), RegisterState()),),
    )
    with AnalysisProject.create(tmp_path / "unknown.ndsre") as project:
        lifted = lift_function(project, function, _cfg(function, unknown), flow, _empty_names())

    statement = lifted.blocks[0].statements[0]
    assert isinstance(statement, UnknownStatement)
    assert statement.description == "unresolved instruction: udf misleading display text"
    assert lifted.warnings == ("0x02000000: unresolved instruction",)
