from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.decompiler.lift import lift_function
from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    BinaryExpression,
    BinaryOperator,
    BranchStatement,
    CompareExpression,
    ConstantExpression,
    UnknownExpression,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.names import NameContext
from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    ArgumentEvidence,
    ArgumentLocationKind,
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    ConditionCode,
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
    OperandAccess,
    OperandKind,
    Register,
    RegisterState,
    StackFrame,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject
from nds_disassembly_toolkit.analysis.decompiler.model import (
    DecompilerVariable,
    DecompilerVariableKind,
)

BASE = 0x02000000


def _register_operand(register: Register, access: OperandAccess) -> InstructionOperand:
    return InstructionOperand(
        OperandKind.REGISTER,
        access,
        register=register,
    )


def _immediate_operand(value: int) -> InstructionOperand:
    return InstructionOperand(
        OperandKind.IMMEDIATE,
        OperandAccess.READ,
        immediate=value,
    )


def _instruction(
    address: int,
    mnemonic: str,
    semantics: InstructionSemantics,
    *,
    instruction_set: InstructionSet = InstructionSet.ARM,
    control_flow: ControlFlowKind = ControlFlowKind.ORDINARY,
    direct_target: int | None = None,
    conditional: bool = False,
) -> DecodedInstruction:
    return DecodedInstruction(
        address=address,
        size=instruction_set.alignment,
        data=b"\x00" * instruction_set.alignment,
        mnemonic=mnemonic,
        operands="misleading display text that must never be parsed",
        instruction_set=instruction_set,
        control_flow=control_flow,
        direct_target=direct_target,
        target_instruction_set=instruction_set if direct_target is not None else None,
        conditional=conditional,
        semantics=semantics,
    )


def _function(instruction_set: InstructionSet = InstructionSet.ARM) -> FunctionCandidate:
    return FunctionCandidate(
        "arm9",
        BASE,
        0,
        instruction_set,
        "high",
        ("test",),
    )


def _argument_context(*registers: Register) -> NameContext:
    variables = tuple(
        DecompilerVariable(
            f"arg{index}",
            DecompilerVariableKind.ARGUMENT,
            register=register,
        )
        for index, register in enumerate(registers)
    )
    return NameContext(
        function_name="entry",
        parameters=variables,
        locals=(),
        register_arguments=tuple(zip(registers, variables, strict=True)),
        stack_arguments=(),
        stack_locals=(),
    )


def _summary(*uses: tuple[int, Register, int]) -> FunctionSummary:
    return FunctionSummary(
        tuple(
            ArgumentEvidence(
                index,
                ArgumentLocationKind.REGISTER,
                register,
                None,
                (address,),
            )
            for address, register, index in uses
        ),
        (),
        StackFrame(0, None, True),
        (),
    )


def _value(value: int) -> AbstractValue:
    return AbstractValue(AbstractValueKind.CONSTANT, value)


def _scalar_fixture() -> tuple[
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    NameContext,
]:
    function = _function()
    mov = _instruction(
        BASE,
        "mov",
        InstructionSemantics(
            operands=(
                _register_operand(Register.R2, OperandAccess.WRITE),
                _immediate_operand(1),
            ),
            registers_written=(Register.R2,),
        ),
    )
    add = _instruction(
        BASE + 4,
        "add",
        InstructionSemantics(
            operands=(
                _register_operand(Register.R3, OperandAccess.WRITE),
                _register_operand(Register.R0, OperandAccess.READ),
                _register_operand(Register.R2, OperandAccess.READ),
            ),
            registers_read=(Register.R0, Register.R2),
            registers_written=(Register.R3,),
        ),
    )
    compare = _instruction(
        BASE + 8,
        "cmp",
        InstructionSemantics(
            operands=(
                _register_operand(Register.R3, OperandAccess.READ),
                _immediate_operand(5),
            ),
            registers_read=(Register.R3,),
        ),
    )
    branch = _instruction(
        BASE + 12,
        "beq",
        InstructionSemantics(condition=ConditionCode.EQ),
        control_flow=ControlFlowKind.BRANCH,
        direct_target=BASE + 0x20,
        conditional=True,
    )
    block = BasicBlock(
        "arm9",
        BASE,
        0,
        InstructionSet.ARM,
        (mov, add, compare, branch),
    )
    cfg = FunctionControlFlowGraph(
        function,
        (block,),
        (
            CFGEdge(
                BASE,
                BASE + 12,
                BASE + 0x20,
                InstructionSet.ARM,
                CFGEdgeKind.BRANCH,
            ),
        ),
        (),
        (),
    )
    empty = RegisterState()
    r2 = RegisterState(((Register.R2, _value(1)),))
    flow = FunctionDataFlow(
        function,
        (),
        (
            InstructionFlowState(mov, empty, r2),
            InstructionFlowState(add, r2, r2),
            InstructionFlowState(compare, r2, r2),
            InstructionFlowState(branch, r2, r2),
        ),
        (),
        _summary((BASE + 4, Register.R0, 0)),
    )
    return function, cfg, flow, _argument_context(Register.R0)


def test_arm_mov_add_cmp_branch_lifts_without_operand_string_parsing(
    tmp_path: Path,
) -> None:
    function, cfg, flow, names = _scalar_fixture()
    with AnalysisProject.create(tmp_path / "project.ndsre") as project:
        lifted = lift_function(project, function, cfg, flow, names)

    first = lifted.blocks[0].statements[0]
    assert isinstance(first, AssignmentStatement)
    assert isinstance(first.value, ConstantExpression)
    assert first.value.value == 1

    second = lifted.blocks[0].statements[1]
    assert isinstance(second, AssignmentStatement)
    assert isinstance(second.value, BinaryExpression)
    assert second.value.operator is BinaryOperator.ADD
    assert isinstance(second.value.left, VariableExpression)
    assert second.value.left.variable.name == "arg0"
    assert isinstance(second.value.right, ConstantExpression)
    assert second.value.right.value == 1

    branch = lifted.blocks[0].statements[-1]
    assert isinstance(branch, BranchStatement)
    assert isinstance(branch.condition, CompareExpression)
    assert branch.condition.condition is ConditionCode.EQ
    assert branch.target_address == BASE + 0x20
    assert len(lifted.blocks[0].statements) == 3


def test_thumb_scalar_lifting_uses_same_ir(tmp_path: Path) -> None:
    function = _function(InstructionSet.THUMB)
    instruction = _instruction(
        BASE,
        "mov",
        InstructionSemantics(
            operands=(
                _register_operand(Register.R2, OperandAccess.WRITE),
                _immediate_operand(3),
            ),
            registers_written=(Register.R2,),
        ),
        instruction_set=InstructionSet.THUMB,
    )
    block = BasicBlock("arm9", BASE, 0, InstructionSet.THUMB, (instruction,))
    cfg = FunctionControlFlowGraph(function, (block,), (), (), ())
    flow = FunctionDataFlow(
        function,
        (),
        (InstructionFlowState(instruction, RegisterState(), RegisterState()),),
    )

    with AnalysisProject.create(tmp_path / "thumb.ndsre") as project:
        lifted = lift_function(project, function, cfg, flow, _argument_context())

    assert lifted.instruction_set is InstructionSet.THUMB
    assert isinstance(lifted.blocks[0].statements[0], AssignmentStatement)


@pytest.mark.parametrize(
    ("mnemonic", "operator"),
    [
        ("sub", BinaryOperator.SUBTRACT),
        ("mul", BinaryOperator.MULTIPLY),
        ("and", BinaryOperator.BITWISE_AND),
        ("orr", BinaryOperator.BITWISE_OR),
        ("eor", BinaryOperator.BITWISE_XOR),
        ("lsl", BinaryOperator.SHIFT_LEFT),
        ("lsr", BinaryOperator.SHIFT_RIGHT_LOGICAL),
        ("asr", BinaryOperator.SHIFT_RIGHT_ARITHMETIC),
    ],
)
def test_scalar_operator_family_maps_to_stable_ir(
    tmp_path: Path,
    mnemonic: str,
    operator: BinaryOperator,
) -> None:
    function = _function()
    instruction = _instruction(
        BASE,
        mnemonic,
        InstructionSemantics(
            operands=(
                _register_operand(Register.R2, OperandAccess.WRITE),
                _register_operand(Register.R0, OperandAccess.READ),
                _register_operand(Register.R1, OperandAccess.READ),
            ),
            registers_read=(Register.R0, Register.R1),
            registers_written=(Register.R2,),
        ),
    )
    block = BasicBlock("arm9", BASE, 0, InstructionSet.ARM, (instruction,))
    cfg = FunctionControlFlowGraph(function, (block,), (), (), ())
    flow = FunctionDataFlow(
        function,
        (),
        (InstructionFlowState(instruction, RegisterState(), RegisterState()),),
        (),
        _summary((BASE, Register.R0, 0), (BASE, Register.R1, 1)),
    )

    with AnalysisProject.create(tmp_path / f"{mnemonic}.ndsre") as project:
        lifted = lift_function(
            project,
            function,
            cfg,
            flow,
            _argument_context(Register.R0, Register.R1),
        )

    statement = lifted.blocks[0].statements[0]
    assert isinstance(statement, AssignmentStatement)
    assert isinstance(statement.value, BinaryExpression)
    assert statement.value.operator is operator


def test_conditional_branch_without_compare_keeps_unknown_condition(tmp_path: Path) -> None:
    function = _function()
    branch = _instruction(
        BASE,
        "bne",
        InstructionSemantics(condition=ConditionCode.NE),
        control_flow=ControlFlowKind.BRANCH,
        direct_target=BASE + 0x20,
        conditional=True,
    )
    block = BasicBlock("arm9", BASE, 0, InstructionSet.ARM, (branch,))
    cfg = FunctionControlFlowGraph(function, (block,), (), (), ())
    flow = FunctionDataFlow(
        function,
        (),
        (InstructionFlowState(branch, RegisterState(), RegisterState()),),
    )

    with AnalysisProject.create(tmp_path / "unknown-condition.ndsre") as project:
        lifted = lift_function(project, function, cfg, flow, _argument_context())

    statement = lifted.blocks[0].statements[0]
    assert isinstance(statement, BranchStatement)
    assert isinstance(statement.condition, UnknownExpression)
    assert statement.condition.description == "condition_ne"
