from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    AssignmentStatement,
    BinaryExpression,
    BinaryOperator,
    BranchStatement,
    CompareExpression,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    DecompilerExpression,
    DecompilerStatement,
    RegisterExpression,
    SourceRef,
    UnaryExpression,
    UnaryOperator,
    UnknownExpression,
    UnknownStatement,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.names import NameContext, TemporaryAllocator
from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    CFGEdge,
    ConditionCode,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    InstructionFlowState,
    InstructionOperand,
    OperandKind,
    Register,
    ShiftKind,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject

_U32_MASK = 0xFFFFFFFF
_SCALAR_BASES = (
    "mov",
    "mvn",
    "add",
    "sub",
    "mul",
    "and",
    "orr",
    "eor",
    "lsl",
    "lsr",
    "asr",
    "cmp",
    "tst",
)
_CONDITION_SUFFIXES = frozenset(
    {
        "eq",
        "ne",
        "hs",
        "cs",
        "lo",
        "cc",
        "mi",
        "pl",
        "vs",
        "vc",
        "hi",
        "ls",
        "ge",
        "lt",
        "gt",
        "le",
    }
)
_BINARY_OPERATORS = {
    "add": BinaryOperator.ADD,
    "sub": BinaryOperator.SUBTRACT,
    "mul": BinaryOperator.MULTIPLY,
    "and": BinaryOperator.BITWISE_AND,
    "orr": BinaryOperator.BITWISE_OR,
    "eor": BinaryOperator.BITWISE_XOR,
    "lsl": BinaryOperator.SHIFT_LEFT,
    "lsr": BinaryOperator.SHIFT_RIGHT_LOGICAL,
    "asr": BinaryOperator.SHIFT_RIGHT_ARITHMETIC,
}
_SHIFT_OPERATORS = {
    ShiftKind.LSL: BinaryOperator.SHIFT_LEFT,
    ShiftKind.LSR: BinaryOperator.SHIFT_RIGHT_LOGICAL,
    ShiftKind.ASR: BinaryOperator.SHIFT_RIGHT_ARITHMETIC,
}


def _source(instruction: DecodedInstruction) -> tuple[SourceRef, ...]:
    return (SourceRef(instruction.address, instruction.instruction_set),)


def _flow_state(flow: FunctionDataFlow, address: int) -> InstructionFlowState | None:
    return flow.at_instruction(address)


def _abstract_expression(
    value: AbstractValue,
    source: tuple[SourceRef, ...],
) -> DecompilerExpression | None:
    if value.kind is AbstractValueKind.UNKNOWN or value.value is None:
        return None
    if value.kind is AbstractValueKind.CONSTANT:
        return ConstantExpression(value.value, source)
    return AddressExpression(value.value, value.component, source)


def _argument_variable(
    flow: FunctionDataFlow,
    names: NameContext,
    *,
    address: int,
    register: Register,
) -> VariableExpression | None:
    summary = flow.summary
    if summary is None:
        return None
    variable_by_register = dict(names.register_arguments)
    variable = variable_by_register.get(register)
    if variable is None:
        return None
    for evidence in summary.arguments:
        if evidence.register is register and address in evidence.uses:
            return VariableExpression(variable)
    return None


def _register_expression(
    flow: FunctionDataFlow,
    names: NameContext,
    state: InstructionFlowState,
    register: Register,
    source: tuple[SourceRef, ...],
    current_values: dict[Register, DecompilerExpression],
) -> DecompilerExpression:
    exact = _abstract_expression(state.before.value(register), source)
    if exact is not None:
        return exact
    current = current_values.get(register)
    if current is not None:
        return current
    argument = _argument_variable(
        flow,
        names,
        address=state.address,
        register=register,
    )
    if argument is not None:
        return VariableExpression(argument.variable, source)
    return RegisterExpression(register, source)


def _apply_shift(
    expression: DecompilerExpression,
    operand: InstructionOperand,
    source: tuple[SourceRef, ...],
) -> DecompilerExpression:
    shift = operand.shift
    if shift.kind is ShiftKind.NONE or shift.value == 0:
        return expression
    operator = _SHIFT_OPERATORS.get(shift.kind)
    if operator is None:
        return UnknownExpression(f"unsupported shift_{shift.kind.value}", source)
    return BinaryExpression(
        operator,
        expression,
        ConstantExpression(shift.value & _U32_MASK, source),
        source,
    )


def _operand_expression(
    flow: FunctionDataFlow,
    names: NameContext,
    state: InstructionFlowState,
    operand: InstructionOperand,
    source: tuple[SourceRef, ...],
    current_values: dict[Register, DecompilerExpression],
) -> DecompilerExpression:
    if operand.kind is OperandKind.IMMEDIATE and operand.immediate is not None:
        return ConstantExpression(operand.immediate & _U32_MASK, source)
    if operand.kind is OperandKind.REGISTER and operand.register is not None:
        expression = _register_expression(
            flow,
            names,
            state,
            operand.register,
            source,
            current_values,
        )
        return _apply_shift(expression, operand, source)
    return UnknownExpression(f"unsupported operand_{operand.kind.value}", source)


def _mnemonic_family(instruction: DecodedInstruction) -> str:
    if instruction.control_flow is ControlFlowKind.BRANCH:
        return "branch"
    if instruction.control_flow is ControlFlowKind.CALL:
        return "call"
    if instruction.control_flow is ControlFlowKind.RETURN:
        return "return"

    raw = instruction.mnemonic.lower().split(".", maxsplit=1)[0]
    for base in _SCALAR_BASES:
        if raw == base:
            return base
        if base not in {"cmp", "tst"} and raw == f"{base}s":
            return base
        if raw.startswith(base):
            suffix = raw[len(base) :]
            if suffix in _CONDITION_SUFFIXES:
                return base
            if suffix.startswith("s") and suffix[1:] in _CONDITION_SUFFIXES:
                return base
    return raw


def _destination(
    instruction: DecodedInstruction,
) -> Register | None:
    if not instruction.semantics.operands:
        return None
    operand = instruction.semantics.operands[0]
    if operand.kind is not OperandKind.REGISTER:
        return None
    return operand.register


def _assignment(
    family: str,
    instruction: DecodedInstruction,
    state: InstructionFlowState,
    flow: FunctionDataFlow,
    names: NameContext,
    temporaries: TemporaryAllocator,
    current_values: dict[Register, DecompilerExpression],
) -> AssignmentStatement | UnknownStatement:
    source = _source(instruction)
    destination = _destination(instruction)
    operands = instruction.semantics.operands
    if destination is None:
        return UnknownStatement("unresolved scalar destination", source)

    if family == "mov" and len(operands) >= 2:
        value = _operand_expression(
            flow,
            names,
            state,
            operands[1],
            source,
            current_values,
        )
    elif family == "mvn" and len(operands) >= 2:
        value = UnaryExpression(
            UnaryOperator.BITWISE_NOT,
            _operand_expression(
                flow,
                names,
                state,
                operands[1],
                source,
                current_values,
            ),
            source,
        )
    elif family in _BINARY_OPERATORS and len(operands) >= 3:
        value = BinaryExpression(
            _BINARY_OPERATORS[family],
            _operand_expression(
                flow,
                names,
                state,
                operands[1],
                source,
                current_values,
            ),
            _operand_expression(
                flow,
                names,
                state,
                operands[2],
                source,
                current_values,
            ),
            source,
        )
    else:
        return UnknownStatement(f"unresolved scalar instruction: {instruction.mnemonic}", source)

    temporary = temporaries.for_definition(instruction.address, destination)
    target = VariableExpression(temporary, source)
    current_values[destination] = target
    return AssignmentStatement(target, value, source)


def _pending_compare(
    family: str,
    instruction: DecodedInstruction,
    state: InstructionFlowState,
    flow: FunctionDataFlow,
    names: NameContext,
    current_values: dict[Register, DecompilerExpression],
) -> tuple[DecompilerExpression, DecompilerExpression] | None:
    operands = instruction.semantics.operands
    source = _source(instruction)
    if len(operands) < 2:
        return None
    left = _operand_expression(
        flow,
        names,
        state,
        operands[0],
        source,
        current_values,
    )
    right = _operand_expression(
        flow,
        names,
        state,
        operands[1],
        source,
        current_values,
    )
    if family == "cmp":
        return left, right
    if family == "tst":
        return (
            BinaryExpression(BinaryOperator.BITWISE_AND, left, right, source),
            ConstantExpression(0, source),
        )
    return None


def _branch(
    instruction: DecodedInstruction,
    pending_compare: tuple[DecompilerExpression, DecompilerExpression] | None,
) -> BranchStatement | UnknownStatement:
    source = _source(instruction)
    if instruction.direct_target is None:
        return UnknownStatement("unresolved direct branch target", source)
    target_mode = instruction.target_instruction_set or instruction.instruction_set
    condition: DecompilerExpression | None = None
    if instruction.conditional:
        code = instruction.semantics.condition
        if pending_compare is None:
            condition = UnknownExpression(f"condition_{code.value}", source)
        else:
            left, right = pending_compare
            condition = CompareExpression(code, left, right, source)
    return BranchStatement(condition, instruction.direct_target, target_mode, source)


def _block_edges(
    cfg: FunctionControlFlowGraph,
    block_address: int,
) -> tuple[CFGEdge, ...]:
    return tuple(
        sorted(
            (edge for edge in cfg.edges if edge.source_address == block_address),
            key=lambda edge: (
                edge.target_address,
                edge.kind.value,
                edge.target_instruction_set.value,
                edge.source_instruction_address,
            ),
        )
    )


def lift_function(
    project: AnalysisProject,
    function: FunctionCandidate,
    cfg: FunctionControlFlowGraph,
    flow: FunctionDataFlow,
    names: NameContext,
) -> DecompiledFunction:
    del project
    if cfg.function != function:
        raise ValueError("CFG does not belong to requested function")
    if flow.function != function:
        raise ValueError("data flow does not belong to requested function")

    temporaries = TemporaryAllocator()
    blocks: list[DecompiledBlock] = []
    warnings = list(flow.warnings)

    for block in sorted(
        cfg.blocks,
        key=lambda item: (item.address, item.instruction_set.value),
    ):
        statements: list[DecompilerStatement] = []
        current_values: dict[Register, DecompilerExpression] = {}
        pending_compare: tuple[DecompilerExpression, DecompilerExpression] | None = None

        for instruction in block.instructions:
            state = _flow_state(flow, instruction.address)
            if state is None:
                source = _source(instruction)
                statements.append(UnknownStatement("missing persisted flow state", source))
                warnings.append(f"0x{instruction.address:08x}: missing persisted flow state")
                continue

            family = _mnemonic_family(instruction)
            if family in {"cmp", "tst"}:
                pending_compare = _pending_compare(
                    family,
                    instruction,
                    state,
                    flow,
                    names,
                    current_values,
                )
                continue
            if family == "branch":
                statements.append(_branch(instruction, pending_compare))
                pending_compare = None
                continue
            if family in {"mov", "mvn", *_BINARY_OPERATORS}:
                if instruction.semantics.condition not in {
                    ConditionCode.AL,
                    ConditionCode.INVALID,
                }:
                    source = _source(instruction)
                    statements.append(
                        UnknownStatement(
                            f"conditional scalar instruction: {instruction.mnemonic}",
                            source,
                        )
                    )
                    warnings.append(
                        f"0x{instruction.address:08x}: conditional scalar instruction"
                    )
                    continue
                statements.append(
                    _assignment(
                        family,
                        instruction,
                        state,
                        flow,
                        names,
                        temporaries,
                        current_values,
                    )
                )
                continue

            source = _source(instruction)
            statements.append(
                UnknownStatement(f"unresolved instruction: {instruction.mnemonic}", source)
            )
            warnings.append(f"0x{instruction.address:08x}: unresolved instruction")

        blocks.append(
            DecompiledBlock(
                block.address,
                block.instruction_set,
                tuple(statements),
                _block_edges(cfg, block.address),
            )
        )

    return DecompiledFunction(
        component=function.component,
        address=function.address,
        instruction_set=function.instruction_set,
        name=names.function_name,
        parameters=names.parameters,
        locals=names.locals + temporaries.variables(),
        blocks=tuple(blocks),
        warnings=tuple(sorted(set(warnings))),
    )
