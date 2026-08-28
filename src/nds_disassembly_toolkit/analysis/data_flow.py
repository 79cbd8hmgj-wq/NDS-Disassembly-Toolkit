from __future__ import annotations

from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    BlockFlowState,
    Component,
    DecodedInstruction,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    InstructionFlowState,
    InstructionOperand,
    OperandKind,
    Register,
    RegisterState,
    ShiftKind,
)

_U32_MASK = 0xFFFFFFFF
_UNKNOWN = AbstractValue(AbstractValueKind.UNKNOWN)


def _u32(value: int) -> int:
    return value & _U32_MASK


def _provenance(*values: AbstractValue, instruction_address: int) -> tuple[int, ...]:
    evidence = {instruction_address}
    for value in values:
        evidence.update(value.provenance)
    return tuple(sorted(evidence))


def _constant(value: int, *, provenance: tuple[int, ...] = ()) -> AbstractValue:
    return AbstractValue(
        AbstractValueKind.CONSTANT,
        _u32(value),
        provenance=provenance,
    )


def _address(
    value: int,
    *,
    component: str | None,
    provenance: tuple[int, ...],
) -> AbstractValue:
    return AbstractValue(
        AbstractValueKind.ADDRESS,
        _u32(value),
        component=component,
        provenance=provenance,
    )


def _unshifted(operand: InstructionOperand) -> bool:
    return operand.shift.kind is ShiftKind.NONE and operand.shift.value == 0


def _operand_value(operand: InstructionOperand, state: RegisterState) -> AbstractValue:
    if not _unshifted(operand):
        return _UNKNOWN
    if operand.kind is OperandKind.IMMEDIATE and operand.immediate is not None:
        return _constant(operand.immediate)
    if operand.kind is OperandKind.REGISTER and operand.register is not None:
        return state.value(operand.register)
    return _UNKNOWN


def _destination(instruction: DecodedInstruction) -> Register | None:
    if not instruction.semantics.operands:
        return None
    operand = instruction.semantics.operands[0]
    if operand.kind is not OperandKind.REGISTER:
        return None
    return operand.register


def _invalidate_written_registers(
    state: RegisterState,
    instruction: DecodedInstruction,
) -> RegisterState:
    result = state
    for register in instruction.semantics.registers_written:
        result = result.with_value(register, _UNKNOWN)
    return result


def _refine_memory_roles(
    state: RegisterState,
    instruction: DecodedInstruction,
) -> RegisterState:
    result = state
    for operand in instruction.semantics.operands:
        if operand.kind is not OperandKind.MEMORY or operand.memory is None:
            continue
        for register in (operand.memory.base, operand.memory.index):
            if register is None:
                continue
            value = result.value(register)
            if value.kind is not AbstractValueKind.CONSTANT or value.value is None:
                continue
            result = result.with_value(
                register,
                _address(
                    value.value,
                    component=None,
                    provenance=_provenance(
                        value,
                        instruction_address=instruction.address,
                    ),
                ),
            )
    return result


def _mov_result(
    instruction: DecodedInstruction,
    state: RegisterState,
) -> AbstractValue:
    operands = instruction.semantics.operands
    if len(operands) != 2 or not _unshifted(operands[0]):
        return _UNKNOWN
    source = _operand_value(operands[1], state)
    if source.kind is AbstractValueKind.UNKNOWN:
        return _UNKNOWN
    if source.value is None:
        return _UNKNOWN
    provenance = _provenance(source, instruction_address=instruction.address)
    if source.kind is AbstractValueKind.CONSTANT:
        return _constant(source.value, provenance=provenance)
    return _address(
        source.value,
        component=source.component,
        provenance=provenance,
    )


def _binary_result(
    instruction: DecodedInstruction,
    state: RegisterState,
    *,
    subtract: bool,
) -> AbstractValue:
    operands = instruction.semantics.operands
    if len(operands) != 3 or not _unshifted(operands[0]):
        return _UNKNOWN
    left = _operand_value(operands[1], state)
    right = _operand_value(operands[2], state)
    if left.value is None or right.value is None:
        return _UNKNOWN
    provenance = _provenance(left, right, instruction_address=instruction.address)
    operation = (lambda a, b: a - b) if subtract else (lambda a, b: a + b)
    if (
        left.kind is AbstractValueKind.CONSTANT
        and right.kind is AbstractValueKind.CONSTANT
    ):
        return _constant(operation(left.value, right.value), provenance=provenance)
    if (
        left.kind is AbstractValueKind.ADDRESS
        and right.kind is AbstractValueKind.CONSTANT
    ):
        return _address(
            operation(left.value, right.value),
            component=left.component,
            provenance=provenance,
        )
    if (
        not subtract
        and left.kind is AbstractValueKind.CONSTANT
        and right.kind is AbstractValueKind.ADDRESS
    ):
        return _address(
            left.value + right.value,
            component=right.component,
            provenance=provenance,
        )
    return _UNKNOWN


def _transfer(state: RegisterState, instruction: DecodedInstruction) -> RegisterState:
    refined = _refine_memory_roles(state, instruction)
    result = _invalidate_written_registers(refined, instruction)
    destination = _destination(instruction)
    if destination is None:
        return result

    mnemonic = instruction.mnemonic.lower().split(".", maxsplit=1)[0]
    if mnemonic == "mov":
        value = _mov_result(instruction, refined)
    elif mnemonic == "add":
        value = _binary_result(instruction, refined, subtract=False)
    elif mnemonic == "sub":
        value = _binary_result(instruction, refined, subtract=True)
    else:
        return result
    return result.with_value(destination, value)


def _validate_cfg(
    cfg: FunctionControlFlowGraph,
    component: Component,
) -> None:
    if cfg.function.component != component.name:
        raise ValueError("data-flow function component does not match component")
    for block in cfg.blocks:
        if block.component != component.name:
            raise ValueError("data-flow block component does not match component")
        expected = component.offset_for_address(block.address)
        if block.offset != expected:
            raise ValueError("data-flow block offset does not match component")


def analyze_data_flow(
    cfg: FunctionControlFlowGraph,
    component: Component,
) -> FunctionDataFlow:
    _validate_cfg(cfg, component)
    if len(cfg.blocks) > 1:
        raise ValueError("multi-block data flow requires CFG fixed-point support")
    if not cfg.blocks:
        return FunctionDataFlow(function=cfg.function, blocks=(), instructions=())

    block = cfg.blocks[0]
    current = RegisterState()
    instruction_states: list[InstructionFlowState] = []
    for instruction in block.instructions:
        before = current
        after = _transfer(before, instruction)
        instruction_states.append(
            InstructionFlowState(
                instruction=instruction,
                before=before,
                after=after,
            )
        )
        current = after

    block_state = BlockFlowState(
        address=block.address,
        instruction_set=block.instruction_set,
        entry=RegisterState(),
        exit=current,
    )
    return FunctionDataFlow(
        function=cfg.function,
        blocks=(block_state,),
        instructions=tuple(instruction_states),
    )
