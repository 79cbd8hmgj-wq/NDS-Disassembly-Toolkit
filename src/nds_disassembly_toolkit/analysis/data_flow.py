from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, replace

from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    ArgumentEvidence,
    ArgumentLocationKind,
    BasicBlock,
    BlockFlowState,
    CFGEdgeKind,
    Component,
    ConditionCode,
    ControlFlowKind,
    DecodedInstruction,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    FunctionSummary,
    InstructionFlowState,
    InstructionOperand,
    InstructionSet,
    OperandKind,
    Register,
    RegisterState,
    ReturnEvidence,
    ShiftKind,
    StackSlotKind,
    StackState,
)
from nds_disassembly_toolkit.analysis.stack import analyze_stack

_U32_MASK = 0xFFFFFFFF
_UNKNOWN = AbstractValue(AbstractValueKind.UNKNOWN)
_CALLER_CLOBBERED = (
    Register.R0,
    Register.R1,
    Register.R2,
    Register.R3,
    Register.R12,
    Register.LR,
)
_ENTRY_ARGUMENT_ORDER = (
    Register.R0,
    Register.R1,
    Register.R2,
    Register.R3,
)
_ENTRY_ARGUMENTS = frozenset(_ENTRY_ARGUMENT_ORDER)
_BlockKey = tuple[int, InstructionSet]


@dataclass(frozen=True)
class _FlowState:
    registers: RegisterState
    stack: StackState
    entry_arguments_live: frozenset[Register]


def _u32(value: int) -> int:
    return value & _U32_MASK


def _provenance(
    *values: AbstractValue,
    instruction_address: int,
    enabled: bool,
) -> tuple[int, ...]:
    if not enabled:
        return ()
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


def _same_value(
    left: AbstractValue,
    right: AbstractValue,
    *,
    include_provenance: bool,
) -> bool:
    if (
        left.kind is not right.kind
        or left.value != right.value
        or left.component != right.component
    ):
        return False
    return not include_provenance or left.provenance == right.provenance


def _same_state(
    left: RegisterState,
    right: RegisterState,
    *,
    include_provenance: bool,
) -> bool:
    if len(left.values) != len(right.values):
        return False
    return all(
        left_register is right_register
        and _same_value(
            left_value,
            right_value,
            include_provenance=include_provenance,
        )
        for (left_register, left_value), (right_register, right_value) in zip(
            left.values,
            right.values,
            strict=True,
        )
    )


def _same_flow_state(
    left: _FlowState,
    right: _FlowState,
    *,
    include_provenance: bool,
) -> bool:
    return (
        left.stack == right.stack
        and left.entry_arguments_live == right.entry_arguments_live
        and _same_state(
            left.registers,
            right.registers,
            include_provenance=include_provenance,
        )
    )


def _join_values(
    values: Sequence[AbstractValue],
    *,
    keep_provenance: bool,
) -> AbstractValue:
    if not values:
        return _UNKNOWN
    first = values[0]
    if not all(
        _same_value(first, value, include_provenance=False) for value in values[1:]
    ):
        return _UNKNOWN
    if first.kind is AbstractValueKind.UNKNOWN or first.value is None:
        return _UNKNOWN
    provenance = (
        tuple(sorted({address for value in values for address in value.provenance}))
        if keep_provenance
        else ()
    )
    if first.kind is AbstractValueKind.CONSTANT:
        return _constant(first.value, provenance=provenance)
    return _address(
        first.value,
        component=first.component,
        provenance=provenance,
    )


def _join_states(
    states: Sequence[RegisterState],
    *,
    keep_provenance: bool,
) -> RegisterState:
    if not states:
        return RegisterState()
    values: list[tuple[Register, AbstractValue]] = []
    for register in Register:
        value = _join_values(
            tuple(state.value(register) for state in states),
            keep_provenance=keep_provenance,
        )
        if value.kind is not AbstractValueKind.UNKNOWN:
            values.append((register, value))
    return RegisterState(tuple(values))


def _join_stack_states(states: Sequence[StackState]) -> StackState:
    if not states:
        return StackState(offset=None)
    first_offset = states[0].offset
    offset = first_offset if all(state.offset == first_offset for state in states) else None
    common = dict(states[0].frame_pointers)
    for state in states[1:]:
        current = dict(state.frame_pointers)
        common = {
            register: value
            for register, value in common.items()
            if current.get(register) == value
        }
    return StackState(offset=offset, frame_pointers=tuple(common.items()))


def _join_live_arguments(states: Sequence[_FlowState]) -> frozenset[Register]:
    if not states:
        return frozenset()
    live = set(states[0].entry_arguments_live)
    for state in states[1:]:
        live.intersection_update(state.entry_arguments_live)
    return frozenset(live)


def _join_flow_states(
    states: Sequence[_FlowState],
    *,
    keep_provenance: bool,
) -> _FlowState:
    if not states:
        return _FlowState(RegisterState(), StackState(offset=None), frozenset())
    return _FlowState(
        registers=_join_states(
            tuple(state.registers for state in states),
            keep_provenance=keep_provenance,
        ),
        stack=_join_stack_states(tuple(state.stack for state in states)),
        entry_arguments_live=_join_live_arguments(states),
    )


def _unshifted(operand: InstructionOperand) -> bool:
    return operand.shift.kind is ShiftKind.NONE and operand.shift.value == 0


def _pc_value(instruction: DecodedInstruction) -> int:
    if instruction.instruction_set is InstructionSet.ARM:
        return _u32(instruction.address + 8)
    return _u32((instruction.address + 4) & ~3)


def _operand_value(
    operand: InstructionOperand,
    state: RegisterState,
    instruction: DecodedInstruction,
    component: Component,
) -> AbstractValue:
    if not _unshifted(operand):
        return _UNKNOWN
    if operand.kind is OperandKind.IMMEDIATE and operand.immediate is not None:
        return _constant(operand.immediate)
    if operand.kind is OperandKind.REGISTER and operand.register is not None:
        if operand.register is Register.PC:
            return _address(
                _pc_value(instruction),
                component=component.name,
                provenance=(),
            )
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
    *,
    record_provenance: bool,
) -> RegisterState:
    result = state
    for operand in instruction.semantics.operands:
        if operand.kind is not OperandKind.MEMORY or operand.memory is None:
            continue
        for register in (operand.memory.base, operand.memory.index):
            if register is None or register is Register.PC:
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
                        enabled=record_provenance,
                    ),
                ),
            )
    return result


def _mov_result(
    instruction: DecodedInstruction,
    state: RegisterState,
    component: Component,
    *,
    record_provenance: bool,
) -> AbstractValue:
    operands = instruction.semantics.operands
    if len(operands) != 2 or not _unshifted(operands[0]):
        return _UNKNOWN
    source = _operand_value(operands[1], state, instruction, component)
    if source.kind is AbstractValueKind.UNKNOWN or source.value is None:
        return _UNKNOWN
    provenance = _provenance(
        source,
        instruction_address=instruction.address,
        enabled=record_provenance,
    )
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
    component: Component,
    *,
    subtract: bool,
    record_provenance: bool,
) -> AbstractValue:
    operands = instruction.semantics.operands
    if len(operands) != 3 or not _unshifted(operands[0]):
        return _UNKNOWN
    left = _operand_value(operands[1], state, instruction, component)
    right = _operand_value(operands[2], state, instruction, component)
    if left.value is None or right.value is None:
        return _UNKNOWN
    provenance = _provenance(
        left,
        right,
        instruction_address=instruction.address,
        enabled=record_provenance,
    )
    result_value = left.value - right.value if subtract else left.value + right.value
    if (
        left.kind is AbstractValueKind.CONSTANT
        and right.kind is AbstractValueKind.CONSTANT
    ):
        return _constant(result_value, provenance=provenance)
    if (
        left.kind is AbstractValueKind.ADDRESS
        and right.kind is AbstractValueKind.CONSTANT
    ):
        return _address(
            result_value,
            component=left.component,
            provenance=provenance,
        )
    if (
        not subtract
        and left.kind is AbstractValueKind.CONSTANT
        and right.kind is AbstractValueKind.ADDRESS
    ):
        return _address(
            result_value,
            component=right.component,
            provenance=provenance,
        )
    return _UNKNOWN


def _literal_load_result(
    instruction: DecodedInstruction,
    component: Component,
    warnings: set[str],
    *,
    record_provenance: bool,
) -> AbstractValue | None:
    mnemonic = instruction.mnemonic.lower().split(".", maxsplit=1)[0]
    if mnemonic not in {"ldr", "ldrb", "ldrh"}:
        return None
    operands = instruction.semantics.operands
    if len(operands) < 2:
        return None
    memory_operand = operands[1]
    if memory_operand.kind is not OperandKind.MEMORY or memory_operand.memory is None:
        return None
    memory = memory_operand.memory
    if memory.base is not Register.PC or memory.index is not None:
        return None
    width = memory_operand.access_width
    if width not in {1, 2, 4}:
        return _UNKNOWN

    target = _u32(_pc_value(instruction) + memory.displacement)
    if not (
        component.base_address <= target
        and target + width <= component.end_address
    ):
        warnings.add(
            f"literal read at 0x{instruction.address:08X} is outside "
            f"{component.name}: 0x{target:08X}"
        )
        return _UNKNOWN
    offset = target - component.base_address
    value = int.from_bytes(component.data[offset : offset + width], "little")
    return _constant(
        value,
        provenance=_provenance(
            instruction_address=instruction.address,
            enabled=record_provenance,
        ),
    )


def _transfer_registers_executed(
    state: RegisterState,
    instruction: DecodedInstruction,
    component: Component,
    warnings: set[str],
    *,
    record_provenance: bool,
) -> RegisterState:
    refined = _refine_memory_roles(
        state,
        instruction,
        record_provenance=record_provenance,
    )
    result = _invalidate_written_registers(refined, instruction)
    destination = _destination(instruction)

    if destination is not None:
        literal = _literal_load_result(
            instruction,
            component,
            warnings,
            record_provenance=record_provenance,
        )
        if literal is not None:
            result = result.with_value(destination, literal)
        else:
            mnemonic = instruction.mnemonic.lower().split(".", maxsplit=1)[0]
            if mnemonic == "mov":
                value = _mov_result(
                    instruction,
                    refined,
                    component,
                    record_provenance=record_provenance,
                )
                result = result.with_value(destination, value)
            elif mnemonic == "add":
                value = _binary_result(
                    instruction,
                    refined,
                    component,
                    subtract=False,
                    record_provenance=record_provenance,
                )
                result = result.with_value(destination, value)
            elif mnemonic == "sub":
                value = _binary_result(
                    instruction,
                    refined,
                    component,
                    subtract=True,
                    record_provenance=record_provenance,
                )
                result = result.with_value(destination, value)

    if instruction.control_flow is ControlFlowKind.CALL:
        for register in _CALLER_CLOBBERED:
            result = result.with_value(register, _UNKNOWN)
    return result


def _transfer_registers(
    state: RegisterState,
    instruction: DecodedInstruction,
    component: Component,
    warnings: set[str],
    *,
    record_provenance: bool,
) -> RegisterState:
    executed = _transfer_registers_executed(
        state,
        instruction,
        component,
        warnings,
        record_provenance=record_provenance,
    )
    if instruction.semantics.condition in {ConditionCode.AL, ConditionCode.INVALID}:
        return executed
    return _join_states(
        (state, executed),
        keep_provenance=record_provenance,
    )


def _register_list(instruction: DecodedInstruction) -> tuple[Register, ...] | None:
    operands = instruction.semantics.operands
    if len(operands) != 1 or operands[0].kind is not OperandKind.REGISTER_LIST:
        return None
    return operands[0].registers


def _stack_adjustment(instruction: DecodedInstruction) -> int | None:
    mnemonic = instruction.mnemonic.lower().split(".", maxsplit=1)[0]
    if mnemonic not in {"add", "sub"}:
        return None
    operands = instruction.semantics.operands
    immediate: int | None = None
    if (
        len(operands) == 3
        and operands[0].kind is OperandKind.REGISTER
        and operands[0].register is Register.SP
        and operands[1].kind is OperandKind.REGISTER
        and operands[1].register is Register.SP
        and operands[2].kind is OperandKind.IMMEDIATE
    ):
        immediate = operands[2].immediate
    elif (
        len(operands) == 2
        and operands[0].kind is OperandKind.REGISTER
        and operands[0].register is Register.SP
        and operands[1].kind is OperandKind.IMMEDIATE
    ):
        immediate = operands[1].immediate
    if immediate is None:
        return None
    return immediate if mnemonic == "add" else -immediate


def _frame_pointer_setup(instruction: DecodedInstruction) -> Register | None:
    mnemonic = instruction.mnemonic.lower().split(".", maxsplit=1)[0]
    operands = instruction.semantics.operands
    if (
        mnemonic != "mov"
        or len(operands) != 2
        or operands[0].kind is not OperandKind.REGISTER
        or operands[0].register is None
        or operands[0].register in {Register.SP, Register.PC}
        or operands[1].kind is not OperandKind.REGISTER
        or operands[1].register is not Register.SP
    ):
        return None
    return operands[0].register


def _transfer_stack_executed(
    state: StackState,
    instruction: DecodedInstruction,
) -> StackState:
    frame_pointers = dict(state.frame_pointers)
    for register in instruction.semantics.registers_written:
        frame_pointers.pop(register, None)

    mnemonic = instruction.mnemonic.lower().split(".", maxsplit=1)[0]
    register_list = _register_list(instruction)
    offset = state.offset
    handled_sp_write = False

    if mnemonic == "push" and register_list is not None:
        if offset is not None:
            offset -= 4 * len(register_list)
        handled_sp_write = True
    elif mnemonic == "pop" and register_list is not None:
        if offset is not None:
            offset += 4 * len(register_list)
        handled_sp_write = True
    else:
        adjustment = _stack_adjustment(instruction)
        if adjustment is not None:
            if offset is not None:
                offset += adjustment
            handled_sp_write = True

    frame_pointer = _frame_pointer_setup(instruction)
    if frame_pointer is not None and state.offset is not None:
        frame_pointers[frame_pointer] = state.offset

    if Register.SP in instruction.semantics.registers_written and not handled_sp_write:
        offset = None

    return StackState(offset=offset, frame_pointers=tuple(frame_pointers.items()))


def _transfer_stack(
    state: StackState,
    instruction: DecodedInstruction,
) -> StackState:
    executed = _transfer_stack_executed(state, instruction)
    if instruction.semantics.condition in {ConditionCode.AL, ConditionCode.INVALID}:
        return executed
    return _join_stack_states((state, executed))


def _transfer_argument_liveness(
    live: frozenset[Register],
    instruction: DecodedInstruction,
) -> frozenset[Register]:
    remaining = set(live)
    remaining.difference_update(instruction.semantics.registers_written)
    if instruction.control_flow is ControlFlowKind.CALL:
        remaining.difference_update(_ENTRY_ARGUMENTS)
    return frozenset(remaining)


def _transfer_flow(
    state: _FlowState,
    instruction: DecodedInstruction,
    component: Component,
    warnings: set[str],
    *,
    record_provenance: bool,
) -> _FlowState:
    return _FlowState(
        registers=_transfer_registers(
            state.registers,
            instruction,
            component,
            warnings,
            record_provenance=record_provenance,
        ),
        stack=_transfer_stack(state.stack, instruction),
        entry_arguments_live=_transfer_argument_liveness(
            state.entry_arguments_live,
            instruction,
        ),
    )


def _validate_cfg(
    cfg: FunctionControlFlowGraph,
    component: Component,
) -> None:
    if cfg.function.component != component.name:
        raise ValueError("data-flow function component does not match component")
    seen: set[_BlockKey] = set()
    for block in cfg.blocks:
        if block.component != component.name:
            raise ValueError("data-flow block component does not match component")
        expected = component.offset_for_address(block.address)
        if block.offset != expected:
            raise ValueError("data-flow block offset does not match component")
        key = (block.address, block.instruction_set)
        if key in seen:
            raise ValueError("data-flow CFG contains duplicate basic-block identity")
        seen.add(key)
    if cfg.blocks and (cfg.function.address, cfg.function.instruction_set) not in seen:
        raise ValueError("data-flow CFG does not contain its function entry block")


def _source_key_for_edge(
    source_address: int,
    source_instruction_address: int,
    blocks: dict[_BlockKey, BasicBlock],
) -> _BlockKey | None:
    candidates = [key for key in blocks if key[0] == source_address]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        return None
    containing = [
        key
        for key in candidates
        if any(
            instruction.address == source_instruction_address
            for instruction in blocks[key].instructions
        )
    ]
    if len(containing) == 1:
        return containing[0]
    raise ValueError("data-flow CFG edge source is ambiguous across instruction sets")


def _flow_graph(
    cfg: FunctionControlFlowGraph,
) -> tuple[
    dict[_BlockKey, BasicBlock],
    dict[_BlockKey, tuple[_BlockKey, ...]],
    dict[_BlockKey, tuple[_BlockKey, ...]],
]:
    blocks = {
        (block.address, block.instruction_set): block
        for block in cfg.blocks
    }
    predecessor_sets: dict[_BlockKey, set[_BlockKey]] = {
        key: set() for key in blocks
    }
    successor_sets: dict[_BlockKey, set[_BlockKey]] = {
        key: set() for key in blocks
    }
    for edge in cfg.edges:
        if edge.kind not in {CFGEdgeKind.BRANCH, CFGEdgeKind.FALLTHROUGH}:
            continue
        target = (edge.target_address, edge.target_instruction_set)
        if target not in blocks:
            continue
        source = _source_key_for_edge(
            edge.source_address,
            edge.source_instruction_address,
            blocks,
        )
        if source is None:
            continue
        predecessor_sets[target].add(source)
        successor_sets[source].add(target)

    def ordered(keys: set[_BlockKey]) -> tuple[_BlockKey, ...]:
        return tuple(sorted(keys, key=lambda key: (key[0], key[1].value)))

    predecessors = {key: ordered(value) for key, value in predecessor_sets.items()}
    successors = {key: ordered(value) for key, value in successor_sets.items()}
    return blocks, predecessors, successors


def _argument_reads(
    live: frozenset[Register],
    instruction: DecodedInstruction,
) -> tuple[tuple[Register, int], ...]:
    return tuple(
        (register, instruction.address)
        for register in _ENTRY_ARGUMENT_ORDER
        if register in live and register in instruction.semantics.registers_read
    )


def _run_block(
    block: BasicBlock,
    entry: _FlowState,
    component: Component,
    warnings: set[str],
    *,
    record_provenance: bool,
) -> tuple[
    _FlowState,
    tuple[InstructionFlowState, ...],
    tuple[tuple[Register, int], ...],
]:
    current = entry
    states: list[InstructionFlowState] = []
    argument_uses: list[tuple[Register, int]] = []
    for instruction in block.instructions:
        before = current
        argument_uses.extend(_argument_reads(before.entry_arguments_live, instruction))
        after = _transfer_flow(
            before,
            instruction,
            component,
            warnings,
            record_provenance=record_provenance,
        )
        states.append(
            InstructionFlowState(
                instruction=instruction,
                before=before.registers,
                after=after.registers,
                stack_before=before.stack,
                stack_after=after.stack,
            )
        )
        current = after
    return current, tuple(states), tuple(argument_uses)


def _solve(
    cfg: FunctionControlFlowGraph,
    component: Component,
    blocks: dict[_BlockKey, BasicBlock],
    predecessors: dict[_BlockKey, tuple[_BlockKey, ...]],
    successors: dict[_BlockKey, tuple[_BlockKey, ...]],
    *,
    record_provenance: bool,
) -> tuple[
    dict[_BlockKey, _FlowState | None],
    dict[_BlockKey, _FlowState | None],
    set[str],
]:
    entries: dict[_BlockKey, _FlowState | None] = {key: None for key in blocks}
    exits: dict[_BlockKey, _FlowState | None] = {key: None for key in blocks}
    warnings: set[str] = set()
    entry_key = (cfg.function.address, cfg.function.instruction_set)
    if entry_key not in blocks:
        return entries, exits, warnings

    entries[entry_key] = _FlowState(
        RegisterState(),
        StackState(offset=0),
        _ENTRY_ARGUMENTS,
    )
    queue: deque[_BlockKey] = deque((entry_key,))
    queued = {entry_key}
    while queue:
        key = queue.popleft()
        queued.discard(key)
        entry = entries[key]
        if entry is None:
            continue
        new_exit, _, _ = _run_block(
            blocks[key],
            entry,
            component,
            warnings,
            record_provenance=record_provenance,
        )
        old_exit = exits[key]
        if old_exit is not None and _same_flow_state(
            old_exit,
            new_exit,
            include_provenance=record_provenance,
        ):
            continue
        exits[key] = new_exit

        for successor in successors[key]:
            if successor == entry_key:
                continue
            incoming = tuple(
                exit_state
                for predecessor in predecessors[successor]
                if (exit_state := exits[predecessor]) is not None
            )
            if not incoming:
                continue
            new_entry = _join_flow_states(
                incoming,
                keep_provenance=record_provenance,
            )
            old_entry = entries[successor]
            if old_entry is not None and _same_flow_state(
                old_entry,
                new_entry,
                include_provenance=record_provenance,
            ):
                continue
            entries[successor] = new_entry
            if successor not in queued:
                queue.append(successor)
                queued.add(successor)
    return entries, exits, warnings


def _verify_semantic_convergence(
    semantic: dict[_BlockKey, _FlowState | None],
    enriched: dict[_BlockKey, _FlowState | None],
) -> None:
    for key, semantic_state in semantic.items():
        enriched_state = enriched[key]
        if semantic_state is None or enriched_state is None:
            if semantic_state is not enriched_state:
                raise RuntimeError("provenance pass changed data-flow reachability")
            continue
        if not _same_flow_state(
            semantic_state,
            enriched_state,
            include_provenance=False,
        ):
            raise RuntimeError("provenance pass changed data-flow semantics")


def _build_summary(
    flow: FunctionDataFlow,
    argument_uses: dict[Register, set[int]],
) -> FunctionSummary:
    stack = analyze_stack(flow)
    arguments: list[ArgumentEvidence] = []
    for index, register in enumerate(_ENTRY_ARGUMENT_ORDER):
        uses = tuple(sorted(argument_uses.get(register, set())))
        if uses:
            arguments.append(
                ArgumentEvidence(
                    index=index,
                    kind=ArgumentLocationKind.REGISTER,
                    register=register,
                    stack_offset=None,
                    uses=uses,
                )
            )

    for slot in stack.slots:
        if slot.kind is not StackSlotKind.INCOMING_ARGUMENT or not slot.accesses:
            continue
        arguments.append(
            ArgumentEvidence(
                index=None,
                kind=ArgumentLocationKind.STACK,
                register=None,
                stack_offset=slot.offset,
                uses=tuple(access.instruction_address for access in slot.accesses),
            )
        )

    arguments.sort(
        key=lambda item: (
            0 if item.kind is ArgumentLocationKind.REGISTER else 1,
            item.index if item.index is not None else 1 << 30,
            item.stack_offset if item.stack_offset is not None else 0,
        )
    )
    returns = tuple(
        ReturnEvidence(
            return_address=state.address,
            value=state.before.value(Register.R0),
        )
        for state in flow.instructions
        if state.instruction.control_flow is ControlFlowKind.RETURN
    )
    return FunctionSummary(
        arguments=tuple(arguments),
        returns=returns,
        stack_frame=stack.frame,
        stack_slots=stack.slots,
    )


def _summarize(
    flow: FunctionDataFlow,
    argument_uses: dict[Register, set[int]],
) -> FunctionDataFlow:
    return replace(flow, summary=_build_summary(flow, argument_uses))


def analyze_data_flow(
    cfg: FunctionControlFlowGraph,
    component: Component,
) -> FunctionDataFlow:
    _validate_cfg(cfg, component)
    if not cfg.blocks:
        return _summarize(
            FunctionDataFlow(function=cfg.function, blocks=(), instructions=()),
            {},
        )

    blocks, predecessors, successors = _flow_graph(cfg)
    semantic_entries, semantic_exits, semantic_warnings = _solve(
        cfg,
        component,
        blocks,
        predecessors,
        successors,
        record_provenance=False,
    )
    entries, exits, warnings = _solve(
        cfg,
        component,
        blocks,
        predecessors,
        successors,
        record_provenance=True,
    )
    _verify_semantic_convergence(semantic_entries, entries)
    _verify_semantic_convergence(semantic_exits, exits)
    warnings.update(semantic_warnings)

    block_states: list[BlockFlowState] = []
    instruction_states: list[InstructionFlowState] = []
    argument_uses: dict[Register, set[int]] = {
        register: set() for register in _ENTRY_ARGUMENT_ORDER
    }
    ordered_keys = sorted(blocks, key=lambda key: (key[0], key[1].value))
    for key in ordered_keys:
        entry = entries[key]
        exit_state = exits[key]
        if entry is None or exit_state is None:
            continue
        block = blocks[key]
        final_exit, states, uses = _run_block(
            block,
            entry,
            component,
            warnings,
            record_provenance=True,
        )
        if not _same_flow_state(final_exit, exit_state, include_provenance=True):
            raise RuntimeError("final data-flow materialization did not converge")
        block_states.append(
            BlockFlowState(
                address=block.address,
                instruction_set=block.instruction_set,
                entry=entry.registers,
                exit=exit_state.registers,
                stack_entry=entry.stack,
                stack_exit=exit_state.stack,
            )
        )
        instruction_states.extend(states)
        for register, address in uses:
            argument_uses[register].add(address)

    instruction_states.sort(
        key=lambda state: (
            state.address,
            state.instruction.instruction_set.value,
        )
    )
    flow = FunctionDataFlow(
        function=cfg.function,
        blocks=tuple(block_states),
        instructions=tuple(instruction_states),
        warnings=tuple(sorted(warnings)),
    )
    return _summarize(flow, argument_uses)
