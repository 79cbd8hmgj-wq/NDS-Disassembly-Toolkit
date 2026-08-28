from __future__ import annotations

from collections import deque
from collections.abc import Sequence

from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    BasicBlock,
    BlockFlowState,
    CFGEdgeKind,
    Component,
    ConditionCode,
    ControlFlowKind,
    DecodedInstruction,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    InstructionFlowState,
    InstructionOperand,
    InstructionSet,
    OperandKind,
    Register,
    RegisterState,
    ShiftKind,
)

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
_BlockKey = tuple[int, InstructionSet]


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


def _transfer_executed(
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


def _transfer(
    state: RegisterState,
    instruction: DecodedInstruction,
    component: Component,
    warnings: set[str],
    *,
    record_provenance: bool,
) -> RegisterState:
    executed = _transfer_executed(
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


def _run_block(
    block: BasicBlock,
    entry: RegisterState,
    component: Component,
    warnings: set[str],
    *,
    record_provenance: bool,
) -> tuple[RegisterState, tuple[InstructionFlowState, ...]]:
    current = entry
    states: list[InstructionFlowState] = []
    for instruction in block.instructions:
        before = current
        after = _transfer(
            before,
            instruction,
            component,
            warnings,
            record_provenance=record_provenance,
        )
        states.append(
            InstructionFlowState(
                instruction=instruction,
                before=before,
                after=after,
            )
        )
        current = after
    return current, tuple(states)


def _solve(
    cfg: FunctionControlFlowGraph,
    component: Component,
    blocks: dict[_BlockKey, BasicBlock],
    predecessors: dict[_BlockKey, tuple[_BlockKey, ...]],
    successors: dict[_BlockKey, tuple[_BlockKey, ...]],
    *,
    record_provenance: bool,
) -> tuple[
    dict[_BlockKey, RegisterState | None],
    dict[_BlockKey, RegisterState | None],
    set[str],
]:
    entries: dict[_BlockKey, RegisterState | None] = {key: None for key in blocks}
    exits: dict[_BlockKey, RegisterState | None] = {key: None for key in blocks}
    warnings: set[str] = set()
    entry_key = (cfg.function.address, cfg.function.instruction_set)
    if entry_key not in blocks:
        return entries, exits, warnings

    entries[entry_key] = RegisterState()
    queue: deque[_BlockKey] = deque((entry_key,))
    queued = {entry_key}
    while queue:
        key = queue.popleft()
        queued.discard(key)
        entry = entries[key]
        if entry is None:
            continue
        new_exit, _ = _run_block(
            blocks[key],
            entry,
            component,
            warnings,
            record_provenance=record_provenance,
        )
        old_exit = exits[key]
        if old_exit is not None and _same_state(
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
            new_entry = _join_states(
                incoming,
                keep_provenance=record_provenance,
            )
            old_entry = entries[successor]
            if old_entry is not None and _same_state(
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
    semantic: dict[_BlockKey, RegisterState | None],
    enriched: dict[_BlockKey, RegisterState | None],
) -> None:
    for key, semantic_state in semantic.items():
        enriched_state = enriched[key]
        if semantic_state is None or enriched_state is None:
            if semantic_state is not enriched_state:
                raise RuntimeError("provenance pass changed data-flow reachability")
            continue
        if not _same_state(
            semantic_state,
            enriched_state,
            include_provenance=False,
        ):
            raise RuntimeError("provenance pass changed data-flow semantics")


def analyze_data_flow(
    cfg: FunctionControlFlowGraph,
    component: Component,
) -> FunctionDataFlow:
    _validate_cfg(cfg, component)
    if not cfg.blocks:
        return FunctionDataFlow(function=cfg.function, blocks=(), instructions=())

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
    ordered_keys = sorted(blocks, key=lambda key: (key[0], key[1].value))
    for key in ordered_keys:
        entry = entries[key]
        exit_state = exits[key]
        if entry is None or exit_state is None:
            continue
        block = blocks[key]
        final_exit, states = _run_block(
            block,
            entry,
            component,
            warnings,
            record_provenance=True,
        )
        if not _same_state(final_exit, exit_state, include_provenance=True):
            raise RuntimeError("final data-flow materialization did not converge")
        block_states.append(
            BlockFlowState(
                address=block.address,
                instruction_set=block.instruction_set,
                entry=entry,
                exit=exit_state,
            )
        )
        instruction_states.extend(states)

    instruction_states.sort(
        key=lambda state: (
            state.address,
            state.instruction.instruction_set.value,
        )
    )
    return FunctionDataFlow(
        function=cfg.function,
        blocks=tuple(block_states),
        instructions=tuple(instruction_states),
        warnings=tuple(sorted(warnings)),
    )
