from __future__ import annotations

from collections import defaultdict

from nds_disassembly_toolkit.analysis.model import (
    FunctionDataFlow,
    InstructionFlowState,
    InstructionOperand,
    OperandAccess,
    OperandKind,
    Register,
    StackAccess,
    StackAccessKind,
    StackAnalysis,
    StackFrame,
    StackSlot,
    StackSlotKind,
    StackState,
)


def _register_list(state: InstructionFlowState) -> tuple[Register, ...] | None:
    operands = state.instruction.semantics.operands
    if len(operands) != 1 or operands[0].kind is not OperandKind.REGISTER_LIST:
        return None
    return operands[0].registers


def _entry_relative_offset(
    operand: InstructionOperand,
    stack: StackState,
) -> tuple[int | None, Register | None]:
    memory = operand.memory
    if memory is None or memory.index is not None:
        return None, None
    if memory.base is Register.SP and stack.offset is not None:
        return stack.offset + memory.displacement, None
    if memory.base is not None:
        frame_offset = stack.frame_offset(memory.base)
        if frame_offset is not None:
            return frame_offset + memory.displacement, memory.base
    return None, None


def _memory_accesses(
    state: InstructionFlowState,
) -> tuple[tuple[int, StackAccess, Register | None], ...]:
    stack = state.stack_before
    if stack is None:
        return ()
    accesses: list[tuple[int, StackAccess, Register | None]] = []
    for operand in state.instruction.semantics.operands:
        if operand.kind is not OperandKind.MEMORY or operand.memory is None:
            continue
        offset, frame_pointer = _entry_relative_offset(operand, stack)
        width = operand.access_width
        if offset is None or width is None:
            continue
        if operand.access & OperandAccess.WRITE:
            accesses.append(
                (
                    offset,
                    StackAccess(
                        instruction_address=state.address,
                        kind=StackAccessKind.STORE,
                        width=width,
                    ),
                    frame_pointer,
                )
            )
        if operand.access & OperandAccess.READ:
            accesses.append(
                (
                    offset,
                    StackAccess(
                        instruction_address=state.address,
                        kind=StackAccessKind.LOAD,
                        width=width,
                    ),
                    frame_pointer,
                )
            )
    return tuple(accesses)


def _all_stack_states(flow: FunctionDataFlow) -> tuple[StackState | None, ...]:
    states: list[StackState | None] = []
    for block in flow.blocks:
        states.extend((block.stack_entry, block.stack_exit))
    for instruction in flow.instructions:
        states.extend((instruction.stack_before, instruction.stack_after))
    return tuple(states)


def analyze_stack(flow: FunctionDataFlow) -> StackAnalysis:
    accesses: dict[int, list[StackAccess]] = defaultdict(list)
    saved_offsets: set[int] = set()
    frame_pointer_uses: set[Register] = set()

    for state in flow.instructions:
        mnemonic = state.instruction.mnemonic.lower().split(".", maxsplit=1)[0]
        register_list = _register_list(state)
        before = state.stack_before

        if register_list is not None and before is not None and before.offset is not None:
            if mnemonic == "push":
                first_offset = before.offset - 4 * len(register_list)
                kind = StackAccessKind.STORE
            elif mnemonic == "pop":
                first_offset = before.offset
                kind = StackAccessKind.LOAD
            else:
                first_offset = 0
                kind = None
            if kind is not None:
                for index, _register in enumerate(register_list):
                    offset = first_offset + 4 * index
                    if mnemonic == "push":
                        saved_offsets.add(offset)
                    accesses[offset].append(
                        StackAccess(
                            instruction_address=state.address,
                            kind=kind,
                            width=4,
                        )
                    )

        for offset, access, frame_pointer in _memory_accesses(state):
            accesses[offset].append(access)
            if frame_pointer is not None:
                frame_pointer_uses.add(frame_pointer)

    stack_states = _all_stack_states(flow)
    known_offsets = tuple(
        state.offset
        for state in stack_states
        if state is not None and state.offset is not None
    )
    frame_size = None
    if known_offsets:
        deepest = min(known_offsets)
        frame_size = max(0, -deepest)

    stack_depth_known = bool(stack_states) and all(
        state is not None and state.offset is not None for state in stack_states
    )
    frame_pointer = (
        next(iter(frame_pointer_uses)) if len(frame_pointer_uses) == 1 else None
    )

    slots: list[StackSlot] = []
    for offset in sorted(accesses):
        if offset in saved_offsets:
            kind = StackSlotKind.SAVED_REGISTER
        elif offset < 0:
            kind = StackSlotKind.LOCAL
        elif offset >= 0:
            kind = StackSlotKind.INCOMING_ARGUMENT
        else:
            kind = StackSlotKind.UNKNOWN
        slot_accesses = tuple(
            sorted(
                accesses[offset],
                key=lambda access: (access.instruction_address, access.kind.value, access.width),
            )
        )
        slots.append(StackSlot(offset=offset, kind=kind, accesses=slot_accesses))

    return StackAnalysis(
        frame=StackFrame(
            frame_size=frame_size,
            frame_pointer=frame_pointer,
            stack_depth_known=stack_depth_known,
        ),
        slots=tuple(slots),
    )
