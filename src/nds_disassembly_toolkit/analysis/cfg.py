from __future__ import annotations

from nds_disassembly_toolkit.analysis.decoder import decode_instruction
from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    Component,
    ControlFlowKind,
    FunctionCandidate,
    FunctionControlFlowGraph,
)


def _validate_function(component: Component, function: FunctionCandidate) -> None:
    if function.component != component.name:
        raise ValueError("function component does not match CFG component")
    if not component.base_address <= function.address < component.end_address:
        raise ValueError("function entry is outside component")
    if function.address % function.instruction_set.alignment:
        raise ValueError(
            f"{function.instruction_set.value} function entry must be "
            f"{function.instruction_set.alignment}-byte aligned"
        )


def build_function_cfg(
    component: Component,
    function: FunctionCandidate,
) -> FunctionControlFlowGraph:
    _validate_function(component, function)
    instructions = []
    decode_failures: list[int] = []
    cursor = function.address
    while cursor < component.end_address:
        offset = cursor - component.base_address
        decoded = decode_instruction(
            component.data[offset:],
            address=cursor,
            instruction_set=function.instruction_set,
        )
        if decoded is None:
            decode_failures.append(cursor)
            break
        instructions.append(decoded)
        if decoded.control_flow is not ControlFlowKind.ORDINARY:
            break
        cursor += decoded.size

    blocks = ()
    if instructions:
        blocks = (
            BasicBlock(
                component=component.name,
                address=function.address,
                offset=function.address - component.base_address,
                instruction_set=function.instruction_set,
                instructions=tuple(instructions),
            ),
        )
    return FunctionControlFlowGraph(
        function=function,
        blocks=blocks,
        edges=(),
        unresolved_transfers=(),
        decode_failures=tuple(decode_failures),
    )
