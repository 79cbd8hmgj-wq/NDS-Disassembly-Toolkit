from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from nds_disassembly_toolkit.analysis.decoder import decode_instruction
from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    Component,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
)

_InstructionKey = tuple[int, InstructionSet]


@dataclass(frozen=True)
class _Successor:
    target: _InstructionKey
    kind: CFGEdgeKind


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


def _is_local(component: Component, key: _InstructionKey) -> bool:
    address, instruction_set = key
    return (
        component.base_address <= address < component.end_address
        and address % instruction_set.alignment == 0
    )


def _decode_reachable(
    component: Component,
    entry: _InstructionKey,
) -> tuple[
    dict[_InstructionKey, DecodedInstruction],
    dict[_InstructionKey, tuple[_Successor, ...]],
    set[_InstructionKey],
    set[int],
]:
    instructions: dict[_InstructionKey, DecodedInstruction] = {}
    successors: dict[_InstructionKey, tuple[_Successor, ...]] = {}
    leaders = {entry}
    decode_failures: set[int] = set()
    worklist = deque([entry])
    queued = {entry}

    while worklist:
        key = worklist.popleft()
        queued.discard(key)
        if key in instructions:
            continue
        address, instruction_set = key
        offset = address - component.base_address
        decoded = decode_instruction(
            component.data[offset:],
            address=address,
            instruction_set=instruction_set,
        )
        if decoded is None:
            decode_failures.add(address)
            continue
        instructions[key] = decoded

        next_key = (address + decoded.size, instruction_set)
        outgoing: list[_Successor] = []
        if decoded.control_flow is ControlFlowKind.ORDINARY:
            if _is_local(component, next_key):
                outgoing.append(_Successor(next_key, CFGEdgeKind.FALLTHROUGH))
        elif decoded.control_flow is ControlFlowKind.BRANCH:
            if decoded.direct_target is not None:
                target_mode = decoded.target_instruction_set or instruction_set
                target_key = (decoded.direct_target, target_mode)
                if _is_local(component, target_key):
                    outgoing.append(_Successor(target_key, CFGEdgeKind.BRANCH))
                    leaders.add(target_key)
            if decoded.conditional and _is_local(component, next_key):
                outgoing.append(_Successor(next_key, CFGEdgeKind.FALLTHROUGH))
                leaders.add(next_key)

        successors[key] = tuple(outgoing)
        for successor in outgoing:
            if successor.target not in instructions and successor.target not in queued:
                worklist.append(successor.target)
                queued.add(successor.target)

    return instructions, successors, leaders, decode_failures


def _build_blocks(
    component: Component,
    instructions: dict[_InstructionKey, DecodedInstruction],
    successors: dict[_InstructionKey, tuple[_Successor, ...]],
    leaders: set[_InstructionKey],
) -> tuple[tuple[BasicBlock, ...], dict[_InstructionKey, _InstructionKey]]:
    blocks: list[BasicBlock] = []
    owner: dict[_InstructionKey, _InstructionKey] = {}

    for leader in sorted(leaders, key=lambda item: (item[0], item[1].value)):
        if leader not in instructions or leader in owner:
            continue
        block_instructions: list[DecodedInstruction] = []
        key = leader
        while key in instructions and key not in owner:
            decoded = instructions[key]
            owner[key] = leader
            block_instructions.append(decoded)
            outgoing = successors.get(key, ())
            if decoded.control_flow is not ControlFlowKind.ORDINARY:
                break
            if len(outgoing) != 1:
                break
            next_key = outgoing[0].target
            if next_key in leaders and next_key != leader:
                break
            key = next_key

        blocks.append(
            BasicBlock(
                component=component.name,
                address=leader[0],
                offset=leader[0] - component.base_address,
                instruction_set=leader[1],
                instructions=tuple(block_instructions),
            )
        )

    return tuple(blocks), owner


def _build_edges(
    successors: dict[_InstructionKey, tuple[_Successor, ...]],
    owner: dict[_InstructionKey, _InstructionKey],
) -> tuple[CFGEdge, ...]:
    edges: set[CFGEdge] = set()
    for source_key, outgoing in successors.items():
        source_block = owner.get(source_key)
        if source_block is None:
            continue
        for successor in outgoing:
            target_block = owner.get(successor.target)
            if target_block is None:
                continue
            if target_block == source_block and successor.kind is CFGEdgeKind.FALLTHROUGH:
                continue
            edges.add(
                CFGEdge(
                    source_address=source_block[0],
                    source_instruction_address=source_key[0],
                    target_address=target_block[0],
                    target_instruction_set=target_block[1],
                    kind=successor.kind,
                )
            )
    return tuple(
        sorted(
            edges,
            key=lambda edge: (
                edge.source_address,
                edge.source_instruction_address,
                edge.kind.value,
                edge.target_address,
                edge.target_instruction_set.value,
            ),
        )
    )


def build_function_cfg(
    component: Component,
    function: FunctionCandidate,
) -> FunctionControlFlowGraph:
    _validate_function(component, function)
    entry = (function.address, function.instruction_set)
    instructions, successors, leaders, decode_failures = _decode_reachable(component, entry)
    blocks, owner = _build_blocks(component, instructions, successors, leaders)
    edges = _build_edges(successors, owner)
    return FunctionControlFlowGraph(
        function=function,
        blocks=blocks,
        edges=edges,
        unresolved_transfers=(),
        decode_failures=tuple(sorted(decode_failures)),
    )
