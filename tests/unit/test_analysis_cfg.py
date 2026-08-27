import struct
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis as analysis
from nds_disassembly_toolkit.analysis.cfg import build_function_cfg
from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    Component,
    ControlFlowKind,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
    UnresolvedTransfer,
)

BASE = 0x02000000


def _component(data: bytes, name: str = "arm9") -> Component:
    return Component(name, Path(f"{name}.bin"), BASE, data)


def _function(address: int = BASE, component: str = "arm9") -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=address,
        offset=address - BASE,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )


def _arm_words(*words: int) -> bytes:
    return b"".join(struct.pack("<I", word) for word in words)


def test_straight_line_function_is_one_basic_block() -> None:
    component = _component(_arm_words(0xE1A00000, 0xE2800001, 0xE12FFF1E))

    cfg = build_function_cfg(component, _function())

    assert cfg.function.address == BASE
    assert len(cfg.blocks) == 1
    block = cfg.blocks[0]
    assert block.address == BASE
    assert block.offset == 0
    assert block.instruction_set is InstructionSet.ARM
    assert [item.address for item in block.instructions] == [BASE, BASE + 4, BASE + 8]
    assert block.size == 12
    assert block.end_address == BASE + 12
    assert cfg.edges == ()
    assert cfg.unresolved_transfers == ()
    assert cfg.decode_failures == ()


def test_cfg_rejects_mismatched_function_component() -> None:
    component = _component(_arm_words(0xE12FFF1E))

    with pytest.raises(ValueError, match="component"):
        build_function_cfg(component, _function(component="overlay"))


def test_cfg_rejects_misaligned_function_entry() -> None:
    component = _component(b"\x00" * 16)

    with pytest.raises(ValueError, match="aligned"):
        build_function_cfg(component, _function(BASE + 2))


def test_conditional_branch_builds_taken_and_fallthrough_edges() -> None:
    component = _component(
        _arm_words(
            0xE1A00000,  # nop
            0x1A000000,  # bne BASE + 0x0C
            0xE3A00001,  # mov r0, #1
            0xE12FFF1E,  # bx lr
        )
    )

    cfg = build_function_cfg(component, _function())

    assert [block.address for block in cfg.blocks] == [BASE, BASE + 8, BASE + 12]
    assert [[item.address for item in block.instructions] for block in cfg.blocks] == [
        [BASE, BASE + 4],
        [BASE + 8],
        [BASE + 12],
    ]
    assert [
        (edge.source_address, edge.source_instruction_address, edge.kind.value, edge.target_address)
        for edge in cfg.edges
    ] == [
        (BASE, BASE + 4, "branch", BASE + 12),
        (BASE, BASE + 4, "fallthrough", BASE + 8),
        (BASE + 8, BASE + 8, "fallthrough", BASE + 12),
    ]


def test_backward_branch_splits_earlier_linear_code_at_target() -> None:
    component = _component(
        _arm_words(
            0xE1A00000,  # nop
            0xE1A01001,  # mov r1, r1
            0x1AFFFFFD,  # bne BASE + 0x04
            0xE12FFF1E,  # bx lr
        )
    )

    cfg = build_function_cfg(component, _function())

    assert [block.address for block in cfg.blocks] == [BASE, BASE + 4, BASE + 12]
    assert [[item.address for item in block.instructions] for block in cfg.blocks] == [
        [BASE],
        [BASE + 4, BASE + 8],
        [BASE + 12],
    ]
    for index, block in enumerate(cfg.blocks[:-1]):
        assert block.end_address <= cfg.blocks[index + 1].address
    assert [
        (edge.source_address, edge.kind.value, edge.target_address)
        for edge in cfg.edges
    ] == [
        (BASE, "fallthrough", BASE + 4),
        (BASE + 4, "branch", BASE + 4),
        (BASE + 4, "fallthrough", BASE + 12),
    ]


def test_direct_call_records_edge_and_does_not_traverse_callee() -> None:
    data = bytearray(0x24)
    data[:8] = _arm_words(
        0xEB000006,  # bl BASE + 0x20
        0xE12FFF1E,  # bx lr
    )
    struct.pack_into("<I", data, 0x20, 0xE12FFF1E)

    cfg = build_function_cfg(_component(bytes(data)), _function())

    assert [block.address for block in cfg.blocks] == [BASE, BASE + 4]
    assert [
        (edge.kind, edge.target_address, edge.target_instruction_set)
        for edge in cfg.edges
    ] == [
        (CFGEdgeKind.CALL, BASE + 0x20, InstructionSet.ARM),
        (CFGEdgeKind.FALLTHROUGH, BASE + 4, InstructionSet.ARM),
    ]
    assert all(block.address != BASE + 0x20 for block in cfg.blocks)


def test_arm_blx_call_edge_targets_thumb_without_traversal() -> None:
    data = bytearray(0x14)
    data[:8] = _arm_words(
        0xFA000002,  # blx BASE + 0x10
        0xE12FFF1E,  # bx lr
    )
    struct.pack_into("<H", data, 0x10, 0x4770)

    cfg = build_function_cfg(_component(bytes(data)), _function())

    call = next(edge for edge in cfg.edges if edge.kind is CFGEdgeKind.CALL)
    assert call.target_address == BASE + 0x10
    assert call.target_instruction_set is InstructionSet.THUMB
    assert all(block.address != BASE + 0x10 for block in cfg.blocks)


def test_external_direct_branch_is_edge_without_traversal() -> None:
    component = _component(
        _arm_words(
            0xEA00003E,  # b BASE + 0x100
            0xE12FFF1E,
        )
    )

    cfg = build_function_cfg(component, _function())

    assert len(cfg.blocks) == 1
    assert [(edge.kind, edge.target_address) for edge in cfg.edges] == [
        (CFGEdgeKind.BRANCH, BASE + 0x100)
    ]
    assert cfg.unresolved_transfers == ()


def test_indirect_branch_is_unresolved_and_stops_path() -> None:
    component = _component(
        _arm_words(
            0xE12FFF10,  # bx r0
            0xE12FFF1E,
        )
    )

    cfg = build_function_cfg(component, _function())

    assert len(cfg.blocks) == 1
    assert [item.address for item in cfg.blocks[0].instructions] == [BASE]
    assert cfg.edges == ()
    unresolved = cfg.unresolved_transfers[0]
    assert unresolved.source_address == BASE
    assert unresolved.instruction_set is InstructionSet.ARM
    assert unresolved.control_flow is ControlFlowKind.BRANCH
    assert unresolved.mnemonic == "bx"
    assert unresolved.operands == "r0"


def test_indirect_call_is_unresolved_but_keeps_fallthrough() -> None:
    component = _component(
        _arm_words(
            0xE12FFF30,  # blx r0
            0xE12FFF1E,
        )
    )

    cfg = build_function_cfg(component, _function())

    assert [block.address for block in cfg.blocks] == [BASE, BASE + 4]
    assert [(edge.kind, edge.target_address) for edge in cfg.edges] == [
        (CFGEdgeKind.FALLTHROUGH, BASE + 4)
    ]
    assert len(cfg.unresolved_transfers) == 1
    assert cfg.unresolved_transfers[0].control_flow is ControlFlowKind.CALL


def test_cfg_api_is_exported_from_analysis_package() -> None:
    assert analysis.build_function_cfg is build_function_cfg
    assert analysis.BasicBlock is BasicBlock
    assert analysis.CFGEdge is CFGEdge
    assert analysis.CFGEdgeKind is CFGEdgeKind
    assert analysis.FunctionControlFlowGraph is FunctionControlFlowGraph
    assert analysis.UnresolvedTransfer is UnresolvedTransfer
