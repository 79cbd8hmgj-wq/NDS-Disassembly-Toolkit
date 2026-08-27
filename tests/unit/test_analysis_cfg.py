import struct
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.cfg import build_function_cfg
from nds_disassembly_toolkit.analysis.model import Component, FunctionCandidate, InstructionSet

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
