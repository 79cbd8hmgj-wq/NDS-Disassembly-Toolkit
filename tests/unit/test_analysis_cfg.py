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
