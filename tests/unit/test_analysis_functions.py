import struct
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.functions import discover_functions
from nds_disassembly_toolkit.analysis.model import Component, FunctionSeed, InstructionSet

BASE = 0x02000000


def _component(data: bytes) -> Component:
    return Component("arm9", Path("arm9.bin"), BASE, data)


def _arm_word(data: bytearray, offset: int, word: int) -> None:
    struct.pack_into("<I", data, offset, word)


def test_discovery_follows_arm_direct_call() -> None:
    data = bytearray(0x30)
    _arm_word(data, 0x00, 0xE92D4010)
    _arm_word(data, 0x04, 0xEB000005)
    _arm_word(data, 0x08, 0xE12FFF1E)
    _arm_word(data, 0x20, 0xE92D4010)
    _arm_word(data, 0x24, 0xE12FFF1E)

    result = discover_functions(
        _component(bytes(data)),
        seeds=(FunctionSeed(BASE, InstructionSet.ARM),),
    )

    assert [(item.address, item.instruction_set) for item in result.functions] == [
        (BASE, InstructionSet.ARM),
        (BASE + 0x20, InstructionSet.ARM),
    ]
    assert result.functions[0].evidence == ("explicit",)
    assert result.functions[1].evidence == ("direct call from 0x02000004",)
    assert result.unresolved_calls == ()
    assert result.decode_failures == ()


def test_duplicate_explicit_and_call_evidence_merges() -> None:
    data = bytearray(0x30)
    _arm_word(data, 0x00, 0xEB000006)
    _arm_word(data, 0x04, 0xE12FFF1E)
    _arm_word(data, 0x20, 0xE12FFF1E)

    result = discover_functions(
        _component(bytes(data)),
        seeds=(
            FunctionSeed(BASE, InstructionSet.ARM),
            FunctionSeed(BASE + 0x20, InstructionSet.ARM, source="known symbol"),
        ),
    )

    callee = result.functions[1]
    assert callee.address == BASE + 0x20
    assert callee.evidence == ("direct call from 0x02000000", "known symbol")


def test_out_of_component_direct_call_is_unresolved() -> None:
    data = bytearray(0x10)
    _arm_word(data, 0x00, 0xEB00003E)
    _arm_word(data, 0x04, 0xE12FFF1E)

    result = discover_functions(
        _component(bytes(data)),
        seeds=(FunctionSeed(BASE, InstructionSet.ARM),),
    )

    assert [item.address for item in result.functions] == [BASE]
    assert result.unresolved_calls == (BASE + 0x100,)


def test_arm_blx_discovers_thumb_function() -> None:
    data = bytearray(0x20)
    _arm_word(data, 0x00, 0xFA000002)
    _arm_word(data, 0x04, 0xE12FFF1E)
    struct.pack_into("<H", data, 0x10, 0xB500)
    struct.pack_into("<H", data, 0x12, 0x4770)

    result = discover_functions(
        _component(bytes(data)),
        seeds=(FunctionSeed(BASE, InstructionSet.ARM),),
    )

    assert [(item.address, item.instruction_set) for item in result.functions] == [
        (BASE, InstructionSet.ARM),
        (BASE + 0x10, InstructionSet.THUMB),
    ]


def test_discovery_rejects_invalid_seed_alignment() -> None:
    with pytest.raises(ValueError, match="aligned"):
        discover_functions(
            _component(b"\x00" * 0x10),
            seeds=(FunctionSeed(BASE + 2, InstructionSet.ARM),),
        )
