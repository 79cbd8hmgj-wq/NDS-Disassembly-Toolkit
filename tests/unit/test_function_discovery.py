import struct
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.functions import discover_functions
from nds_disassembly_toolkit.analysis.model import Component, ExecutionMode, FunctionSeed
from nds_disassembly_toolkit.arm32 import Register, encode_branch, encode_bx


BASE = 0x02000000


def _word(value: int) -> bytes:
    return struct.pack("<I", value)


def test_discovers_in_component_direct_callee() -> None:
    data = bytearray(0x18)
    data[0x00:0x04] = _word(encode_branch(BASE, BASE + 0x10, link=True))
    data[0x04:0x08] = _word(encode_bx(Register.LR))
    data[0x10:0x14] = _word(encode_bx(Register.LR))
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(data))

    result = discover_functions(
        component,
        [FunctionSeed(BASE, ExecutionMode.ARM, "arm9-entry", "high")],
    )

    assert [function.address for function in result.functions] == [BASE, BASE + 0x10]
    assert result.functions[0].evidence == ("arm9-entry",)
    assert result.functions[1].evidence == ("direct-call",)
    assert result.functions[1].confidence == "high"
    assert result.unresolved_indirect_transfers == ()


def test_follows_direct_branch_without_promoting_target_to_function() -> None:
    data = bytearray(0x18)
    data[0x00:0x04] = _word(encode_branch(BASE, BASE + 0x10))
    data[0x10:0x14] = _word(encode_bx(Register.LR))
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(data))

    result = discover_functions(
        component,
        [FunctionSeed(BASE, ExecutionMode.ARM, "entry", "high")],
    )

    assert [function.address for function in result.functions] == [BASE]
    assert result.unresolved_indirect_transfers == ()


def test_reports_unresolved_indirect_transfer() -> None:
    component = Component(
        "overlay",
        Path("overlay.bin"),
        BASE,
        _word(encode_bx(Register.R3)),
    )

    result = discover_functions(
        component,
        [FunctionSeed(BASE, ExecutionMode.ARM, "entry", "high")],
    )

    assert result.unresolved_indirect_transfers == (BASE,)


def test_merges_duplicate_seed_evidence_and_strongest_confidence() -> None:
    component = Component(
        "arm9",
        Path("arm9.bin"),
        BASE,
        _word(encode_bx(Register.LR)),
    )

    result = discover_functions(
        component,
        [
            FunctionSeed(BASE, ExecutionMode.ARM, "arm-prologue", "medium"),
            FunctionSeed(BASE, ExecutionMode.ARM, "arm9-entry", "high"),
            FunctionSeed(BASE, ExecutionMode.ARM, "arm9-entry", "high"),
        ],
    )

    assert len(result.functions) == 1
    assert result.functions[0].evidence == ("arm-prologue", "arm9-entry")
    assert result.functions[0].confidence == "high"


@pytest.mark.parametrize(
    ("address", "mode", "message"),
    [
        (BASE - 4, ExecutionMode.ARM, "outside"),
        (BASE + 2, ExecutionMode.ARM, "ARM aligned"),
        (BASE + 1, ExecutionMode.THUMB, "Thumb aligned"),
    ],
)
def test_rejects_invalid_function_seed(address: int, mode: ExecutionMode, message: str) -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, b"\x00" * 0x20)

    with pytest.raises(ValueError, match=message):
        discover_functions(component, [FunctionSeed(address, mode, "entry", "high")])
