import struct

import pytest

from nds_disassembly_toolkit.analysis.decoder import decode_instruction
from nds_disassembly_toolkit.analysis.model import ControlFlowKind, InstructionSet


def test_decode_arm_direct_call() -> None:
    instruction = struct.pack("<I", 0xEB000002)

    decoded = decode_instruction(
        instruction,
        address=0x02000000,
        instruction_set=InstructionSet.ARM,
    )

    assert decoded is not None
    assert decoded.address == 0x02000000
    assert decoded.size == 4
    assert decoded.instruction_set is InstructionSet.ARM
    assert decoded.control_flow is ControlFlowKind.CALL
    assert decoded.direct_target == 0x02000010
    assert decoded.target_instruction_set is InstructionSet.ARM
    assert not decoded.conditional


def test_decode_arm_blx_switches_to_thumb() -> None:
    instruction = struct.pack("<I", 0xFA000002)

    decoded = decode_instruction(
        instruction,
        address=0x02000000,
        instruction_set=InstructionSet.ARM,
    )

    assert decoded is not None
    assert decoded.mnemonic == "blx"
    assert decoded.control_flow is ControlFlowKind.CALL
    assert decoded.direct_target == 0x02000010
    assert decoded.target_instruction_set is InstructionSet.THUMB


def test_decode_arm_return() -> None:
    instruction = struct.pack("<I", 0xE12FFF1E)

    decoded = decode_instruction(
        instruction,
        address=0x02000000,
        instruction_set=InstructionSet.ARM,
    )

    assert decoded is not None
    assert decoded.control_flow is ControlFlowKind.RETURN
    assert decoded.direct_target is None


def test_decode_rejects_misaligned_address() -> None:
    with pytest.raises(ValueError, match="aligned"):
        decode_instruction(
            b"\x00\x00\x00\x00",
            address=0x02000002,
            instruction_set=InstructionSet.ARM,
        )

    with pytest.raises(ValueError, match="aligned"):
        decode_instruction(
            b"\x00\x00",
            address=0x02000001,
            instruction_set=InstructionSet.THUMB,
        )
