import struct

import pytest

import nds_disassembly_toolkit.analysis.model as analysis_model
from nds_disassembly_toolkit.analysis.decoder import decode_instruction
from nds_disassembly_toolkit.analysis.model import (
    ControlFlowKind,
    DecodedInstruction,
    InstructionSet,
)


def test_analysis_register_aliases_are_canonical() -> None:
    assert hasattr(analysis_model, "Register")
    register = analysis_model.Register

    assert register.SP is register.R13
    assert register.LR is register.R14
    assert register.PC is register.R15


def test_analysis_register_names_normalize_gpr_aliases() -> None:
    register = analysis_model.Register

    assert register.from_name("r0") is register.R0
    assert register.from_name("SP") is register.SP
    assert register.from_name("lr") is register.LR
    assert register.from_name("pc") is register.PC
    assert register.from_name("cpsr") is None


def test_decoded_instruction_has_compatible_default_semantics() -> None:
    assert hasattr(analysis_model, "InstructionSemantics")

    decoded = DecodedInstruction(
        address=0x02000000,
        size=4,
        data=b"\x00\x00\xA0\xE1",
        mnemonic="mov",
        operands="r0, r0",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
    )

    assert decoded.semantics == analysis_model.InstructionSemantics()


def test_instruction_semantics_models_typed_memory_and_register_lists() -> None:
    assert hasattr(analysis_model, "OperandKind")
    assert hasattr(analysis_model, "OperandAccess")
    assert hasattr(analysis_model, "MemoryOperand")
    assert hasattr(analysis_model, "InstructionOperand")

    register = analysis_model.Register
    memory = analysis_model.MemoryOperand(
        base=register.SP,
        index=None,
        scale=1,
        displacement=12,
    )
    load = analysis_model.InstructionOperand(
        kind=analysis_model.OperandKind.MEMORY,
        access=analysis_model.OperandAccess.READ,
        memory=memory,
        access_width=4,
    )
    register_list = analysis_model.InstructionOperand(
        kind=analysis_model.OperandKind.REGISTER_LIST,
        access=analysis_model.OperandAccess.READ,
        registers=(register.R4, register.LR),
    )
    semantics = analysis_model.InstructionSemantics(
        operands=(load, register_list),
        registers_read=(register.SP, register.R4, register.LR),
        registers_written=(),
        writeback=True,
    )

    assert load.memory == memory
    assert load.access_width == 4
    assert register_list.registers == (register.R4, register.LR)
    assert semantics.operands == (load, register_list)
    assert semantics.writeback


def test_instruction_operand_rejects_payload_for_wrong_kind() -> None:
    assert hasattr(analysis_model, "OperandKind")
    assert hasattr(analysis_model, "OperandAccess")
    assert hasattr(analysis_model, "InstructionOperand")

    with pytest.raises(ValueError, match="payload"):
        analysis_model.InstructionOperand(
            kind=analysis_model.OperandKind.REGISTER,
            access=analysis_model.OperandAccess.READ,
            immediate=3,
        )


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
