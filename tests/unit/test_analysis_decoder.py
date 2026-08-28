import struct

import pytest

import nds_disassembly_toolkit.analysis.model as analysis_model
from nds_disassembly_toolkit.analysis.decoder import decode_instruction
from nds_disassembly_toolkit.analysis.model import (
    ConditionCode,
    ControlFlowKind,
    DecodedInstruction,
    InstructionSet,
    OperandAccess,
    OperandKind,
    Register,
)


def test_analysis_register_aliases_are_canonical() -> None:
    assert Register.SP is Register.R13
    assert Register.LR is Register.R14
    assert Register.PC is Register.R15


def test_analysis_register_names_normalize_gpr_aliases() -> None:
    assert Register.from_name("r0") is Register.R0
    assert Register.from_name("SP") is Register.SP
    assert Register.from_name("lr") is Register.LR
    assert Register.from_name("pc") is Register.PC
    assert Register.from_name("cpsr") is None


def test_decoded_instruction_has_compatible_default_semantics() -> None:
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
    memory = analysis_model.MemoryOperand(
        base=Register.SP,
        index=None,
        scale=1,
        displacement=12,
    )
    load = analysis_model.InstructionOperand(
        kind=OperandKind.MEMORY,
        access=OperandAccess.READ,
        memory=memory,
        access_width=4,
    )
    register_list = analysis_model.InstructionOperand(
        kind=OperandKind.REGISTER_LIST,
        access=OperandAccess.READ,
        registers=(Register.R4, Register.LR),
    )
    semantics = analysis_model.InstructionSemantics(
        operands=(load, register_list),
        registers_read=(Register.SP, Register.R4, Register.LR),
        registers_written=(),
        writeback=True,
    )

    assert load.memory == memory
    assert load.access_width == 4
    assert register_list.registers == (Register.R4, Register.LR)
    assert semantics.operands == (load, register_list)
    assert semantics.writeback


def test_instruction_operand_rejects_payload_for_wrong_kind() -> None:
    with pytest.raises(ValueError, match="payload"):
        analysis_model.InstructionOperand(
            kind=OperandKind.REGISTER,
            access=OperandAccess.READ,
            immediate=3,
        )


def test_decode_arm_move_exposes_typed_register_effects() -> None:
    decoded = decode_instruction(
        struct.pack("<I", 0xE1A01000),  # mov r1, r0
        address=0x02000000,
        instruction_set=InstructionSet.ARM,
    )

    assert decoded is not None
    assert [operand.kind for operand in decoded.semantics.operands] == [
        OperandKind.REGISTER,
        OperandKind.REGISTER,
    ]
    assert decoded.semantics.operands[0].register is Register.R1
    assert decoded.semantics.operands[1].register is Register.R0
    assert Register.R0 in decoded.semantics.registers_read
    assert Register.R1 in decoded.semantics.registers_written


def test_decode_thumb_literal_load_exposes_memory_direction_and_width() -> None:
    decoded = decode_instruction(
        struct.pack("<H", 0x4800),  # ldr r0, [pc, #0]
        address=0x02000000,
        instruction_set=InstructionSet.THUMB,
    )

    assert decoded is not None
    operand = decoded.semantics.operands[1]
    assert operand.kind is OperandKind.MEMORY
    assert operand.memory is not None
    assert operand.memory.base is Register.PC
    assert operand.memory.displacement == 0
    assert operand.access == OperandAccess.READ
    assert operand.access_width == 4


def test_decode_arm_condition_and_writeback_are_typed() -> None:
    conditional = decode_instruction(
        struct.pack("<I", 0x11A00001),  # movne r0, r1
        address=0x02000000,
        instruction_set=InstructionSet.ARM,
    )
    writeback_store = decode_instruction(
        struct.pack("<I", 0xE5A10004),  # str r0, [r1, #4]!
        address=0x02000004,
        instruction_set=InstructionSet.ARM,
    )

    assert conditional is not None
    assert conditional.semantics.condition is ConditionCode.NE
    assert writeback_store is not None
    assert writeback_store.semantics.writeback
    memory = writeback_store.semantics.operands[1]
    assert memory.access == OperandAccess.WRITE
    assert memory.access_width == 4


def test_decode_push_normalizes_register_list() -> None:
    arm = decode_instruction(
        struct.pack("<I", 0xE92D4010),  # push {r4, lr}
        address=0x02000000,
        instruction_set=InstructionSet.ARM,
    )
    thumb = decode_instruction(
        struct.pack("<H", 0xB510),  # push {r4, lr}
        address=0x02000000,
        instruction_set=InstructionSet.THUMB,
    )

    assert arm is not None
    assert thumb is not None
    for decoded in (arm, thumb):
        assert len(decoded.semantics.operands) == 1
        operand = decoded.semantics.operands[0]
        assert operand.kind is OperandKind.REGISTER_LIST
        assert operand.registers == (Register.R4, Register.LR)


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
