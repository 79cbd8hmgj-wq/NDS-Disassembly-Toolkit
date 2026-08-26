from __future__ import annotations

import struct

import pytest

from nds_disassembly_toolkit.arm32 import (
    ArmProgram,
    Condition,
    DataOpcode,
    Register,
    ShiftType,
    align,
    branch_to,
    decode_branch_target,
    encode_branch,
    encode_bx,
    encode_data_processing_immediate,
    encode_data_processing_register,
    encode_data_processing_shifted_register,
    encode_halfword_transfer,
    encode_literal_load,
    encode_load_store,
    encode_mul,
    encode_pop,
    encode_push,
    label,
    literal,
    load_literal,
    word,
)
from nds_disassembly_toolkit.errors import WorkspaceError

PROGRAM_BASE = 0x02001000


def test_branch_encodings_and_validation() -> None:
    assert encode_branch(0x1000, 0x1010) == 0xEA000002
    assert encode_branch(0x1000, 0x1010, link=True) == 0xEB000002
    assert encode_branch(0x1010, 0x1000) == 0xEAFFFFFA
    assert decode_branch_target(0x1010, 0xEAFFFFFA) == 0x1000
    assert encode_branch(0x1000, 0x1010, condition=Condition.EQ) == 0x0A000002
    assert encode_bx(Register.LR) == 0xE12FFF1E

    with pytest.raises(WorkspaceError, match="ARM aligned"):
        encode_branch(0x1001, 0x1010)
    with pytest.raises(WorkspaceError, match="out of range"):
        encode_branch(0, 0x08000000)


def test_data_processing_encodings() -> None:
    assert (
        encode_data_processing_immediate(DataOpcode.MOV, rd=Register.R0, immediate=1)
        == 0xE3A00001
    )
    assert (
        encode_data_processing_immediate(
            DataOpcode.ADD,
            rd=Register.R1,
            rn=Register.R2,
            immediate=4,
        )
        == 0xE2821004
    )
    assert (
        encode_data_processing_immediate(
            DataOpcode.CMP,
            rn=Register.R3,
            immediate=6,
            set_flags=True,
        )
        == 0xE3530006
    )
    assert (
        encode_data_processing_register(
            DataOpcode.MOV,
            rd=Register.R4,
            rm=Register.R5,
            condition=Condition.NE,
        )
        == 0x11A04005
    )
    with pytest.raises(WorkspaceError, match="rotated immediate"):
        encode_data_processing_immediate(DataOpcode.MOV, rd=Register.R0, immediate=0x12345678)


def test_shifted_register_encodings() -> None:
    assert (
        encode_data_processing_shifted_register(
            DataOpcode.MOV,
            rd=Register.R0,
            rm=Register.R0,
            shift_type=ShiftType.LSR,
            shift_amount=8,
        )
        == 0xE1A00420
    )
    assert (
        encode_data_processing_shifted_register(
            DataOpcode.ADD,
            rd=Register.R1,
            rn=Register.R1,
            rm=Register.R0,
            shift_type=ShiftType.LSL,
            shift_amount=2,
        )
        == 0xE0811100
    )


def test_multiply_memory_and_stack_encodings() -> None:
    assert encode_mul(Register.R0, Register.R1, Register.R2) == 0xE0000291
    assert encode_load_store(Register.R0, Register.R1, offset=4, load=True) == 0xE5910004
    assert (
        encode_load_store(
            Register.R2,
            Register.R3,
            offset=-1,
            load=False,
            byte=True,
        )
        == 0xE5432001
    )
    assert encode_halfword_transfer(Register.R0, Register.R1, offset=2, load=True) == 0xE1D100B2
    assert encode_halfword_transfer(Register.R2, Register.R3, offset=4, load=False) == 0xE1C320B4
    assert encode_push((Register.R4, Register.R5, Register.LR)) == 0xE92D4030
    assert encode_pop((Register.R4, Register.R5, Register.PC)) == 0xE8BD8030

    with pytest.raises(WorkspaceError, match="duplicate"):
        encode_push((Register.R4, Register.R4))
    with pytest.raises(WorkspaceError, match="nonempty"):
        encode_pop(())


def test_literal_load_encodes_pc_relative_offsets() -> None:
    assert encode_literal_load(0x1000, 0x1010, Register.R0) == 0xE59F0008
    assert encode_literal_load(0x1010, 0x1000, Register.R1) == 0xE51F1018
    with pytest.raises(WorkspaceError, match="literal range"):
        encode_literal_load(0x1000, 0x3000, Register.R0)


def test_program_build_resolves_symbols_and_uses_requested_size() -> None:
    program = ArmProgram(
        (
            label("entry"),
            load_literal(Register.R0, "value"),
            branch_to("done"),
            align(16),
            literal("value", 0x12345678),
            label("done"),
            word(encode_bx(Register.LR)),
        )
    )

    built = program.build(PROGRAM_BASE, 0x100)

    assert len(built.image) == 0x100
    assert built.symbols == {
        "entry": PROGRAM_BASE,
        "value": PROGRAM_BASE + 0x10,
        "done": PROGRAM_BASE + 0x14,
    }
    assert struct.unpack_from("<I", built.image, 0x10)[0] == 0x12345678
    assert struct.unpack_from("<I", built.image, 0x14)[0] == 0xE12FFF1E
    assert built.image[0x18:] == b"\0" * (0x100 - 0x18)
    assert [item.kind for item in built.relocations] == ["literal_load", "branch"]


def test_program_rejects_invalid_sizes_and_symbols() -> None:
    with pytest.raises(WorkspaceError, match="nonnegative"):
        ArmProgram((word(0),)).build(PROGRAM_BASE, -4)
    with pytest.raises(WorkspaceError, match="word aligned"):
        ArmProgram((word(0),)).build(PROGRAM_BASE, 0x101)

    duplicate = ArmProgram((label("same"), word(0), label("same")))
    with pytest.raises(WorkspaceError, match="duplicate symbol"):
        duplicate.build(PROGRAM_BASE, 0x100)

    unresolved = ArmProgram((branch_to("missing"),))
    with pytest.raises(WorkspaceError, match="unresolved symbol"):
        unresolved.build(PROGRAM_BASE, 0x100)


def test_program_rejects_literal_and_image_overflow() -> None:
    far_literal_items = [load_literal(Register.R0, "far")]
    far_literal_items.extend(word(0) for _ in range(1025))
    far_literal_items.append(literal("far", 1))
    with pytest.raises(WorkspaceError, match="literal range"):
        ArmProgram(tuple(far_literal_items)).build(PROGRAM_BASE, 0x2000)

    too_large = ArmProgram(tuple(word(0) for _ in range(65)))
    with pytest.raises(WorkspaceError, match="image exceeds"):
        too_large.build(PROGRAM_BASE, 0x100)
