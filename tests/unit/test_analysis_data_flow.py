from __future__ import annotations

import struct
from pathlib import Path

from nds_disassembly_toolkit.analysis.cfg import build_function_cfg
from nds_disassembly_toolkit.analysis.data_flow import analyze_data_flow
from nds_disassembly_toolkit.analysis.model import (
    AbstractValueKind,
    Component,
    FunctionCandidate,
    FunctionDataFlow,
    InstructionSet,
    Register,
)
from nds_disassembly_toolkit.arm32 import (
    DataOpcode,
    Register as ArmRegister,
    encode_bx,
    encode_data_processing_immediate,
    encode_data_processing_register,
    encode_load_store,
    encode_mul,
)

BASE = 0x02000000


def _arm_words(*words: int) -> bytes:
    return b"".join(struct.pack("<I", word) for word in words)


def _function(
    *,
    component: str = "arm9",
    address: int = BASE,
    instruction_set: InstructionSet = InstructionSet.ARM,
) -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=address,
        offset=address - BASE,
        instruction_set=instruction_set,
        confidence="high",
        evidence=("test",),
    )


def _flow_from_arm(*words: int) -> FunctionDataFlow:
    component = Component("arm9", Path("arm9.bin"), BASE, _arm_words(*words))
    return analyze_data_flow(build_function_cfg(component, _function()), component)


def test_mov_and_add_propagate_exact_constants() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.MOV,
            rd=ArmRegister.R0,
            immediate=4,
        ),
        encode_data_processing_immediate(
            DataOpcode.ADD,
            rd=ArmRegister.R1,
            rn=ArmRegister.R0,
            immediate=3,
        ),
        encode_bx(ArmRegister.LR),
    )

    state = flow.at_instruction(BASE + 4)
    assert state is not None
    value = state.after.value(Register.R1)
    assert value.kind is AbstractValueKind.CONSTANT
    assert value.value == 7
    assert value.provenance == (BASE, BASE + 4)


def test_register_move_and_subtract_propagate_known_value() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.MOV,
            rd=ArmRegister.R0,
            immediate=10,
        ),
        encode_data_processing_register(
            DataOpcode.MOV,
            rd=ArmRegister.R1,
            rm=ArmRegister.R0,
        ),
        encode_data_processing_immediate(
            DataOpcode.SUB,
            rd=ArmRegister.R2,
            rn=ArmRegister.R1,
            immediate=3,
        ),
        encode_bx(ArmRegister.LR),
    )

    state = flow.at_instruction(BASE + 8)
    assert state is not None
    value = state.after.value(Register.R2)
    assert value.kind is AbstractValueKind.CONSTANT
    assert value.value == 7


def test_unknown_register_source_keeps_destination_unknown() -> None:
    flow = _flow_from_arm(
        encode_data_processing_register(
            DataOpcode.MOV,
            rd=ArmRegister.R1,
            rm=ArmRegister.R0,
        ),
        encode_bx(ArmRegister.LR),
    )

    state = flow.at_instruction(BASE)
    assert state is not None
    assert state.after.value(Register.R1).kind is AbstractValueKind.UNKNOWN


def test_unsupported_write_clears_previously_known_destination() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.MOV,
            rd=ArmRegister.R2,
            immediate=9,
        ),
        encode_mul(ArmRegister.R2, ArmRegister.R0, ArmRegister.R1),
        encode_bx(ArmRegister.LR),
    )

    before_mul = flow.at_instruction(BASE + 4)
    assert before_mul is not None
    assert before_mul.before.value(Register.R2).kind is AbstractValueKind.CONSTANT
    assert before_mul.after.value(Register.R2).kind is AbstractValueKind.UNKNOWN


def test_memory_base_use_reclassifies_constant_as_unowned_address() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.MOV,
            rd=ArmRegister.R2,
            immediate=BASE,
        ),
        encode_load_store(
            ArmRegister.R0,
            ArmRegister.R2,
            load=True,
        ),
        encode_bx(ArmRegister.LR),
    )

    state = flow.at_instruction(BASE + 4)
    assert state is not None
    value = state.after.value(Register.R2)
    assert value.kind is AbstractValueKind.ADDRESS
    assert value.value == BASE
    assert value.component is None
    assert value.provenance == (BASE, BASE + 4)
