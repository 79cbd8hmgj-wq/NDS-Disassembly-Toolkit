import struct
from pathlib import Path

from nds_disassembly_toolkit.analysis.cfg import build_function_cfg
from nds_disassembly_toolkit.analysis.data_flow import analyze_data_flow
from nds_disassembly_toolkit.analysis.model import (
    AbstractValueKind,
    ArgumentLocationKind,
    Component,
    FunctionCandidate,
    InstructionSet,
    Register,
)
from nds_disassembly_toolkit.arm32 import (
    Condition,
    Register as ArmRegister,
    encode_branch,
    encode_bx,
    encode_load_store,
)

BASE = 0x02000000


def _function() -> FunctionCandidate:
    return FunctionCandidate(
        component="arm9",
        address=BASE,
        offset=0,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )


def _flow_from_arm(*words: int):
    data = b"".join(struct.pack("<I", word) for word in words)
    component = Component("arm9", Path("arm9.bin"), BASE, data)
    return analyze_data_flow(build_function_cfg(component, _function()), component)


def test_use_before_overwrite_recovers_register_argument() -> None:
    flow = _flow_from_arm(0xE2804001, 0xE12FFF1E)  # add r4,r0,#1; bx lr

    assert flow.summary is not None
    argument = next(item for item in flow.summary.arguments if item.register is Register.R0)
    assert argument.index == 0
    assert argument.kind is ArgumentLocationKind.REGISTER
    assert argument.uses == (BASE,)


def test_write_before_first_read_is_not_entry_argument() -> None:
    flow = _flow_from_arm(
        0xE3A00007,  # mov r0,#7
        0xE2804001,  # add r4,r0,#1
        0xE12FFF1E,
    )

    assert flow.summary is not None
    assert all(item.register is not Register.R0 for item in flow.summary.arguments)


def test_read_write_same_instruction_records_argument_then_kills_liveness() -> None:
    flow = _flow_from_arm(
        0xE2800001,  # add r0,r0,#1
        0xE2804001,  # add r4,r0,#1
        0xE12FFF1E,
    )

    assert flow.summary is not None
    argument = next(item for item in flow.summary.arguments if item.register is Register.R0)
    assert argument.uses == (BASE,)


def test_call_kills_entry_argument_liveness_for_later_use() -> None:
    flow = _flow_from_arm(
        0xEB000000,  # bl BASE+8
        0xE2804001,  # add r4,r0,#1
        0xE12FFF1E,
    )

    assert flow.summary is not None
    assert all(item.register is not Register.R0 for item in flow.summary.arguments)


def test_join_intersects_entry_argument_liveness() -> None:
    flow = _flow_from_arm(
        encode_branch(BASE, BASE + 12, condition=Condition.NE),
        0xE3A00007,  # mov r0,#7
        encode_branch(BASE + 8, BASE + 16),
        0xE1A01001,  # mov r1,r1
        0xE2804001,  # add r4,r0,#1
        encode_bx(ArmRegister.LR),
    )

    assert flow.summary is not None
    assert all(item.register is not Register.R0 for item in flow.summary.arguments)


def test_entry_sp_load_recovers_stack_argument() -> None:
    flow = _flow_from_arm(
        encode_load_store(
            ArmRegister.R0,
            ArmRegister.SP,
            offset=0,
            load=True,
        ),
        encode_bx(ArmRegister.LR),
    )

    assert flow.summary is not None
    stack_argument = next(
        item
        for item in flow.summary.arguments
        if item.kind is ArgumentLocationKind.STACK and item.stack_offset == 0
    )
    assert stack_argument.index is None
    assert stack_argument.uses == (BASE,)


def test_constant_return_is_reported_at_return_site() -> None:
    flow = _flow_from_arm(0xE3A00007, 0xE12FFF1E)  # mov r0,#7; bx lr

    assert flow.summary is not None
    evidence = flow.summary.returns[0]
    assert evidence.return_address == BASE + 4
    assert evidence.value.kind is AbstractValueKind.CONSTANT
    assert evidence.value.value == 7


def test_distinct_return_sites_are_kept_sorted() -> None:
    flow = _flow_from_arm(
        0xE3A00001,  # mov r0,#1
        encode_branch(BASE + 4, BASE + 16, condition=Condition.NE),
        0xE3A00002,  # mov r0,#2
        encode_bx(ArmRegister.LR),
        0xE3A00003,  # mov r0,#3
        encode_bx(ArmRegister.LR),
    )

    assert flow.summary is not None
    assert tuple(item.return_address for item in flow.summary.returns) == (
        BASE + 12,
        BASE + 20,
    )
    assert tuple(item.value.value for item in flow.summary.returns) == (2, 3)


def test_unknown_r0_return_is_reported_as_unknown() -> None:
    flow = _flow_from_arm(encode_bx(ArmRegister.LR))

    assert flow.summary is not None
    evidence = flow.summary.returns[0]
    assert evidence.return_address == BASE
    assert evidence.value.kind is AbstractValueKind.UNKNOWN
