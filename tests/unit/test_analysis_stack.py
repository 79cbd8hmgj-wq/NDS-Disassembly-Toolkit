from __future__ import annotations

import struct
from pathlib import Path

from nds_disassembly_toolkit.analysis.cfg import build_function_cfg
from nds_disassembly_toolkit.analysis.data_flow import analyze_data_flow
from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    Component,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    OperandAccess,
    OperandKind,
    Register,
    StackAccessKind,
    StackSlotKind,
)
from nds_disassembly_toolkit.analysis.stack import analyze_stack
from nds_disassembly_toolkit.arm32 import (
    DataOpcode,
    encode_bx,
    encode_data_processing_immediate,
    encode_data_processing_register,
    encode_load_store,
    encode_pop,
    encode_push,
)
from nds_disassembly_toolkit.arm32 import Register as ArmRegister

BASE = 0x02000000


def _function(instruction_set: InstructionSet = InstructionSet.ARM) -> FunctionCandidate:
    return FunctionCandidate(
        component="arm9",
        address=BASE,
        offset=0,
        instruction_set=instruction_set,
        confidence="high",
        evidence=("test",),
    )


def _flow_from_arm(*words: int) -> FunctionDataFlow:
    data = b"".join(struct.pack("<I", word) for word in words)
    component = Component("arm9", Path("arm9.bin"), BASE, data)
    return analyze_data_flow(build_function_cfg(component, _function()), component)


def _flow_from_thumb(*halfwords: int) -> FunctionDataFlow:
    data = b"".join(struct.pack("<H", word) for word in halfwords)
    component = Component("arm9", Path("arm9.bin"), BASE, data)
    return analyze_data_flow(
        build_function_cfg(component, _function(InstructionSet.THUMB)),
        component,
    )


def test_arm_push_and_sub_sp_recover_frame_size() -> None:
    flow = _flow_from_arm(
        encode_push((ArmRegister.R4, ArmRegister.LR)),
        encode_data_processing_immediate(
            DataOpcode.SUB,
            rd=ArmRegister.SP,
            rn=ArmRegister.SP,
            immediate=0x10,
        ),
        encode_data_processing_immediate(
            DataOpcode.ADD,
            rd=ArmRegister.SP,
            rn=ArmRegister.SP,
            immediate=0x10,
        ),
        encode_pop((ArmRegister.R4, ArmRegister.PC)),
    )

    stack = analyze_stack(flow)

    assert stack.frame.frame_size == 0x18
    assert stack.frame.stack_depth_known


def test_thumb_stack_adjustments_match_arm_depth() -> None:
    flow = _flow_from_thumb(0xB510, 0xB084, 0xB004, 0xBD10)

    stack = analyze_stack(flow)

    assert stack.frame.frame_size == 0x18
    assert stack.frame.stack_depth_known


def _stack_adjust(address: int, immediate: int) -> DecodedInstruction:
    return DecodedInstruction(
        address=address,
        size=4,
        data=b"\x00" * 4,
        mnemonic="sub",
        operands=f"sp, sp, #{immediate}",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
        semantics=InstructionSemantics(
            operands=(
                InstructionOperand(
                    OperandKind.REGISTER,
                    OperandAccess.READ | OperandAccess.WRITE,
                    register=Register.SP,
                ),
                InstructionOperand(
                    OperandKind.REGISTER,
                    OperandAccess.READ,
                    register=Register.SP,
                ),
                InstructionOperand(
                    OperandKind.IMMEDIATE,
                    OperandAccess.READ,
                    immediate=immediate,
                ),
            ),
            registers_read=(Register.SP,),
            registers_written=(Register.SP,),
        ),
    )


def _empty_block(address: int, *instructions: DecodedInstruction) -> BasicBlock:
    return BasicBlock(
        component="arm9",
        address=address,
        offset=address - BASE,
        instruction_set=InstructionSet.ARM,
        instructions=instructions,
    )


def _edge(source: int, target: int, kind: CFGEdgeKind) -> CFGEdge:
    return CFGEdge(
        source_address=source,
        source_instruction_address=source,
        target_address=target,
        target_instruction_set=InstructionSet.ARM,
        kind=kind,
    )


def test_conflicting_stack_depths_become_unknown_at_join() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    cfg = FunctionControlFlowGraph(
        function=_function(),
        blocks=(
            _empty_block(BASE),
            _empty_block(BASE + 4, _stack_adjust(BASE + 4, 4)),
            _empty_block(BASE + 8, _stack_adjust(BASE + 8, 8)),
            _empty_block(BASE + 12),
        ),
        edges=(
            _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
            _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
            _edge(BASE + 4, BASE + 12, CFGEdgeKind.BRANCH),
            _edge(BASE + 8, BASE + 12, CFGEdgeKind.BRANCH),
        ),
        unresolved_transfers=(),
        decode_failures=(),
    )

    flow = analyze_data_flow(cfg, component)
    join = flow.for_block(BASE + 12)

    assert join is not None
    assert join.stack_entry is not None
    assert join.stack_entry.offset is None
    assert not analyze_stack(flow).frame.stack_depth_known


def test_sp_relative_store_and_load_recover_local_slot() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.SUB,
            rd=ArmRegister.SP,
            rn=ArmRegister.SP,
            immediate=0x10,
        ),
        encode_load_store(
            ArmRegister.R0,
            ArmRegister.SP,
            offset=4,
            load=False,
        ),
        encode_load_store(
            ArmRegister.R1,
            ArmRegister.SP,
            offset=4,
            load=True,
        ),
        encode_data_processing_immediate(
            DataOpcode.ADD,
            rd=ArmRegister.SP,
            rn=ArmRegister.SP,
            immediate=0x10,
        ),
        encode_bx(ArmRegister.LR),
    )

    stack = analyze_stack(flow)
    slot = next(item for item in stack.slots if item.offset == -0x0C)

    assert slot.kind is StackSlotKind.LOCAL
    assert tuple(access.kind for access in slot.accesses) == (
        StackAccessKind.STORE,
        StackAccessKind.LOAD,
    )
    assert tuple(access.width for access in slot.accesses) == (4, 4)


def test_explicit_frame_pointer_recovers_frame_relative_slot() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.SUB,
            rd=ArmRegister.SP,
            rn=ArmRegister.SP,
            immediate=0x10,
        ),
        encode_data_processing_register(
            DataOpcode.MOV,
            rd=ArmRegister.R11,
            rm=ArmRegister.SP,
        ),
        encode_load_store(
            ArmRegister.R0,
            ArmRegister.R11,
            offset=-4,
            load=False,
        ),
        encode_data_processing_immediate(
            DataOpcode.ADD,
            rd=ArmRegister.SP,
            rn=ArmRegister.SP,
            immediate=0x10,
        ),
        encode_bx(ArmRegister.LR),
    )

    stack = analyze_stack(flow)

    assert stack.frame.frame_pointer is Register.R11
    slot = next(item for item in stack.slots if item.offset == -0x14)
    assert slot.kind is StackSlotKind.LOCAL
    assert slot.accesses[0].kind is StackAccessKind.STORE


def test_push_registers_create_saved_register_slots() -> None:
    flow = _flow_from_arm(
        encode_push((ArmRegister.R4, ArmRegister.LR)),
        encode_pop((ArmRegister.R4, ArmRegister.PC)),
    )

    stack = analyze_stack(flow)
    saved = tuple(slot for slot in stack.slots if slot.kind is StackSlotKind.SAVED_REGISTER)

    assert tuple(slot.offset for slot in saved) == (-8, -4)
