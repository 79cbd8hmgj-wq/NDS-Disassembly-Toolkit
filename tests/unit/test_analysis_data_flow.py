from __future__ import annotations

import struct
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.cfg import build_function_cfg
from nds_disassembly_toolkit.analysis.data_flow import analyze_data_flow
from nds_disassembly_toolkit.analysis.model import (
    AbstractValueKind,
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    Component,
    ConditionCode,
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
)
from nds_disassembly_toolkit.arm32 import (
    Condition,
    DataOpcode,
    encode_branch,
    encode_bx,
    encode_data_processing_immediate,
    encode_data_processing_register,
    encode_literal_load,
    encode_load_store,
    encode_mul,
)
from nds_disassembly_toolkit.arm32 import Register as ArmRegister

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


def _manual_cfg(
    function: FunctionCandidate,
    blocks: tuple[BasicBlock, ...],
    edges: tuple[CFGEdge, ...],
) -> FunctionControlFlowGraph:
    return FunctionControlFlowGraph(
        function=function,
        blocks=blocks,
        edges=edges,
        unresolved_transfers=(),
        decode_failures=(),
    )


def _single_block_cfg(
    *,
    component: str = "arm9",
    block_offset: int = 0,
) -> FunctionControlFlowGraph:
    function = _function(component=component)
    block = BasicBlock(
        component=component,
        address=BASE,
        offset=block_offset,
        instruction_set=InstructionSet.ARM,
        instructions=(),
    )
    return _manual_cfg(function, (block,), ())


def _manual_mov_immediate(
    address: int,
    register: Register,
    immediate: int,
    *,
    condition: ConditionCode = ConditionCode.AL,
) -> DecodedInstruction:
    return DecodedInstruction(
        address=address,
        size=4,
        data=b"\x00" * 4,
        mnemonic="mov",
        operands=f"{register.value}, #{immediate}",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
        semantics=InstructionSemantics(
            operands=(
                InstructionOperand(
                    OperandKind.REGISTER,
                    OperandAccess.WRITE,
                    register=register,
                ),
                InstructionOperand(
                    OperandKind.IMMEDIATE,
                    OperandAccess.READ,
                    immediate=immediate,
                ),
            ),
            registers_written=(register,),
            condition=condition,
        ),
    )


def _manual_mov_register(
    address: int,
    destination: Register,
    source: Register,
) -> DecodedInstruction:
    return DecodedInstruction(
        address=address,
        size=4,
        data=b"\x00" * 4,
        mnemonic="mov",
        operands=f"{destination.value}, {source.value}",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
        semantics=InstructionSemantics(
            operands=(
                InstructionOperand(
                    OperandKind.REGISTER,
                    OperandAccess.WRITE,
                    register=destination,
                ),
                InstructionOperand(
                    OperandKind.REGISTER,
                    OperandAccess.READ,
                    register=source,
                ),
            ),
            registers_read=(source,),
            registers_written=(destination,),
        ),
    )


def _block(address: int, *instructions: DecodedInstruction) -> BasicBlock:
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


def test_data_flow_rejects_mismatched_cfg_component() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    with pytest.raises(ValueError, match="component"):
        analyze_data_flow(_single_block_cfg(component="overlay_1"), component)


def test_data_flow_rejects_inconsistent_block_offset() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    with pytest.raises(ValueError, match="offset"):
        analyze_data_flow(_single_block_cfg(block_offset=4), component)


def test_cfg_join_conflicting_constants_becomes_unknown() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    blocks = (
        _block(BASE),
        _block(BASE + 4, _manual_mov_immediate(BASE + 4, Register.R1, 2)),
        _block(BASE + 8, _manual_mov_immediate(BASE + 8, Register.R1, 3)),
        _block(BASE + 12),
    )
    edges = (
        _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
        _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        _edge(BASE + 4, BASE + 12, CFGEdgeKind.BRANCH),
        _edge(BASE + 8, BASE + 12, CFGEdgeKind.BRANCH),
    )

    flow = analyze_data_flow(_manual_cfg(_function(), blocks, edges), component)
    join = flow.for_block(BASE + 12)
    assert join is not None
    assert join.entry.value(Register.R1).kind is AbstractValueKind.UNKNOWN


def test_cfg_join_equal_constants_keeps_constant() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    blocks = (
        _block(BASE),
        _block(BASE + 4, _manual_mov_immediate(BASE + 4, Register.R1, 2)),
        _block(BASE + 8, _manual_mov_immediate(BASE + 8, Register.R1, 2)),
        _block(BASE + 12),
    )
    edges = (
        _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
        _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        _edge(BASE + 4, BASE + 12, CFGEdgeKind.BRANCH),
        _edge(BASE + 8, BASE + 12, CFGEdgeKind.BRANCH),
    )

    flow = analyze_data_flow(_manual_cfg(_function(), blocks, edges), component)
    join = flow.for_block(BASE + 12)
    assert join is not None
    value = join.entry.value(Register.R1)
    assert value.kind is AbstractValueKind.CONSTANT
    assert value.value == 2


def test_cfg_loop_reaches_stable_deterministic_fixed_point() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    blocks = (
        _block(BASE, _manual_mov_immediate(BASE, Register.R0, 1)),
        _block(BASE + 4, _manual_mov_register(BASE + 4, Register.R1, Register.R0)),
    )
    edges = (
        _edge(BASE, BASE + 4, CFGEdgeKind.FALLTHROUGH),
        _edge(BASE + 4, BASE + 4, CFGEdgeKind.BRANCH),
    )
    cfg = _manual_cfg(_function(), blocks, edges)

    first = analyze_data_flow(cfg, component)
    second = analyze_data_flow(cfg, component)

    assert first == second
    loop = first.for_block(BASE + 4)
    assert loop is not None
    assert loop.exit.value(Register.R0).value == 1
    assert loop.exit.value(Register.R1).value == 1


def test_arm_add_pc_materializes_component_owned_address() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.ADD,
            rd=ArmRegister.R0,
            rn=ArmRegister.PC,
            immediate=4,
        ),
        encode_bx(ArmRegister.LR),
    )

    state = flow.at_instruction(BASE)
    assert state is not None
    value = state.after.value(Register.R0)
    assert value.kind is AbstractValueKind.ADDRESS
    assert value.value == BASE + 12
    assert value.component == "arm9"


def test_arm_literal_pool_load_is_constant_not_guessed_address() -> None:
    data = bytearray(0x10)
    struct.pack_into("<I", data, 0, encode_literal_load(BASE, BASE + 8, ArmRegister.R0))
    struct.pack_into("<I", data, 4, encode_bx(ArmRegister.LR))
    struct.pack_into("<I", data, 8, BASE + 0x40)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(data))

    flow = analyze_data_flow(build_function_cfg(component, _function()), component)

    state = flow.at_instruction(BASE)
    assert state is not None
    value = state.after.value(Register.R0)
    assert value.kind is AbstractValueKind.CONSTANT
    assert value.value == BASE + 0x40
    assert value.component is None


def test_thumb_literal_pool_uses_aligned_pc_plus_four() -> None:
    data = bytearray(0x0C)
    struct.pack_into("<H", data, 0, 0x4801)  # ldr r0, [pc, #4] -> BASE + 8
    struct.pack_into("<H", data, 2, 0x4770)  # bx lr
    struct.pack_into("<I", data, 8, 0x12345678)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(data))

    flow = analyze_data_flow(
        build_function_cfg(
            component,
            _function(instruction_set=InstructionSet.THUMB),
        ),
        component,
    )

    state = flow.at_instruction(BASE)
    assert state is not None
    value = state.after.value(Register.R0)
    assert value.kind is AbstractValueKind.CONSTANT
    assert value.value == 0x12345678


def test_out_of_range_literal_is_unknown_with_stable_warning() -> None:
    data = _arm_words(
        encode_literal_load(BASE, BASE + 0x100, ArmRegister.R0),
        encode_bx(ArmRegister.LR),
    )
    component = Component("arm9", Path("arm9.bin"), BASE, data)

    flow = analyze_data_flow(build_function_cfg(component, _function()), component)

    state = flow.at_instruction(BASE)
    assert state is not None
    assert state.after.value(Register.R0).kind is AbstractValueKind.UNKNOWN
    assert flow.warnings == (
        "literal read at 0x02000000 is outside arm9: 0x02000100",
    )


def test_conditional_write_joins_executed_and_skipped_states() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.MOV,
            rd=ArmRegister.R0,
            immediate=1,
        ),
        encode_data_processing_immediate(
            DataOpcode.MOV,
            rd=ArmRegister.R0,
            immediate=2,
            condition=Condition.NE,
        ),
        encode_bx(ArmRegister.LR),
    )

    state = flow.at_instruction(BASE + 4)
    assert state is not None
    assert state.after.value(Register.R0).kind is AbstractValueKind.UNKNOWN


def test_direct_call_clobbers_caller_saved_registers_only() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.MOV,
            rd=ArmRegister.R0,
            immediate=1,
        ),
        encode_data_processing_immediate(
            DataOpcode.MOV,
            rd=ArmRegister.R4,
            immediate=4,
        ),
        encode_branch(BASE + 8, BASE + 0x100, link=True),
        encode_bx(ArmRegister.LR),
    )

    call = flow.at_instruction(BASE + 8)
    assert call is not None
    assert call.after.value(Register.R0).kind is AbstractValueKind.UNKNOWN
    assert call.after.value(Register.R4).value == 4


def test_overlapping_components_keep_independent_address_ownership() -> None:
    word = encode_data_processing_immediate(
        DataOpcode.ADD,
        rd=ArmRegister.R0,
        rn=ArmRegister.PC,
        immediate=0,
    )
    payload = _arm_words(word, encode_bx(ArmRegister.LR))
    overlay_1 = Component("overlay_1", Path("ov1.bin"), BASE, payload)
    overlay_2 = Component("overlay_2", Path("ov2.bin"), BASE, payload)

    flow_1 = analyze_data_flow(
        build_function_cfg(overlay_1, _function(component="overlay_1")),
        overlay_1,
    )
    flow_2 = analyze_data_flow(
        build_function_cfg(overlay_2, _function(component="overlay_2")),
        overlay_2,
    )

    state_1 = flow_1.at_instruction(BASE)
    state_2 = flow_2.at_instruction(BASE)
    assert state_1 is not None and state_2 is not None
    assert state_1.after.value(Register.R0).component == "overlay_1"
    assert state_2.after.value(Register.R0).component == "overlay_2"
