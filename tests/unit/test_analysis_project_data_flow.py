from __future__ import annotations

from pathlib import Path

from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    ArgumentEvidence,
    ArgumentLocationKind,
    BasicBlock,
    BlockFlowState,
    Component,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    FunctionSummary,
    InstructionFlowState,
    InstructionSet,
    Register,
    RegisterState,
    ReturnEvidence,
    StackAccess,
    StackAccessKind,
    StackFrame,
    StackSlot,
    StackSlotKind,
    StackState,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject, ComponentAnalysisBundle

BASE = 0x02000000


def _function() -> FunctionCandidate:
    return FunctionCandidate("arm9", BASE, 0, InstructionSet.ARM, "high", ("seed",))


def _instruction(address: int, flow: ControlFlowKind) -> DecodedInstruction:
    return DecodedInstruction(
        address,
        4,
        b"\x00" * 4,
        "bx" if flow is ControlFlowKind.RETURN else "mov",
        "",
        InstructionSet.ARM,
        flow,
    )


def _cfg() -> FunctionControlFlowGraph:
    first = (
        _instruction(BASE, ControlFlowKind.ORDINARY),
        _instruction(BASE + 4, ControlFlowKind.RETURN),
    )
    second = (
        _instruction(BASE + 0x10, ControlFlowKind.ORDINARY),
        _instruction(BASE + 0x14, ControlFlowKind.RETURN),
    )
    return FunctionControlFlowGraph(
        _function(),
        (
            BasicBlock("arm9", BASE, 0, InstructionSet.ARM, first),
            BasicBlock("arm9", BASE + 0x10, 0x10, InstructionSet.ARM, second),
        ),
        (),
        (),
        (),
    )


def _flow(cfg: FunctionControlFlowGraph) -> FunctionDataFlow:
    constant = AbstractValue(AbstractValueKind.CONSTANT, 7, provenance=(BASE, BASE + 4))
    owned = AbstractValue(
        AbstractValueKind.ADDRESS,
        0x02200000,
        "overlay_3",
        (BASE + 0x10, BASE + 0x14),
    )
    unowned = AbstractValue(AbstractValueKind.ADDRESS, 0x04000000, provenance=(BASE,))
    entry_stack = StackState(0, ((Register.R11, -0x20),))
    inner_stack = StackState(-0x20, ((Register.R11, -0x20),))
    exit_stack = StackState(0, ((Register.R11, -0x20),))
    r0 = RegisterState(((Register.R0, unowned),))
    r1 = RegisterState(((Register.R1, constant),))
    r2 = RegisterState(((Register.R2, owned),))
    r3 = RegisterState(((Register.R3, constant),))
    instructions = tuple(
        instruction for block in cfg.blocks for instruction in block.instructions
    )
    return FunctionDataFlow(
        cfg.function,
        (
            BlockFlowState(BASE, InstructionSet.ARM, r0, r1, entry_stack, inner_stack),
            BlockFlowState(
                BASE + 0x10,
                InstructionSet.ARM,
                r2,
                r3,
                inner_stack,
                exit_stack,
            ),
        ),
        (
            InstructionFlowState(instructions[0], r0, r1, entry_stack, inner_stack),
            InstructionFlowState(instructions[1], r1, r1, inner_stack, inner_stack),
            InstructionFlowState(instructions[2], r2, r2, inner_stack, inner_stack),
            InstructionFlowState(instructions[3], r2, r3, inner_stack, exit_stack),
        ),
        ("stack join became conservative", "indirect value remained unknown"),
        FunctionSummary(
            (
                ArgumentEvidence(
                    0,
                    ArgumentLocationKind.REGISTER,
                    Register.R0,
                    None,
                    (BASE,),
                ),
                ArgumentEvidence(
                    None,
                    ArgumentLocationKind.STACK,
                    None,
                    0,
                    (BASE + 0x10,),
                ),
            ),
            (ReturnEvidence(BASE + 4, constant), ReturnEvidence(BASE + 0x14, owned)),
            StackFrame(0x20, Register.R11, True),
            (
                StackSlot(
                    -0x10,
                    StackSlotKind.LOCAL,
                    (
                        StackAccess(BASE, StackAccessKind.STORE, 4),
                        StackAccess(BASE + 0x10, StackAccessKind.LOAD, 4),
                    ),
                ),
                StackSlot(
                    -4,
                    StackSlotKind.SAVED_REGISTER,
                    (StackAccess(BASE, StackAccessKind.STORE, 4),),
                ),
                StackSlot(
                    0,
                    StackSlotKind.INCOMING_ARGUMENT,
                    (StackAccess(BASE + 0x10, StackAccessKind.LOAD, 4),),
                ),
            ),
        ),
    )


def test_data_flow_and_summary_round_trip_exactly(tmp_path: Path) -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    cfg = _cfg()
    flow = _flow(cfg)
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                component,
                functions=(cfg.function,),
                cfgs=(cfg,),
                data_flows=(flow,),
            )
        )
    with AnalysisProject.open(root, read_only=True) as project:
        stored = project.data_flow("arm9", BASE, InstructionSet.ARM)

    assert stored == flow
    assert stored is not None
    assert stored.blocks[0].entry.value(Register.R0).provenance == (BASE,)
    assert stored.blocks[1].entry.value(Register.R2).provenance == (
        BASE + 0x10,
        BASE + 0x14,
    )
    assert stored.summary is not None
    assert stored.summary.returns[0].value.provenance == (BASE, BASE + 4)
    assert stored.summary.returns[1].value.provenance == (
        BASE + 0x10,
        BASE + 0x14,
    )
