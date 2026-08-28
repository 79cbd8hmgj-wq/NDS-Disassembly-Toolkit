from __future__ import annotations

import sqlite3
from pathlib import Path

from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    Component,
    ConditionCode,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    MemoryOperand,
    OperandAccess,
    OperandKind,
    OperandShift,
    Register,
    ShiftKind,
    UnresolvedTransfer,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
)

BASE = 0x02000000


def _function() -> FunctionCandidate:
    return FunctionCandidate(
        component="arm9",
        address=BASE,
        offset=0,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("seed",),
    )


def _cfg() -> FunctionControlFlowGraph:
    move = DecodedInstruction(
        address=BASE,
        size=4,
        data=b"\x01\x00\xa0\xe3",
        mnemonic="mov",
        operands="r0, #1",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
        semantics=InstructionSemantics(
            operands=(
                InstructionOperand(
                    OperandKind.REGISTER,
                    OperandAccess.WRITE,
                    register=Register.R0,
                    shift=OperandShift(ShiftKind.LSL, 2),
                ),
                InstructionOperand(
                    OperandKind.IMMEDIATE,
                    OperandAccess.READ,
                    immediate=1,
                ),
            ),
            registers_written=(Register.R0,),
        ),
    )
    load = DecodedInstruction(
        address=BASE + 4,
        size=4,
        data=b"\x08\x10\xb2\xe7",
        mnemonic="ldrne",
        operands="r1, [r2, pc]",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
        conditional=True,
        semantics=InstructionSemantics(
            operands=(
                InstructionOperand(
                    OperandKind.REGISTER,
                    OperandAccess.WRITE,
                    register=Register.R1,
                ),
                InstructionOperand(
                    OperandKind.MEMORY,
                    OperandAccess.READ,
                    memory=MemoryOperand(
                        base=Register.R2,
                        index=Register.PC,
                        scale=1,
                        displacement=8,
                        subtract_index=True,
                    ),
                    access_width=4,
                ),
            ),
            registers_read=(Register.R2, Register.PC),
            registers_written=(Register.R1,),
            condition=ConditionCode.NE,
            writeback=True,
        ),
    )
    branch = DecodedInstruction(
        address=BASE + 8,
        size=4,
        data=b"\x02\x00\x00\xea",
        mnemonic="b",
        operands="0x02000018",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.BRANCH,
        direct_target=BASE + 0x18,
        target_instruction_set=InstructionSet.ARM,
        semantics=InstructionSemantics(
            operands=(
                InstructionOperand(
                    OperandKind.IMMEDIATE,
                    OperandAccess.READ,
                    immediate=BASE + 0x18,
                ),
            )
        ),
    )
    push = DecodedInstruction(
        address=BASE + 0x10,
        size=4,
        data=b"\x10\x40\x2d\xe9",
        mnemonic="push",
        operands="{r4, lr}",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
        semantics=InstructionSemantics(
            operands=(
                InstructionOperand(
                    OperandKind.REGISTER_LIST,
                    OperandAccess.READ,
                    registers=(Register.R4, Register.LR),
                ),
            ),
            registers_read=(Register.R4, Register.LR, Register.SP),
            registers_written=(Register.SP,),
            writeback=True,
        ),
    )
    ret = DecodedInstruction(
        address=BASE + 0x14,
        size=4,
        data=b"\x1e\xff\x2f\xe1",
        mnemonic="bx",
        operands="lr",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.RETURN,
        semantics=InstructionSemantics(
            operands=(
                InstructionOperand(
                    OperandKind.REGISTER,
                    OperandAccess.READ,
                    register=Register.LR,
                ),
            ),
            registers_read=(Register.LR,),
        ),
    )
    return FunctionControlFlowGraph(
        function=_function(),
        blocks=(
            BasicBlock(
                component="arm9",
                address=BASE,
                offset=0,
                instruction_set=InstructionSet.ARM,
                instructions=(move, load, branch),
            ),
            BasicBlock(
                component="arm9",
                address=BASE + 0x10,
                offset=0x10,
                instruction_set=InstructionSet.ARM,
                instructions=(push, ret),
            ),
        ),
        edges=(
            CFGEdge(
                source_address=BASE,
                source_instruction_address=BASE + 8,
                target_address=BASE + 0x10,
                target_instruction_set=InstructionSet.ARM,
                kind=CFGEdgeKind.FALLTHROUGH,
            ),
            CFGEdge(
                source_address=BASE,
                source_instruction_address=BASE + 8,
                target_address=BASE + 0x18,
                target_instruction_set=InstructionSet.ARM,
                kind=CFGEdgeKind.BRANCH,
            ),
            CFGEdge(
                source_address=BASE + 0x10,
                source_instruction_address=BASE + 0x10,
                target_address=BASE + 0x80,
                target_instruction_set=InstructionSet.THUMB,
                kind=CFGEdgeKind.CALL,
            ),
        ),
        unresolved_transfers=(
            UnresolvedTransfer(
                source_address=BASE + 0x14,
                instruction_set=InstructionSet.ARM,
                control_flow=ControlFlowKind.RETURN,
                mnemonic="bx",
                operands="lr",
            ),
        ),
        decode_failures=(BASE + 0x0C,),
    )


def test_cfg_and_typed_semantics_round_trip_exactly(tmp_path: Path) -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    cfg = _cfg()
    root = tmp_path / "game.ndsre"

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(component, functions=(cfg.function,), cfgs=(cfg,))
        )

    with AnalysisProject.open(root, read_only=True) as project:
        assert project.cfg("arm9", BASE, InstructionSet.ARM) == cfg


def test_semantic_storage_contains_no_capstone_objects(tmp_path: Path) -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    cfg = _cfg()
    root = tmp_path / "game.ndsre"

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(component, functions=(cfg.function,), cfgs=(cfg,))
        )

    with sqlite3.connect(root / "analysis.sqlite") as connection:
        payload = "\n".join(
            row[0] for row in connection.execute("SELECT semantics_json FROM instructions")
        ).lower()

    assert "capstone" not in payload
    assert "csarm" not in payload
