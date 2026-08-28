from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.project_cli as project_cli
from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    ArgumentEvidence,
    ArgumentLocationKind,
    BasicBlock,
    BlockFlowState,
    Component,
    ConditionCode,
    ControlFlowKind,
    CrossReference,
    CrossReferenceKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    FunctionSummary,
    InstructionFlowState,
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    MemoryOperand,
    OperandAccess,
    OperandKind,
    OperandShift,
    Register,
    RegisterState,
    ReturnEvidence,
    ShiftKind,
    StackAccess,
    StackAccessKind,
    StackFrame,
    StackSlot,
    StackSlotKind,
    StackState,
    StringRecord,
    Symbol,
    SymbolKind,
    SymbolTable,
    UnresolvedTransfer,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)
from nds_disassembly_toolkit.analysis.project_cli import (
    _auto_int,
    _hex,
    _instruction_set,
    _operand_access_json,
    _signed_hex,
    _write_json,
)
from nds_disassembly_toolkit.cli import main

BASE = 0x02000000
OVERLAY_BASE = 0x02200000


def _component() -> Component:
    return Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))


def _seed_project(root: Path) -> None:
    arm = FunctionCandidate(
        component="arm9",
        address=BASE + 0x20,
        offset=0x20,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("seed",),
    )
    thumb = FunctionCandidate(
        component="arm9",
        address=BASE + 0x24,
        offset=0x24,
        instruction_set=InstructionSet.THUMB,
        confidence="medium",
        evidence=("call",),
    )
    strings = (
        StringRecord("arm9", 0x50, BASE + 0x50, "battle manager"),
        StringRecord("arm9", 0x60, BASE + 0x60, "Menu"),
    )
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                _component(),
                functions=(thumb, arm),
                strings=strings,
            )
        )


def _deep_project(root: Path) -> None:
    arm = FunctionCandidate(
        "arm9",
        BASE,
        0,
        InstructionSet.ARM,
        "high",
        ("seed",),
    )
    thumb = FunctionCandidate(
        "arm9",
        BASE,
        0,
        InstructionSet.THUMB,
        "medium",
        ("alternate-mode",),
    )
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
                        displacement=-4,
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
    ret = DecodedInstruction(
        address=BASE + 8,
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
    block = BasicBlock(
        "arm9",
        BASE,
        0,
        InstructionSet.ARM,
        (move, load, ret),
    )
    cfg = FunctionControlFlowGraph(
        arm,
        (block,),
        (),
        (
            UnresolvedTransfer(
                BASE + 8,
                InstructionSet.ARM,
                ControlFlowKind.RETURN,
                "bx",
                "lr",
            ),
        ),
        (BASE + 0x0C,),
    )

    constant = AbstractValue(AbstractValueKind.CONSTANT, 7, provenance=(BASE,))
    owned = AbstractValue(
        AbstractValueKind.ADDRESS,
        OVERLAY_BASE,
        "overlay_3",
        (BASE + 4,),
    )
    before = RegisterState()
    after_move = RegisterState(((Register.R0, constant),))
    after_load = RegisterState(
        ((Register.R0, constant), (Register.R1, owned))
    )
    entry_stack = StackState(0, ((Register.R11, -0x10),))
    inner_stack = StackState(-0x10, ((Register.R11, -0x10),))
    flow = FunctionDataFlow(
        arm,
        (
            BlockFlowState(
                BASE,
                InstructionSet.ARM,
                before,
                after_load,
                entry_stack,
                inner_stack,
            ),
        ),
        (
            InstructionFlowState(move, before, after_move, entry_stack, entry_stack),
            InstructionFlowState(
                load,
                after_move,
                after_load,
                entry_stack,
                inner_stack,
            ),
            InstructionFlowState(
                ret,
                after_load,
                after_load,
                inner_stack,
                inner_stack,
            ),
        ),
        ("stack depth remains proven",),
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
                    (BASE + 4,),
                ),
            ),
            (ReturnEvidence(BASE + 8, constant),),
            StackFrame(0x10, Register.R11, True),
            (
                StackSlot(
                    -4,
                    StackSlotKind.LOCAL,
                    (StackAccess(BASE + 4, StackAccessKind.LOAD, 4),),
                ),
            ),
        ),
    )
    symbols = SymbolTable(
        (
            Symbol(
                "arm9",
                BASE,
                0,
                "entry",
                SymbolKind.FUNCTION,
                InstructionSet.ARM,
                "high",
                ("function",),
            ),
        )
    )
    arm9_xrefs = (
        CrossReference(
            CrossReferenceKind.CALL,
            "arm9",
            BASE + 4,
            BASE,
            InstructionSet.ARM,
            OVERLAY_BASE,
            InstructionSet.THUMB,
        ),
        CrossReference(
            CrossReferenceKind.DATA_POINTER,
            "arm9",
            BASE + 8,
            None,
            None,
            OVERLAY_BASE,
            None,
        ),
    )
    shared_3 = Symbol(
        "overlay_3",
        OVERLAY_BASE,
        0,
        "shared",
        SymbolKind.DATA,
        None,
        "high",
        ("overlay3",),
    )
    shared_7 = Symbol(
        "overlay_7",
        OVERLAY_BASE,
        0,
        "shared",
        SymbolKind.DATA,
        None,
        "medium",
        ("overlay7",),
    )
    overlay_xref = CrossReference(
        CrossReferenceKind.DATA_POINTER,
        "overlay_3",
        OVERLAY_BASE + 4,
        None,
        None,
        OVERLAY_BASE,
        None,
    )

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(
            ComponentAnalysisBundle(
                _component(),
                functions=(arm, thumb),
                symbols=symbols,
                xrefs=arm9_xrefs,
                cfgs=(cfg,),
                data_flows=(flow,),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component(
                    "overlay_3",
                    Path("overlay_3.bin"),
                    OVERLAY_BASE,
                    bytes(0x100),
                ),
                symbols=SymbolTable((shared_3,)),
                xrefs=(overlay_xref,),
            )
        )
        project.store_component_analysis(
            ComponentAnalysisBundle(
                Component(
                    "overlay_7",
                    Path("overlay_7.bin"),
                    OVERLAY_BASE,
                    bytes(0x100),
                ),
                symbols=SymbolTable((shared_7,)),
            )
        )
        project.set_annotation(
            LocationAnnotation(
                "arm9",
                BASE,
                name_override="UserEntry",
                comment="confirmed",
                tags=("runtime",),
                bookmarked=True,
            )
        )


def test_project_scalar_parsers_are_re_friendly() -> None:
    assert _auto_int("33554432") == 0x02000000
    assert _auto_int("0x02000000") == 0x02000000
    assert _instruction_set("arm") is InstructionSet.ARM
    assert _instruction_set("THUMB") is InstructionSet.THUMB
    assert _hex(0x02012340) == "0x02012340"
    assert _hex(0) == "0x00000000"
    assert _signed_hex(-12) == "-0x0000000c"
    assert _signed_hex(12) == "0x0000000c"


def test_project_scalar_parsers_reject_invalid_inputs() -> None:
    with pytest.raises(argparse.ArgumentTypeError, match="invalid integer/address"):
        _auto_int("not-an-address")
    with pytest.raises(argparse.ArgumentTypeError, match="non-negative"):
        _auto_int("-1")
    with pytest.raises(argparse.ArgumentTypeError, match=r"arm.*thumb"):
        _instruction_set("mips")
    with pytest.raises(ValueError, match="cannot be negative"):
        _hex(-1)


def test_operand_access_serializes_symbolically() -> None:
    assert _operand_access_json(OperandAccess.NONE) == []
    assert _operand_access_json(OperandAccess.READ) == ["read"]
    assert _operand_access_json(OperandAccess.WRITE) == ["write"]
    assert _operand_access_json(OperandAccess.READ | OperandAccess.WRITE) == [
        "read",
        "write",
    ]


def test_json_writer_is_deterministic_on_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    _write_json({"z": 1, "a": [2, 1]}, None)
    assert capsys.readouterr().out == '{\n  "a": [\n    2,\n    1\n  ],\n  "z": 1\n}\n'


def test_json_writer_atomically_replaces_output(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    output.write_text("old", encoding="utf-8")

    _write_json({"address": "0x02000000"}, output)

    assert json.loads(output.read_text(encoding="utf-8")) == {
        "address": "0x02000000"
    }
    assert not (tmp_path / "report.json.tmp").exists()


def test_project_create_and_info_are_deterministic(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "sample.ndsre"

    assert main(["project", "create", str(root)]) == 0
    created = json.loads(capsys.readouterr().out)
    assert created == {
        "components": [],
        "metadata": {
            "analysis_model_version": 1,
            "project_format_version": 1,
            "read_only": False,
            "schema_version": 1,
        },
        "project": str(root),
    }

    assert main(["project", "info", str(root)]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["project"] == str(root)
    assert info["components"] == []
    assert info["metadata"] == {
        "analysis_model_version": 1,
        "project_format_version": 1,
        "read_only": True,
        "schema_version": 1,
    }


def test_project_functions_filter_and_serialize_deterministically(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(root)

    assert main(["project", "functions", str(root), "--component", "arm9"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [entry["address"] for entry in payload["functions"]] == [
        "0x02000020",
        "0x02000024",
    ]
    assert payload["functions"][0] == {
        "address": "0x02000020",
        "component": "arm9",
        "confidence": "high",
        "evidence": ["seed"],
        "instruction_set": "arm",
        "offset": "0x00000020",
    }


def test_project_strings_contains_is_case_insensitive_and_keeps_order(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(root)

    assert main(["project", "strings", str(root), "--contains", "BATTLE"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["strings"] == [
        {
            "address": "0x02000050",
            "component": "arm9",
            "offset": "0x00000050",
            "text": "battle manager",
        }
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        ["project", "info"],
        ["project", "functions"],
        ["project", "strings"],
    ],
)
def test_project_queries_open_read_only(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(root)
    original_open = AnalysisProject.open
    calls: list[bool] = []

    def recording_open(path: Path, *, read_only: bool = False) -> AnalysisProject:
        calls.append(read_only)
        return original_open(path, read_only=read_only)

    monkeypatch.setattr(project_cli.AnalysisProject, "open", staticmethod(recording_open))

    assert main([*arguments, str(root)]) == 0
    capsys.readouterr()
    assert calls == [True]


def test_project_function_deep_inspection_serializes_public_models(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "deep.ndsre"
    _deep_project(root)

    assert main(["project", "function", str(root), "arm9", hex(BASE), "arm"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["function"]["instruction_set"] == "arm"
    assert payload["annotation"] == {
        "address": "0x02000000",
        "bookmarked": True,
        "comment": "confirmed",
        "component": "arm9",
        "name_override": "UserEntry",
        "tags": ["runtime"],
    }
    first_operand = payload["cfg"]["blocks"][0]["instructions"][0]["semantics"][
        "operands"
    ][0]
    assert first_operand["access"] == ["write"]
    assert first_operand["register"] == "r0"
    assert first_operand["shift"] == {"kind": "lsl", "value": 2}
    memory = payload["cfg"]["blocks"][0]["instructions"][1]["semantics"][
        "operands"
    ][1]["memory"]
    assert memory["displacement"] == "-0x00000004"
    assert memory["base"] == "r2"
    assert memory["index"] == "r15"
    assert payload["data_flow"]["summary"]["stack_frame"]["frame_size"] == (
        "0x00000010"
    )
    assert payload["data_flow"]["summary"]["stack_slots"][0]["offset"] == (
        "-0x00000004"
    )
    assert payload["data_flow"]["summary"]["returns"][0]["value"]["value"] == (
        "0x00000007"
    )
    rendered = json.dumps(payload).lower()
    assert "capstone" not in rendered
    assert "sqlite" not in rendered


def test_project_function_lookup_preserves_arm_thumb_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "deep.ndsre"
    _deep_project(root)

    assert main(["project", "function", str(root), "arm9", hex(BASE), "thumb"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["function"]["instruction_set"] == "thumb"
    assert payload["function"]["confidence"] == "medium"
    assert payload["cfg"] is None
    assert payload["data_flow"] is None


def test_project_missing_exact_function_is_toolkit_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "deep.ndsre"
    _deep_project(root)

    assert main(
        ["project", "function", str(root), "arm9", hex(BASE + 0x40), "arm"]
    ) == 4
    assert "analysis function not found" in capsys.readouterr().err


def test_project_symbols_preserve_overlay_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "deep.ndsre"
    _deep_project(root)

    assert main(["project", "symbols", str(root), "--name", "shared"]) == 0
    by_name = json.loads(capsys.readouterr().out)
    assert [symbol["component"] for symbol in by_name["symbols"]] == [
        "overlay_3",
        "overlay_7",
    ]

    assert main(["project", "symbols", str(root), "--address", hex(OVERLAY_BASE)]) == 2
    assert "--component" in capsys.readouterr().err

    assert main(
        [
            "project",
            "symbols",
            str(root),
            "--address",
            hex(OVERLAY_BASE),
            "--component",
            "overlay_7",
        ]
    ) == 0
    by_address = json.loads(capsys.readouterr().out)
    assert [symbol["component"] for symbol in by_address["symbols"]] == ["overlay_7"]


def test_project_xref_queries_are_component_safe(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "deep.ndsre"
    _deep_project(root)

    assert main(
        ["project", "xrefs-from", str(root), "arm9", hex(BASE + 4)]
    ) == 0
    from_payload = json.loads(capsys.readouterr().out)
    assert from_payload["xrefs"] == [
        {
            "kind": "call",
            "source_address": "0x02000004",
            "source_component": "arm9",
            "source_function_address": "0x02000000",
            "source_instruction_set": "arm",
            "target_address": "0x02200000",
            "target_instruction_set": "thumb",
        }
    ]

    assert main(["project", "xrefs-to", str(root), hex(OVERLAY_BASE)]) == 0
    all_payload = json.loads(capsys.readouterr().out)
    assert len(all_payload["xrefs"]) == 3
    assert all("target_component" not in xref for xref in all_payload["xrefs"])

    assert main(
        [
            "project",
            "xrefs-to",
            str(root),
            hex(OVERLAY_BASE),
            "--source-component",
            "arm9",
        ]
    ) == 0
    filtered = json.loads(capsys.readouterr().out)
    assert len(filtered["xrefs"]) == 2
    assert {xref["source_component"] for xref in filtered["xrefs"]} == {"arm9"}
