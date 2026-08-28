from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.project_cli as project_cli
from nds_disassembly_toolkit.analysis.model import (
    Component,
    FunctionCandidate,
    InstructionSet,
    OperandAccess,
    StringRecord,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
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
