from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.model import InstructionSet, OperandAccess
from nds_disassembly_toolkit.analysis.project_cli import (
    _auto_int,
    _hex,
    _instruction_set,
    _operand_access_json,
    _signed_hex,
    _write_json,
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
