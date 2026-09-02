from __future__ import annotations

import json
import struct
from pathlib import Path

from nds_disassembly_toolkit.cli import main


def _module_params_bytes() -> bytes:
    values = (
        0x020C0100,
        0x020C0118,
        0x020BAF00,
        0x020BAF00,
        0x02219440,
        0x0206D6C0,
        0x04027539,
        0xDEC00621,
    )
    return (
        b"\x00" * 0x20
        + struct.pack("<8I", *values)
        + struct.pack("<I", 0x2106C0DE)
        + b"\x00" * 0x20
    )


def test_cli_disasm_module_params_outputs_json(tmp_path: Path, capsys) -> None:
    binary = tmp_path / "arm9.bin"
    binary.write_bytes(_module_params_bytes())

    result = main(
        [
            "disasm",
            "module-params",
            str(binary),
            "--base-address",
            "0x02000000",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["offset"] == 0x20
    assert payload["address"] == 0x02000020
    assert payload["static_bss_end"] == 0x02219440


def test_cli_analyze_scans_generic_component(tmp_path: Path, capsys) -> None:
    binary = tmp_path / "component.bin"
    binary.write_bytes(b"\x00engine_state\x00other_label\x00")

    result = main(
        [
            "analyze",
            "--component",
            "test_component",
            str(binary),
            "0x02000000",
            "--keyword",
            "engine",
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["components"][0]["name"] == "test_component"
    assert [row["text"] for row in payload["string_records"]] == ["engine_state"]


def test_cli_disasm_requires_subcommand(capsys) -> None:
    result = main(["disasm"])

    assert result == 4
    assert "subcommand is required" in capsys.readouterr().err
