from __future__ import annotations

from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.project_cli as project_cli
from nds_disassembly_toolkit.cli import build_parser, main


def test_top_level_parser_registers_project() -> None:
    args = build_parser().parse_args(["project", "info", "sample.ndsre"])
    assert args.command == "project"
    assert args.project_command == "info"
    assert args.project == Path("sample.ndsre")


def test_project_without_subcommand_is_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["project"]) == 2
    captured = capsys.readouterr()
    assert "project" in captured.err.lower()


def test_missing_project_uses_toolkit_error_mapping(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing.ndsre"

    assert main(["project", "info", str(missing)]) == 4
    assert str(missing) in capsys.readouterr().err


def test_project_output_oserror_uses_filesystem_error_mapping(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "sample.ndsre"

    def fail_write(payload: object, output: Path | None) -> None:
        raise OSError("simulated output failure")

    monkeypatch.setattr(project_cli, "_write_json", fail_write)

    assert main(["project", "create", str(root)]) == 5
    assert "simulated output failure" in capsys.readouterr().err


def test_existing_analyze_parser_contract_is_unchanged(tmp_path: Path) -> None:
    binary = tmp_path / "component.bin"
    args = build_parser().parse_args(
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

    assert args.command == "analyze"
    assert args.component == [("test_component", binary, 0x02000000)]
    assert args.keyword == ["engine"]
