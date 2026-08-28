from __future__ import annotations

from pathlib import Path

import pytest

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
