from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.project_cli as project_cli
from nds_disassembly_toolkit.cli import main


def _block_project_open(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    opened: list[Path] = []

    class FakeAnalysisProject:
        @classmethod
        def open(cls, path: Path, *, read_only: bool = False):
            opened.append(path)
            raise AssertionError("project should not be opened")

    monkeypatch.setattr(project_cli, "AnalysisProject", FakeAnalysisProject)
    return opened


def test_investigate_rejects_empty_request_before_project_open(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    opened = _block_project_open(monkeypatch)

    assert main(["project", "investigate", "game.ndsre"]) == 2
    assert opened == []
    assert "at least one investigation selector" in capsys.readouterr().err


def test_investigate_rejects_one_sided_trace_before_project_open(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    opened = _block_project_open(monkeypatch)

    assert (
        main(
            [
                "project",
                "investigate",
                "game.ndsre",
                "--baseline",
                "idle.ndstrace",
            ]
        )
        == 2
    )
    assert opened == []
    assert "baseline and target traces" in capsys.readouterr().err
