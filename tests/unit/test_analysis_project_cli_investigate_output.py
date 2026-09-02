from __future__ import annotations

import json
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.investigation_cli as investigation_cli
from nds_disassembly_toolkit.analysis.investigation import (
    InvestigationCandidate,
    InvestigationEvidence,
    InvestigationEvidenceKind,
    InvestigationReport,
    InvestigationRequest,
)
from nds_disassembly_toolkit.analysis.model import FunctionCandidate, InstructionSet
from nds_disassembly_toolkit.cli import main

BASE = 0x02000000


def _install_fake_service(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Path, bool]]:
    open_calls: list[tuple[Path, bool]] = []
    project = object()

    class Context:
        def __enter__(self) -> object:
            return project

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            return None

    class FakeProject:
        @classmethod
        def open(cls, path: Path, *, read_only: bool = False) -> Context:
            open_calls.append((path, read_only))
            return Context()

    function = FunctionCandidate(
        "arm9",
        BASE,
        0,
        InstructionSet.ARM,
        "high",
        ("entry",),
    )
    evidence = InvestigationEvidence(
        InvestigationEvidenceKind.CONSTANT,
        1.0,
        0.20,
        0.20,
        ("typed immediate constant 500 at 0x02000000",),
        (BASE,),
    )

    def fake_investigate(
        received_project: object,
        request: InvestigationRequest,
    ) -> InvestigationReport:
        assert received_project is project
        return InvestigationReport(
            request,
            (
                InvestigationCandidate(
                    function,
                    "ScoreFunction",
                    0.20,
                    (evidence,),
                    pseudo_c="int ScoreFunction(void) { return 500; }\n",
                ),
            ),
        )

    monkeypatch.setattr(investigation_cli, "AnalysisProject", FakeProject)
    monkeypatch.setattr(investigation_cli, "investigate_project", fake_investigate)
    return open_calls


def test_investigate_json_is_read_only_and_stable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    open_calls = _install_fake_service(monkeypatch)

    assert (
        main(
            [
                "project",
                "investigate",
                "game.ndsre",
                "--constant",
                "500",
                "--decompile",
                "--json",
            ]
        )
        == 0
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["request"]["constants"] == [500]
    assert payload["candidates"][0]["address"] == "0x02000000"
    assert payload["candidates"][0]["score"] == 0.20
    assert payload["candidates"][0]["evidence"][0]["kind"] == "constant"
    assert payload["candidates"][0]["pseudo_c"].startswith("int ScoreFunction")
    assert open_calls == [(Path("game.ndsre"), True)]


def test_investigate_json_output_is_atomic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_fake_service(monkeypatch)
    output = tmp_path / "report.json"
    output.write_text("stale", encoding="utf-8")

    assert (
        main(
            [
                "project",
                "investigate",
                "game.ndsre",
                "--constant",
                "500",
                "--json",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    assert capsys.readouterr().out == ""
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["candidates"][0]["name"] == "ScoreFunction"
    assert not output.with_suffix(output.suffix + ".tmp").exists()
