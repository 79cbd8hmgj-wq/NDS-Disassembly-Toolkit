from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.investigation import (
    InvestigationRequest,
    investigate_project,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject
from nds_disassembly_toolkit.analysis.runtime.melonds import MelonDSSession


def test_offline_investigation_never_connects_melonds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def blocked_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline investigation must not connect to melonDS")

    monkeypatch.setattr(MelonDSSession, "connect", blocked_connect)
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root):
        pass

    with AnalysisProject.open(root, read_only=True) as project:
        report = investigate_project(project, InvestigationRequest(text="unused"))

    assert report.candidates == ()
