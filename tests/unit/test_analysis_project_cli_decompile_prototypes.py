from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest

from nds_disassembly_toolkit.analysis import project_cli
from nds_disassembly_toolkit.analysis.model import InstructionSet

BASE = 0x0200E000


class _ProjectContext:
    def __init__(self, project: object) -> None:
        self.project = project

    def __enter__(self) -> object:
        return self.project

    def __exit__(self, *args: object) -> None:
        del args


def test_project_decompile_automatically_supplies_prototype_analysis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class ProjectStub:
        def functions(self) -> tuple[object, ...]:
            return ()

    project = ProjectStub()
    prototype_analysis = object()
    output = tmp_path / "decompiled.c"
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        project_cli.AnalysisProject,
        "open",
        lambda *args, **kwargs: _ProjectContext(project),
    )
    monkeypatch.setattr(
        project_cli,
        "recover_project_prototypes",
        lambda candidate: (
            prototype_analysis
            if candidate is project
            else (_ for _ in ()).throw(AssertionError("wrong project"))
        ),
    )

    def decompile(
        candidate: object,
        component: str,
        address: int,
        mode: InstructionSet,
        *,
        prototype_analysis: object | None = None,
    ) -> object:
        observed.update(
            project=candidate,
            component=component,
            address=address,
            mode=mode,
            prototype_analysis=prototype_analysis,
        )
        return SimpleNamespace(pseudo_c="void entry(void) {\n}\n")

    monkeypatch.setattr(project_cli, "decompile_function", decompile)

    status = project_cli._run_decompile(
        Namespace(
            project=tmp_path / "project",
            component="arm9",
            address=BASE,
            mode=InstructionSet.ARM,
            format="text",
            output=output,
        )
    )

    assert status == 0
    assert observed == {
        "project": project,
        "component": "arm9",
        "address": BASE,
        "mode": InstructionSet.ARM,
        "prototype_analysis": prototype_analysis,
    }
    assert output.read_text(encoding="utf-8") == (
        "void entry(void) {\n}\n"
    )
