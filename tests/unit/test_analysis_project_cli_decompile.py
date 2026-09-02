from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import nds_disassembly_toolkit.analysis.project_cli as project_cli
from nds_disassembly_toolkit.analysis.model import InstructionSet
from nds_disassembly_toolkit.cli import build_parser, main

BASE = 0x02000000


def _fake_result() -> SimpleNamespace:
    return SimpleNamespace(
        ir=SimpleNamespace(
            component="arm9",
            address=BASE,
            instruction_set=InstructionSet.ARM,
            name="UserEntry",
            warnings=("visible warning",),
        ),
        structured=SimpleNamespace(fallback_used=False),
        pseudo_c="void UserEntry(void) {\n}\n",
    )


def _install_fake_service(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Path, bool]]:
    open_calls: list[tuple[Path, bool]] = []
    project = object()

    class ProjectContext:
        def __enter__(self) -> object:
            return project

        def __exit__(
            self,
            exc_type: object,
            exc: object,
            traceback: object,
        ) -> None:
            return None

    class FakeAnalysisProject:
        @classmethod
        def open(cls, path: Path, *, read_only: bool = False) -> ProjectContext:
            open_calls.append((path, read_only))
            return ProjectContext()

    def fake_decompile(
        received_project: object,
        component: str,
        address: int,
        mode: InstructionSet,
    ) -> SimpleNamespace:
        assert received_project is project
        assert component == "arm9"
        assert address == BASE
        assert mode is InstructionSet.ARM
        return _fake_result()

    monkeypatch.setattr(project_cli, "AnalysisProject", FakeAnalysisProject)
    monkeypatch.setattr(project_cli, "decompile_function", fake_decompile, raising=False)
    return open_calls


def test_project_decompile_parser_defaults_to_text() -> None:
    arguments = build_parser().parse_args(
        [
            "project",
            "decompile",
            "game.ndsre",
            "arm9",
            hex(BASE),
            "--mode",
            "arm",
        ]
    )

    assert arguments.project_command == "decompile"
    assert arguments.project == Path("game.ndsre")
    assert arguments.component == "arm9"
    assert arguments.address == BASE
    assert arguments.mode is InstructionSet.ARM
    assert arguments.format == "text"
    assert arguments.output is None


@pytest.mark.parametrize(
    "argv",
    (
        ["project", "decompile", "game.ndsre", "arm9", hex(BASE)],
        [
            "project",
            "decompile",
            "game.ndsre",
            "arm9",
            hex(BASE),
            "--mode",
            "invalid",
        ],
        [
            "project",
            "decompile",
            "game.ndsre",
            "arm9",
            hex(BASE),
            "--mode",
            "arm",
            "--format",
            "yaml",
        ],
    ),
)
def test_project_decompile_parser_rejects_invalid_contract(argv: list[str]) -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)


def test_project_decompile_text_is_read_only_and_deterministic(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    open_calls = _install_fake_service(monkeypatch)

    assert (
        main(
            [
                "project",
                "decompile",
                "game.ndsre",
                "arm9",
                hex(BASE),
                "--mode",
                "arm",
            ]
        )
        == 0
    )

    assert capsys.readouterr().out == "void UserEntry(void) {\n}\n"
    assert open_calls == [(Path("game.ndsre"), True)]


def test_project_decompile_json_shape_is_small_and_stable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    open_calls = _install_fake_service(monkeypatch)

    assert (
        main(
            [
                "project",
                "decompile",
                "game.ndsre",
                "arm9",
                hex(BASE),
                "--mode",
                "arm",
                "--format",
                "json",
            ]
        )
        == 0
    )

    assert json.loads(capsys.readouterr().out) == {
        "address": "0x02000000",
        "component": "arm9",
        "fallback_used": False,
        "instruction_set": "arm",
        "name": "UserEntry",
        "pseudo_c": "void UserEntry(void) {\n}\n",
        "warnings": ["visible warning"],
    }
    assert open_calls == [(Path("game.ndsre"), True)]


@pytest.mark.parametrize("format_name", ("text", "json"))
def test_project_decompile_output_is_atomic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    format_name: str,
) -> None:
    _install_fake_service(monkeypatch)
    output = tmp_path / ("function.c" if format_name == "text" else "function.json")
    output.write_text("stale", encoding="utf-8")

    assert (
        main(
            [
                "project",
                "decompile",
                "game.ndsre",
                "arm9",
                hex(BASE),
                "--mode",
                "arm",
                "--format",
                format_name,
                "--output",
                str(output),
            ]
        )
        == 0
    )

    assert output.read_text(encoding="utf-8") != "stale"
    assert not output.with_suffix(output.suffix + ".tmp").exists()
    if format_name == "text":
        assert output.read_text(encoding="utf-8") == "void UserEntry(void) {\n}\n"
    else:
        assert json.loads(output.read_text(encoding="utf-8"))["name"] == "UserEntry"
