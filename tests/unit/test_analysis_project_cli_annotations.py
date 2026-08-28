from __future__ import annotations

import json
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.project_cli as project_cli
from nds_disassembly_toolkit.analysis.model import Component
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)
from nds_disassembly_toolkit.cli import build_parser, main

BASE = 0x02000000


def _seed_project(root: Path, *, annotation: LocationAnnotation | None = None) -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x100))
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(ComponentAnalysisBundle(component))
        if annotation is not None:
            project.set_annotation(annotation)


def _read_annotation(root: Path) -> LocationAnnotation | None:
    with AnalysisProject.open(root, read_only=True) as project:
        return project.annotation("arm9", BASE)


@pytest.mark.parametrize(
    "flags",
    [
        ["--name", "New", "--clear-name"],
        ["--comment", "New", "--clear-comment"],
        ["--tag", "one", "--clear-tags"],
        ["--bookmark", "--unbookmark"],
    ],
)
def test_annotation_parser_enforces_mutually_exclusive_flags(flags: list[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(
            [
                "project",
                "annotate",
                "sample.ndsre",
                "arm9",
                hex(BASE),
                *flags,
            ]
        )
    assert exc_info.value.code == 2


def test_annotation_noop_is_usage_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(root)

    assert main(["project", "annotate", str(root), "arm9", hex(BASE)]) == 2
    assert "at least one annotation field must be changed" in capsys.readouterr().err


def test_annotations_list_is_deterministic_and_read_only(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(
        root,
        annotation=LocationAnnotation(
            "arm9",
            BASE,
            name_override="Entry",
            tags=("beta", "alpha"),
            bookmarked=True,
        ),
    )
    original_open = AnalysisProject.open
    calls: list[bool] = []

    def recording_open(path: Path, *, read_only: bool = False) -> AnalysisProject:
        calls.append(read_only)
        return original_open(path, read_only=read_only)

    monkeypatch.setattr(project_cli.AnalysisProject, "open", staticmethod(recording_open))

    assert main(["project", "annotations", str(root), "--component", "arm9"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert calls == [True]
    assert payload == {
        "annotations": [
            {
                "address": "0x02000000",
                "bookmarked": True,
                "comment": None,
                "component": "arm9",
                "name_override": "Entry",
                "tags": ["alpha", "beta"],
            }
        ],
        "component": "arm9",
    }


def test_annotation_patch_preserves_unspecified_fields(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(
        root,
        annotation=LocationAnnotation(
            "arm9",
            BASE,
            name_override="OldName",
            comment="keep me",
            tags=("alpha", "beta"),
            bookmarked=True,
        ),
    )

    assert main(
        [
            "project",
            "annotate",
            str(root),
            "arm9",
            hex(BASE),
            "--name",
            "NewName",
        ]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["annotation"]["name_override"] == "NewName"

    stored = _read_annotation(root)
    assert stored == LocationAnnotation(
        "arm9",
        BASE,
        name_override="NewName",
        comment="keep me",
        tags=("alpha", "beta"),
        bookmarked=True,
    )


def test_annotation_explicit_clears_are_independent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(
        root,
        annotation=LocationAnnotation(
            "arm9",
            BASE,
            name_override="OldName",
            comment="remove me",
            tags=("alpha", "beta"),
            bookmarked=True,
        ),
    )

    for flag in ("--clear-name", "--clear-comment", "--clear-tags", "--unbookmark"):
        assert main(
            ["project", "annotate", str(root), "arm9", hex(BASE), flag]
        ) == 0
        capsys.readouterr()

    stored = _read_annotation(root)
    assert stored == LocationAnnotation("arm9", BASE)


def test_annotation_repeated_tags_replace_and_normalize_complete_set(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(
        root,
        annotation=LocationAnnotation("arm9", BASE, tags=("old",)),
    )

    assert main(
        [
            "project",
            "annotate",
            str(root),
            "arm9",
            hex(BASE),
            "--tag",
            "beta",
            "--tag",
            "alpha",
            "--tag",
            "beta",
        ]
    ) == 0
    capsys.readouterr()
    stored = _read_annotation(root)
    assert stored is not None
    assert stored.tags == ("alpha", "beta")


def test_new_annotation_uses_defaults_for_omitted_fields(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(root)

    assert main(
        [
            "project",
            "annotate",
            str(root),
            "arm9",
            hex(BASE),
            "--bookmark",
        ]
    ) == 0
    capsys.readouterr()
    assert _read_annotation(root) == LocationAnnotation("arm9", BASE, bookmarked=True)


def test_annotation_unknown_component_uses_project_error_mapping(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = tmp_path / "sample.ndsre"
    _seed_project(root)

    assert main(
        [
            "project",
            "annotate",
            str(root),
            "missing",
            hex(BASE),
            "--bookmark",
        ]
    ) == 4
    assert "not registered" in capsys.readouterr().err
