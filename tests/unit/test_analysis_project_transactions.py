from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.project.project as project_module
from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    Component,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
    StringRecord,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    ComponentAnalysisBundle,
    LocationAnnotation,
)
from nds_disassembly_toolkit.errors import AnalysisProjectError

BASE = 0x02000000


def _function() -> FunctionCandidate:
    return FunctionCandidate(
        component="arm9",
        address=BASE,
        offset=0,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )


def _cfg(function: FunctionCandidate | None = None) -> FunctionControlFlowGraph:
    candidate = _function() if function is None else function
    return FunctionControlFlowGraph(
        function=candidate,
        blocks=(
            BasicBlock(
                component="arm9",
                address=BASE,
                offset=0,
                instruction_set=InstructionSet.ARM,
                instructions=(),
            ),
        ),
        edges=(),
        unresolved_transfers=(),
        decode_failures=(),
    )


def _bundle(data: bytes, text: str | None) -> ComponentAnalysisBundle:
    component = Component("arm9", Path("arm9.bin"), BASE, data)
    function = _function()
    strings = ()
    if text is not None:
        strings = (
            StringRecord(
                component="arm9",
                offset=0x20,
                address=BASE + 0x20,
                text=text,
            ),
        )
    return ComponentAnalysisBundle(
        component,
        functions=(function,),
        cfgs=(_cfg(function),),
        strings=strings,
    )


def _component_row(root: Path) -> tuple[object, ...]:
    with sqlite3.connect(root / "analysis.sqlite") as connection:
        row = connection.execute(
            """
            SELECT base_address, size, sha256, toolkit_version, analyzed_at
            FROM components
            WHERE name = 'arm9'
            """
        ).fetchone()
    assert row is not None
    return tuple(row)


def test_failed_replacement_rolls_back_everything_and_keeps_annotation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "game.ndsre"
    bundle_a = _bundle(b"A" * 0x40, "old")
    bundle_b = _bundle(b"B" * 0x40, "new")
    annotation = LocationAnnotation("arm9", BASE + 4, comment="keep me")

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(bundle_a)
        project.set_annotation(annotation)
        identity_a = project.component_identities()
        cfg_a = project.cfg("arm9", BASE, InstructionSet.ARM)
        strings_a = project.strings(component="arm9")
    metadata_a = _component_row(root)

    def fail_insert_cfgs(*args: object, **kwargs: object) -> None:
        raise AnalysisProjectError("injected failure")

    monkeypatch.setattr(project_module, "_insert_cfgs", fail_insert_cfgs, raising=False)
    with AnalysisProject.open(root) as project, pytest.raises(
        AnalysisProjectError,
        match="injected failure",
    ):
        project.store_component_analysis(bundle_b)

    with AnalysisProject.open(root, read_only=True) as project:
        assert project.component_identities() == identity_a
        assert project.cfg("arm9", BASE, InstructionSet.ARM) == cfg_a
        assert project.strings(component="arm9") == strings_a
        assert project.annotation("arm9", BASE + 4) == annotation
    assert _component_row(root) == metadata_a


def test_successful_replacement_removes_obsolete_rows_and_keeps_annotation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "game.ndsre"
    bundle_a = _bundle(b"A" * 0x40, "obsolete")
    bundle_b = _bundle(b"B" * 0x40, None)
    annotation = LocationAnnotation("arm9", BASE + 4, tags=("review",))

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(bundle_a)
        project.set_annotation(annotation)
        project.store_component_analysis(bundle_b)
        assert project.strings(component="arm9") == ()
        assert project.annotation("arm9", BASE + 4) == annotation
        assert project.component_status(bundle_b.component).value == "current"

    row = _component_row(root)
    assert row[2] == bundle_b.component.data.hex() or isinstance(row[2], str)
    assert row[3] is not None
    assert row[4] is not None


def test_invalid_bundle_is_rejected_before_existing_analysis_is_deleted(
    tmp_path: Path,
) -> None:
    root = tmp_path / "game.ndsre"
    bundle_a = _bundle(b"A" * 0x40, "old")
    wrong_function = FunctionCandidate(
        component="arm9",
        address=BASE + 4,
        offset=4,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("bad",),
    )
    invalid = ComponentAnalysisBundle(
        Component("arm9", Path("arm9.bin"), BASE, b"B" * 0x40),
        functions=(_function(),),
        cfgs=(_cfg(wrong_function),),
    )

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(bundle_a)
        before = project.strings(component="arm9")
        with pytest.raises(AnalysisProjectError, match="bundle functions"):
            project.store_component_analysis(invalid)
        assert project.strings(component="arm9") == before
        assert project.component_status(bundle_a.component).value == "current"
