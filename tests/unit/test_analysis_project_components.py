from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.model import Component
from nds_disassembly_toolkit.analysis.project import (
    AnalysisFreshness,
    AnalysisProject,
    AnalysisProjectError,
    ComponentAnalysisBundle,
    LocationAnnotation,
)


def _component(
    name: str,
    *,
    base: int = 0x02000000,
    data: bytes = b"abcd",
) -> Component:
    return Component(name, Path(f"{name}.bin"), base, data)


def test_component_freshness_uses_name_base_size_and_hash(tmp_path: Path) -> None:
    original = _component("arm9")
    changed_bytes = _component("arm9", data=b"abce")
    changed_base = _component("arm9", base=0x02001000)
    changed_size = _component("arm9", data=b"abcde")
    missing = _component("arm7", base=0x03800000)

    with AnalysisProject.create(tmp_path / "game.ndsre") as project:
        project.store_component_analysis(ComponentAnalysisBundle(original))

        assert project.component_status(original) is AnalysisFreshness.CURRENT
        assert project.component_status(changed_bytes) is AnalysisFreshness.STALE
        assert project.component_status(changed_base) is AnalysisFreshness.STALE
        assert project.component_status(changed_size) is AnalysisFreshness.STALE
        assert project.component_status(missing) is AnalysisFreshness.MISSING


def test_overlapping_overlay_addresses_keep_independent_components(tmp_path: Path) -> None:
    overlay_3 = _component("overlay_3", base=0x02200000, data=b"one")
    overlay_7 = _component("overlay_7", base=0x02200000, data=b"two")

    with AnalysisProject.create(tmp_path / "game.ndsre") as project:
        project.store_component_analysis(ComponentAnalysisBundle(overlay_7))
        project.store_component_analysis(ComponentAnalysisBundle(overlay_3))

        identities = project.component_identities()

    assert tuple(identity.name for identity in identities) == ("overlay_3", "overlay_7")
    assert tuple(identity.base_address for identity in identities) == (
        0x02200000,
        0x02200000,
    )


def test_annotations_persist_and_are_deterministically_ordered(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    arm9 = _component("arm9")
    overlay = _component("overlay_1", base=0x02200000)

    with AnalysisProject.create(root) as project:
        project.store_component_analysis(ComponentAnalysisBundle(overlay))
        project.store_component_analysis(ComponentAnalysisBundle(arm9))
        project.set_annotation(
            LocationAnnotation(
                component="overlay_1",
                address=0x02200008,
                comment="overlay note",
                tags=("code",),
                bookmarked=True,
            )
        )
        project.set_annotation(
            LocationAnnotation(
                component="arm9",
                address=0x02000010,
                name_override="MainLoop",
                tags=("loop", "important"),
            )
        )
        project.set_annotation(
            LocationAnnotation(component="arm9", address=0x02000004, comment="first")
        )

    with AnalysisProject.open(root, read_only=True) as project:
        assert project.annotation("arm9", 0x02000010) == LocationAnnotation(
            component="arm9",
            address=0x02000010,
            name_override="MainLoop",
            tags=("important", "loop"),
        )
        assert tuple(
            (annotation.component, annotation.address)
            for annotation in project.annotations()
        ) == (
            ("arm9", 0x02000004),
            ("arm9", 0x02000010),
            ("overlay_1", 0x02200008),
        )
        assert tuple(
            annotation.address for annotation in project.annotations(component="arm9")
        ) == (0x02000004, 0x02000010)


def test_annotation_requires_registered_component(tmp_path: Path) -> None:
    with (
        AnalysisProject.create(tmp_path / "game.ndsre") as project,
        pytest.raises(AnalysisProjectError, match="component"),
    ):
        project.set_annotation(LocationAnnotation("arm9", 0x02000000))


def test_read_only_project_rejects_annotation_write(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    component = _component("arm9")
    with AnalysisProject.create(root) as project:
        project.store_component_analysis(ComponentAnalysisBundle(component))

    with (
        AnalysisProject.open(root, read_only=True) as project,
        pytest.raises(AnalysisProjectError, match="read-only"),
    ):
        project.set_annotation(LocationAnnotation("arm9", 0x02000000))
