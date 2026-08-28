from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.model import Component, SymbolTable
from nds_disassembly_toolkit.analysis.project import (
    AnalysisFreshness,
    ComponentAnalysisBundle,
    ComponentAnalysisIdentity,
    LocationAnnotation,
)


def test_component_identity_hashes_bytes() -> None:
    component = Component("overlay_3", Path("overlay_3.bin"), 0x02200000, b"abc")

    identity = ComponentAnalysisIdentity.from_component(component)

    assert identity.name == "overlay_3"
    assert identity.base_address == 0x02200000
    assert identity.size == 3
    assert identity.sha256 == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_annotation_normalizes_tags() -> None:
    annotation = LocationAnnotation(
        component="arm9",
        address=0x02000000,
        tags=("combat", "ai", "combat"),
    )

    assert annotation.tags == ("ai", "combat")
    with pytest.raises(ValueError, match="name override"):
        LocationAnnotation("arm9", 0x02000000, name_override="")


def test_bundle_defaults_are_empty() -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, b"\0\0\0\0")

    bundle = ComponentAnalysisBundle(component)

    assert bundle.functions == ()
    assert bundle.symbols == SymbolTable(())
    assert AnalysisFreshness.CURRENT.value == "current"
