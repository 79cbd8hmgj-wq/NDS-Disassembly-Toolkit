from pathlib import Path

import pytest

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout
from nds_disassembly_toolkit.workspace.overrides import (
    BuildOverrides,
    OverlayLayoutOverride,
    RawNitroFsOverride,
    load_build_overrides,
    write_build_overrides,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def test_workspace_layout_exposes_raw_override_directory(tmp_path: Path) -> None:
    layout = WorkspaceLayout.from_root(tmp_path / "work")
    assert layout.modified_raw_nitrofs == tmp_path / "work/modified/raw/nitrofs"
    assert layout.build_overrides == tmp_path / "work/manifests/build-overrides.json"


def test_build_overrides_allow_profile_free_workspace(tmp_path: Path) -> None:
    raw = RawNitroFsOverride(1, "a.bin", 1, DIGEST_A, 2, DIGEST_B)
    overlay = OverlayLayoutOverride(7, 4, 0, 8, 1, 0)
    overrides = BuildOverrides(1, None, (raw,), (overlay,))
    path = tmp_path / "build-overrides.json"

    write_build_overrides(path, overrides)

    assert load_build_overrides(path) == overrides
    assert path.read_text(encoding="utf-8").endswith("\n")


def test_build_overrides_allow_arbitrary_consumer_profile_id(tmp_path: Path) -> None:
    overrides = BuildOverrides(1, "synthetic_rev1", (), ())
    path = tmp_path / "build-overrides.json"

    write_build_overrides(path, overrides)

    assert load_build_overrides(path) == overrides


def test_build_overrides_reject_empty_profile_id() -> None:
    overrides = BuildOverrides(1, "", (), ())

    with pytest.raises(WorkspaceError, match="profile"):
        overrides.validate()
