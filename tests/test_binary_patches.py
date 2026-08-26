from __future__ import annotations

import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.patches.apply import apply_patch_set
from nds_disassembly_toolkit.patches.model import load_patch_set
from nds_disassembly_toolkit.workspace.manifest import (
    ExtractedFile,
    ExtractedOverlay,
    sha256_bytes,
    WorkspaceManifest,
)
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout


TEST_PROFILE = "test_rev0"


def make_workspace(tmp_path: Path, *, profile_id: str | None = TEST_PROFILE) -> Path:
    root = tmp_path / "workspace"
    layout = WorkspaceLayout.from_root(root)
    for directory in layout.all_directories():
        directory.mkdir(parents=True, exist_ok=True)
    (layout.modified / "arm9.bin").write_bytes(bytes.fromhex("001122334455"))
    (layout.modified / "arm7.bin").write_bytes(bytes.fromhex("AABBCCDD"))
    (layout.modified_overlays / "overlay_007.bin").write_bytes(bytes.fromhex("1020304050"))
    (layout.modified_nitrofs / "Game/a.bin").parent.mkdir(parents=True, exist_ok=True)
    (layout.modified_nitrofs / "Game/a.bin").write_bytes(bytes.fromhex("DEADBEEF"))
    manifest = WorkspaceManifest(
        format_version=1,
        profile_id=profile_id,
        rom_sha256="a" * 64,
        rom_size=1,
        arm9_sha256=sha256_bytes(bytes.fromhex("001122334455")),
        arm7_sha256=sha256_bytes(bytes.fromhex("AABBCCDD")),
        files=(
            ExtractedFile(9, "Game/a.bin", 4, 4, "none", "b" * 64, "c" * 64),
        ),
        overlays=(
            ExtractedOverlay(7, 7, 0x02219440, 5, 0, 5, 5, "d" * 64, "e" * 64, "blz"),
        ),
    )
    (layout.manifests / "workspace.json").write_text(manifest.to_json(), encoding="utf-8")
    return root


def write_patch(
    tmp_path: Path,
    patches: list[dict[str, object]],
    *,
    profile_id: str | None = TEST_PROFILE,
) -> Path:
    path = tmp_path / "patch.json"
    path.write_text(
        json.dumps(
            {
                "format_version": 1,
                "profile_id": profile_id,
                "patches": patches,
            }
        ),
        encoding="utf-8",
    )
    return path


def binary_patch(
    patch_id: str,
    target: str,
    offset: int,
    expected: str,
    replacement: str,
) -> dict[str, object]:
    return {
        "id": patch_id,
        "type": "binary_replace",
        "target": target,
        "offset": offset,
        "expected": expected,
        "replacement": replacement,
        "rationale": "test",
    }


def test_load_patch_set_parses_binary_replacement(tmp_path: Path) -> None:
    path = write_patch(tmp_path, [binary_patch("p1", "overlay:7", 1, "2030", "A0B0")])

    patch_set = load_patch_set(path)

    assert patch_set.profile_id == TEST_PROFILE
    assert patch_set.patches[0].expected == bytes.fromhex("2030")
    assert patch_set.patches[0].replacement == bytes.fromhex("A0B0")


@pytest.mark.parametrize("target", ["unknown", "overlay:x", "overlay:-1", "nitrofs:../evil"])
def test_apply_rejects_invalid_target(tmp_path: Path, target: str) -> None:
    workspace = make_workspace(tmp_path)
    path = write_patch(tmp_path, [binary_patch("p1", target, 0, "00", "11")])

    with pytest.raises(WorkspaceError):
        apply_patch_set(workspace, path)


def test_load_rejects_duplicate_patch_ids(tmp_path: Path) -> None:
    path = write_patch(
        tmp_path,
        [
            binary_patch("same", "arm9", 0, "00", "11"),
            binary_patch("same", "arm7", 0, "AA", "BB"),
        ],
    )

    with pytest.raises(WorkspaceError, match="duplicate"):
        load_patch_set(path)


def test_load_rejects_unequal_lengths(tmp_path: Path) -> None:
    path = write_patch(tmp_path, [binary_patch("p1", "arm9", 0, "00", "1122")])

    with pytest.raises(WorkspaceError, match="same length"):
        load_patch_set(path)


def test_apply_guarded_patches_to_all_target_types(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    path = write_patch(
        tmp_path,
        [
            binary_patch("arm9", "arm9", 1, "1122", "9988"),
            binary_patch("arm7", "arm7", 0, "AABB", "0102"),
            binary_patch("ov7", "overlay:7", 2, "3040", "ABCD"),
            binary_patch("file", "nitrofs:Game/a.bin", 1, "ADBE", "1234"),
        ],
    )

    report = apply_patch_set(workspace, path)

    assert (workspace / "modified/arm9.bin").read_bytes() == bytes.fromhex("009988334455")
    assert (workspace / "modified/arm7.bin").read_bytes() == bytes.fromhex("0102CCDD")
    assert (workspace / "modified/overlays/overlay_007.bin").read_bytes() == bytes.fromhex(
        "1020ABCD50"
    )
    assert (workspace / "modified/nitrofs/Game/a.bin").read_bytes() == bytes.fromhex("DE1234EF")
    assert [item.patch_id for item in report.applied] == ["arm9", "arm7", "ov7", "file"]
    assert (workspace / "manifests/patch-patch.json").is_file()


def test_apply_rejects_stale_expected_bytes_without_writing_anything(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    original = (workspace / "modified/arm9.bin").read_bytes()
    path = write_patch(
        tmp_path,
        [
            binary_patch("first", "arm9", 0, "0011", "AABB"),
            binary_patch("stale", "arm9", 2, "FFFF", "CCDD"),
        ],
    )

    with pytest.raises(WorkspaceError, match="expected bytes"):
        apply_patch_set(workspace, path)

    assert (workspace / "modified/arm9.bin").read_bytes() == original


def test_apply_rejects_out_of_bounds_write(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    path = write_patch(tmp_path, [binary_patch("p1", "arm7", 4, "AA", "BB")])

    with pytest.raises(WorkspaceError, match="outside"):
        apply_patch_set(workspace, path)


def test_apply_rejects_profile_mismatch(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path)
    path = write_patch(
        tmp_path,
        [binary_patch("p1", "arm9", 0, "00", "11")],
        profile_id="other",
    )

    with pytest.raises(WorkspaceError, match="profile"):
        apply_patch_set(workspace, path)


def test_profile_free_patch_set_applies_to_profile_free_workspace(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path, profile_id=None)
    path = write_patch(
        tmp_path,
        [binary_patch("p1", "arm9", 0, "00", "11")],
        profile_id=None,
    )

    report = apply_patch_set(workspace, path)

    assert report.profile_id is None
    assert (workspace / "modified/arm9.bin").read_bytes().startswith(bytes.fromhex("11"))
