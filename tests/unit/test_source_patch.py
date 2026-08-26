from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit.compression.blz import compress_blz
from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.source_patch import load_source_patch_manifest, resolve_source_target
from nds_disassembly_toolkit.workspace.manifest import (
    ExtractedOverlay,
    WorkspaceManifest,
    sha256_bytes,
    write_json_atomic,
)
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout

OVERLAY_BASE = 0x02200000


def _payload() -> dict[str, object]:
    return {
        "format_version": 1,
        "target": "overlay:3",
        "runtime_address": OVERLAY_BASE + 0x100,
        "max_size": 0x20,
        "mode": "arm",
        "expected_runtime_sha256": hashlib.sha256(b"target").hexdigest(),
        "sources": ["src/injected.c"],
        "definitions": {"helper": 0x02001000},
        "hooks": [],
    }


def _write_patch_manifest(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "source-patch.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_workspace(
    tmp_path: Path,
    *,
    overlay_data: bytes = b"\x00" * 0x400,
    arm9_data: bytes = b"\x00" * 0x800,
    arm9_base: int | None = 0x02000000,
    profile_id: str | None = None,
) -> Path:
    root = tmp_path / "workspace"
    layout = WorkspaceLayout.from_root(root)
    for directory in layout.all_directories():
        directory.mkdir(parents=True, exist_ok=True)
    (layout.original / "arm9.bin").write_bytes(arm9_data)
    (layout.original / "arm7.bin").write_bytes(b"\x00" * 0x200)
    (layout.modified / "arm9.bin").write_bytes(arm9_data)
    (layout.modified / "arm7.bin").write_bytes(b"\x00" * 0x200)
    (layout.modified_overlays / "overlay_003.bin").write_bytes(overlay_data)
    manifest = WorkspaceManifest(
        format_version=1,
        profile_id=profile_id,
        rom_sha256="0" * 64,
        rom_size=1,
        arm9_sha256=sha256_bytes(arm9_data),
        arm7_sha256=sha256_bytes(b"\x00" * 0x200),
        files=(),
        overlays=(
            ExtractedOverlay(
                overlay_id=3,
                file_id=3,
                ram_address=OVERLAY_BASE,
                ram_size=len(overlay_data),
                bss_size=0,
                raw_size=len(overlay_data),
                decoded_size=len(overlay_data),
                raw_sha256=sha256_bytes(overlay_data),
                decoded_sha256=sha256_bytes(overlay_data),
                compression="none",
            ),
        ),
        arm9_ram_address=arm9_base,
        arm7_ram_address=0x02380000,
    )
    write_json_atomic(layout.manifests / "workspace.json", manifest.to_dict())
    return root


def test_manifest_is_profile_optional_and_normalizes_fields(tmp_path: Path) -> None:
    manifest = load_source_patch_manifest(_write_patch_manifest(tmp_path, _payload()))

    assert manifest.profile_id is None
    assert manifest.target == "overlay:3"
    assert manifest.sources == ("src/injected.c",)
    assert manifest.definitions == (("helper", 0x02001000),)
    assert manifest.blz_passthrough_length is None


def test_manifest_accepts_optional_consumer_profile_and_blz_geometry(tmp_path: Path) -> None:
    payload = _payload()
    payload.update(
        profile_id="sample_rev0",
        target="arm9",
        runtime_address=0x02000100,
        blz_passthrough_length=0x80,
    )

    manifest = load_source_patch_manifest(_write_patch_manifest(tmp_path, payload))

    assert manifest.profile_id == "sample_rev0"
    assert manifest.blz_passthrough_length == 0x80


def test_manifest_rejects_blz_geometry_for_overlay(tmp_path: Path) -> None:
    payload = _payload()
    payload["blz_passthrough_length"] = 0x80

    with pytest.raises(WorkspaceError, match="BLZ passthrough"):
        load_source_patch_manifest(_write_patch_manifest(tmp_path, payload))


def test_manifest_rejects_source_path_traversal(tmp_path: Path) -> None:
    payload = _payload()
    payload["sources"] = ["../escape.c"]

    with pytest.raises(WorkspaceError, match="unsafe path"):
        load_source_patch_manifest(_write_patch_manifest(tmp_path, payload))


def test_resolve_overlay_target_requires_no_game_profile(tmp_path: Path) -> None:
    overlay = bytes(index & 0xFF for index in range(0x400))
    workspace = _write_workspace(tmp_path, overlay_data=overlay)
    payload = _payload()
    payload["expected_runtime_sha256"] = sha256_bytes(overlay)
    manifest = load_source_patch_manifest(_write_patch_manifest(tmp_path, payload))

    target = resolve_source_target(workspace, manifest)

    assert target.runtime_base == OVERLAY_BASE
    assert target.placement_offset == 0x100
    assert target.runtime_image == overlay


def test_resolve_raw_arm9_uses_workspace_runtime_metadata(tmp_path: Path) -> None:
    arm9 = b"\xAA" * 0x800
    workspace = _write_workspace(tmp_path, arm9_data=arm9, arm9_base=0x02004000)
    payload = _payload()
    payload.update(
        target="arm9",
        runtime_address=0x02004100,
        expected_runtime_sha256=sha256_bytes(arm9),
    )
    manifest = load_source_patch_manifest(_write_patch_manifest(tmp_path, payload))

    target = resolve_source_target(workspace, manifest)

    assert target.runtime_base == 0x02004000
    assert target.placement_offset == 0x100
    assert target.storage_encoding == "raw-arm"


def test_resolve_blz_arm9_uses_explicit_passthrough_override(tmp_path: Path) -> None:
    decoded = (b"ARM9" * 0x200) + b"\x00" * 0x800
    stored = compress_blz(decoded)
    workspace = _write_workspace(tmp_path, arm9_data=stored)
    payload = _payload()
    payload.update(
        target="arm9",
        runtime_address=0x02000100,
        expected_runtime_sha256=sha256_bytes(decoded),
        blz_passthrough_length=0x80,
    )
    manifest = load_source_patch_manifest(_write_patch_manifest(tmp_path, payload))

    target = resolve_source_target(workspace, manifest)

    assert target.storage_encoding == "blz"
    assert target.runtime_image == decoded
    assert target.passthrough_length == 0x80


def test_resolve_target_rejects_runtime_hash_mismatch(tmp_path: Path) -> None:
    workspace = _write_workspace(tmp_path)
    manifest = load_source_patch_manifest(_write_patch_manifest(tmp_path, _payload()))

    with pytest.raises(WorkspaceError, match="runtime SHA-256"):
        resolve_source_target(workspace, manifest)
