from __future__ import annotations

import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit import source_apply
from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.source_compile import CompiledSource
from nds_disassembly_toolkit.workspace.manifest import (
    ExtractedOverlay,
    WorkspaceManifest,
    sha256_bytes,
    write_json_atomic,
)
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout


def test_apply_source_patch_refuses_target_changed_during_compile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    layout = WorkspaceLayout.from_root(workspace)
    for directory in layout.all_directories():
        directory.mkdir(parents=True, exist_ok=True)

    original = b"\x00" * 0x400
    changed = b"\xFF" + original[1:]
    target_path = layout.modified_overlays / "overlay_003.bin"
    target_path.write_bytes(original)

    workspace_manifest = WorkspaceManifest(
        format_version=1,
        profile_id=None,
        rom_sha256="0" * 64,
        rom_size=1,
        arm9_sha256="1" * 64,
        arm7_sha256="2" * 64,
        files=(),
        overlays=(
            ExtractedOverlay(
                overlay_id=3,
                file_id=3,
                ram_address=0x02200000,
                ram_size=len(original),
                bss_size=0,
                raw_size=len(original),
                decoded_size=len(original),
                raw_sha256=sha256_bytes(original),
                decoded_sha256=sha256_bytes(original),
                compression="none",
            ),
        ),
    )
    write_json_atomic(layout.manifests / "workspace.json", workspace_manifest.to_dict())

    patch_manifest = tmp_path / "patch.json"
    patch_manifest.write_text(
        json.dumps(
            {
                "format_version": 1,
                "target": "overlay:3",
                "runtime_address": 0x02200100,
                "max_size": 4,
                "mode": "arm",
                "expected_runtime_sha256": sha256_bytes(original),
                "sources": ["injected.c"],
                "hooks": [],
            }
        ),
        encoding="utf-8",
    )

    def compile_and_change_target(*args: object, **kwargs: object) -> CompiledSource:
        target_path.write_bytes(changed)
        return CompiledSource(
            image=b"\x01\x02\x03\x04",
            symbols=(),
            source_hashes=(("injected.c", "3" * 64),),
            commands=(("clang", "..."),),
        )

    monkeypatch.setattr(source_apply, "compile_source_patch", compile_and_change_target)

    with pytest.raises(WorkspaceError, match="runtime SHA-256 mismatch"):
        source_apply.apply_source_patch(workspace, patch_manifest)

    assert target_path.read_bytes() == changed
    assert not (layout.manifests / "source-patch-patch.json").exists()
