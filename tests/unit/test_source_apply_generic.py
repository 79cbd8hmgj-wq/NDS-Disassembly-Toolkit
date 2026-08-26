from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit.compression.blz import compress_blz, decompress_blz, parse_blz_footer
from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.profile import LayoutExpectations, RomProfile
from nds_disassembly_toolkit.source_apply import (
    apply_source_patch,
    build_patched_runtime,
    encode_target_storage,
)
from nds_disassembly_toolkit.source_compile import CompiledSource, SourceToolchain
from nds_disassembly_toolkit.source_patch import (
    SourceHook,
    SourcePatchManifest,
    SourceTarget,
    load_source_patch_manifest,
    resolve_source_target,
)
from nds_disassembly_toolkit.workspace.manifest import (
    ExtractedOverlay,
    WorkspaceManifest,
    sha256_bytes,
    write_json_atomic,
)
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout

OVERLAY_BASE = 0x02219000


def _workspace(tmp_path: Path, overlay: bytes, *, profile_id: str | None = None) -> Path:
    root = tmp_path / "workspace"
    layout = WorkspaceLayout.from_root(root)
    for directory in layout.all_directories():
        directory.mkdir(parents=True, exist_ok=True)
    (layout.modified / "arm9.bin").write_bytes(b"\x00" * 0x100)
    (layout.modified / "arm7.bin").write_bytes(b"\x00" * 0x100)
    (layout.modified_overlays / "overlay_007.bin").write_bytes(overlay)
    manifest = WorkspaceManifest(
        format_version=1,
        profile_id=profile_id,
        rom_sha256="0" * 64,
        rom_size=1,
        arm9_sha256=sha256_bytes(b"\x00" * 0x100),
        arm7_sha256=sha256_bytes(b"\x00" * 0x100),
        files=(),
        overlays=(
            ExtractedOverlay(
                overlay_id=7,
                file_id=7,
                ram_address=OVERLAY_BASE,
                ram_size=len(overlay),
                bss_size=0,
                raw_size=len(overlay),
                decoded_size=len(overlay),
                raw_sha256=sha256_bytes(overlay),
                decoded_sha256=sha256_bytes(overlay),
                compression="none",
            ),
        ),
    )
    write_json_atomic(layout.manifests / "workspace.json", manifest.to_dict())
    return root


def _patch_manifest(tmp_path: Path, runtime: bytes, *, profile_id: str | None = None) -> Path:
    payload: dict[str, object] = {
        "format_version": 1,
        "target": "overlay:7",
        "runtime_address": OVERLAY_BASE + 0x100,
        "max_size": 4,
        "mode": "arm",
        "expected_runtime_sha256": sha256_bytes(runtime),
        "sources": ["src/injected.c"],
        "hooks": [],
    }
    if profile_id is not None:
        payload["profile_id"] = profile_id
    path = tmp_path / "source-patch.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    source = tmp_path / "src" / "injected.c"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("void entry(void) {}\n", encoding="utf-8")
    return path


def _compiled(image: bytes, symbols: tuple[tuple[str, int], ...] = ()) -> CompiledSource:
    return CompiledSource(image, symbols, (("src/injected.c", "1" * 64),), (("clang", "..."),))


def test_overlay_target_resolves_without_profile(tmp_path: Path) -> None:
    runtime = b"\xAA" * 0x200
    workspace = _workspace(tmp_path, runtime)
    manifest = load_source_patch_manifest(_patch_manifest(tmp_path, runtime))

    target = resolve_source_target(workspace, manifest)

    assert target.runtime_base == OVERLAY_BASE
    assert target.placement_offset == 0x100
    assert target.storage_encoding == "decoded-overlay"


def test_profile_binding_is_optional_but_enforced_when_declared(tmp_path: Path) -> None:
    runtime = b"\x00" * 0x200
    workspace = _workspace(tmp_path, runtime, profile_id="workspace_profile")
    manifest = load_source_patch_manifest(
        _patch_manifest(tmp_path, runtime, profile_id="different_profile")
    )

    with pytest.raises(WorkspaceError, match="profile mismatch"):
        resolve_source_target(workspace, manifest)


def test_build_patched_runtime_places_code_and_checks_hook_guards() -> None:
    runtime = bytearray(b"\x00" * 0x200)
    hook = SourceHook(
        "entry",
        OVERLAY_BASE + 0x40,
        b"\x00" * 4,
        "entry",
        True,
        "arm",
    )
    manifest = SourcePatchManifest(
        1,
        None,
        "overlay:7",
        OVERLAY_BASE + 0x100,
        4,
        "arm",
        "0" * 64,
        ("src/injected.c",),
        (),
        (hook,),
    )
    target = SourceTarget(
        "overlay:7",
        Path("overlay_007.bin"),
        OVERLAY_BASE,
        bytes(runtime),
        0x100,
        "decoded-overlay",
        len(runtime),
        None,
    )

    patched, hooks = build_patched_runtime(
        target,
        manifest,
        _compiled(b"\x01\x02\x03\x04", (("entry", OVERLAY_BASE + 0x100),)),
    )

    assert patched[0x100:0x104] == b"\x01\x02\x03\x04"
    assert patched[0x40:0x44] != b"\x00" * 4
    assert hooks[0].destination == OVERLAY_BASE + 0x100


def test_blz_storage_uses_explicit_target_passthrough_geometry() -> None:
    decoded = (b"ABCD" * 0x200) + (b"\x00" * 0x1000)
    minimal = compress_blz(decoded)
    stored = compress_blz(decoded, target_size=len(minimal) + 32)
    footer = parse_blz_footer(stored)
    passthrough = len(stored) - footer.compressed_length
    target = SourceTarget(
        "arm9",
        Path("arm9.bin"),
        0x02000000,
        decoded,
        0,
        "blz",
        len(stored),
        passthrough,
    )
    patched = bytearray(decoded)
    patched[0] ^= 1

    encoded = encode_target_storage(target, bytes(patched))

    assert len(encoded) == len(stored)
    assert decompress_blz(encoded) == bytes(patched)


def _profile(arm9_size: int) -> RomProfile:
    return RomProfile(
        id="example_rev0",
        sha256="0" * 64,
        size=1,
        title="EXAMPLE",
        game_code="EXMP",
        maker_code="01",
        revision=0,
        expected=LayoutExpectations(
            arm9_offset=0,
            arm9_ram_address=0x02000000,
            arm9_size=arm9_size,
            arm7_offset=0,
            arm7_ram_address=0x02380000,
            arm7_size=0x100,
            fnt_offset=0,
            fnt_size=0,
            fat_offset=0,
            fat_size=0,
            arm9_overlay_offset=0,
            arm9_overlay_size=0,
            arm7_overlay_offset=0,
            arm7_overlay_size=0,
            nitrofs_file_count=0,
            directory_count=0,
            arm9_overlay_count=0,
            arm7_overlay_count=0,
        ),
    )


def test_arm_target_requires_profile_and_accepts_explicit_blz_passthrough_override(
    tmp_path: Path,
) -> None:
    decoded = (b"ARM9" * 0x200) + (b"\x00" * 0x800)
    stored = compress_blz(decoded)
    root = tmp_path / "workspace-arm"
    layout = WorkspaceLayout.from_root(root)
    for directory in layout.all_directories():
        directory.mkdir(parents=True, exist_ok=True)
    (layout.modified / "arm9.bin").write_bytes(stored)
    (layout.modified / "arm7.bin").write_bytes(b"\x00" * 0x100)
    workspace_manifest = WorkspaceManifest(
        1,
        "example_rev0",
        "0" * 64,
        1,
        sha256_bytes(stored),
        sha256_bytes(b"\x00" * 0x100),
        (),
        (),
    )
    write_json_atomic(layout.manifests / "workspace.json", workspace_manifest.to_dict())
    payload = {
        "format_version": 1,
        "profile_id": "example_rev0",
        "target": "arm9",
        "runtime_address": 0x02000100,
        "max_size": 4,
        "mode": "arm",
        "expected_runtime_sha256": sha256_bytes(decoded),
        "sources": ["entry.c"],
        "hooks": [],
    }
    path = tmp_path / "arm-source-patch.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    manifest = load_source_patch_manifest(path)

    with pytest.raises(WorkspaceError, match="requires a ROM profile"):
        resolve_source_target(root, manifest)

    target = resolve_source_target(
        root,
        manifest,
        _profile(len(stored)),
        blz_passthrough_length=0x20,
    )
    assert target.storage_encoding == "blz"
    assert target.passthrough_length == 0x20


def test_end_to_end_profile_free_overlay_apply_is_transactional(tmp_path: Path) -> None:
    runtime = b"\xAA" * 0x200
    workspace = _workspace(tmp_path, runtime)
    manifest_path = _patch_manifest(tmp_path, runtime)

    def fake_run(command: tuple[str, ...]) -> str:
        if command[0] == "clang":
            Path(command[command.index("-o") + 1]).write_bytes(b"object")
        elif command[0] == "ld.lld":
            output = Path(command[command.index("-o") + 1])
            output.write_bytes(b"\x01\x02\x03\x04" if "--oformat=binary" in command else b"elf")
        elif command[0] == "nm":
            return f"{OVERLAY_BASE + 0x100:08x} T entry\n"
        return ""

    report = apply_source_patch(
        workspace,
        manifest_path,
        toolchain=SourceToolchain(),
        runner=fake_run,
    )

    layout = WorkspaceLayout.from_root(workspace)
    patched = (layout.modified_overlays / "overlay_007.bin").read_bytes()
    assert patched[0x100:0x104] == b"\x01\x02\x03\x04"
    assert report.profile_id is None
    assert (layout.manifests / "source-patch-source-patch.json").is_file()
