import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.inspection import RomInspection
from nds_disassembly_toolkit.nds.fat import FatEntry
from nds_disassembly_toolkit.nds.fnt import FntDirectory, FntFile, FntTree
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.nds.overlays import OverlayEntry
from nds_disassembly_toolkit.profile import RomIdentity
from nds_disassembly_toolkit.workspace.manifest import (
    ExtractedFile,
    ExtractedOverlay,
    WorkspaceManifest,
    load_workspace_manifest,
    sha256_bytes,
)
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout
from nds_disassembly_toolkit.workspace.overrides import (
    BuildOverrides,
    OverlayLayoutOverride,
    RawNitroFsOverride,
    write_build_overrides,
)
from nds_disassembly_toolkit.workspace.validate import validate_workspace


def make_workspace(tmp_path: Path) -> tuple[Path, Path, RomInspection]:
    root = tmp_path / "workspace"
    layout = WorkspaceLayout.from_root(root)
    for directory in layout.all_directories():
        directory.mkdir(parents=True, exist_ok=True)

    source = tmp_path / "game.nds"
    source_bytes = b"R" * 1024
    source.write_bytes(source_bytes)

    arm9 = b"ARM9"
    arm7 = b"ARM7"
    raw_file = b"RAW"
    decoded_file = b"FILE"
    raw_overlay = b"BLZ"
    decoded_overlay = b"OVER"

    (layout.original / "arm9.bin").write_bytes(arm9)
    (layout.original / "arm7.bin").write_bytes(arm7)
    (layout.modified / "arm9.bin").write_bytes(arm9)
    (layout.modified / "arm7.bin").write_bytes(arm7)
    for target, payload in (
        (layout.original_raw_nitrofs / "Game/a.bin", raw_file),
        (layout.original_decoded_nitrofs / "Game/a.bin", decoded_file),
        (layout.modified_nitrofs / "Game/a.bin", decoded_file),
        (layout.original_raw_overlays / "overlay_000.bin", raw_overlay),
        (layout.original_decoded_overlays / "overlay_000.bin", decoded_overlay),
        (layout.modified_overlays / "overlay_000.bin", decoded_overlay),
    ):
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)

    manifest = WorkspaceManifest(
        format_version=1,
        profile_id=None,
        rom_sha256=sha256_bytes(source_bytes),
        rom_size=len(source_bytes),
        arm9_sha256=sha256_bytes(arm9),
        arm7_sha256=sha256_bytes(arm7),
        files=(
            ExtractedFile(
                file_id=1,
                path="Game/a.bin",
                raw_size=len(raw_file),
                decoded_size=len(decoded_file),
                compression="lz10",
                raw_sha256=sha256_bytes(raw_file),
                decoded_sha256=sha256_bytes(decoded_file),
            ),
        ),
        overlays=(
            ExtractedOverlay(
                overlay_id=0,
                file_id=0,
                ram_address=0x02219440,
                ram_size=len(decoded_overlay),
                bss_size=0,
                raw_size=len(raw_overlay),
                decoded_size=len(decoded_overlay),
                raw_sha256=sha256_bytes(raw_overlay),
                decoded_sha256=sha256_bytes(decoded_overlay),
                compression="blz",
            ),
        ),
    )
    (layout.manifests / "workspace.json").write_text(manifest.to_json(), encoding="utf-8")

    header = NdsHeader(
        title="SYNTH NDS",
        game_code="TST0",
        maker_code="00",
        revision=1,
        arm9_offset=0,
        arm9_entry_address=0,
        arm9_ram_address=0,
        arm9_size=4,
        arm7_offset=4,
        arm7_entry_address=0,
        arm7_ram_address=0,
        arm7_size=4,
        fnt_offset=0,
        fnt_size=0,
        fat_offset=0,
        fat_size=16,
        arm9_overlay_offset=0,
        arm9_overlay_size=32,
        arm7_overlay_offset=0,
        arm7_overlay_size=0,
        rom_size_field=len(source_bytes),
    )
    inspection = RomInspection(
        source_path=source,
        identity=RomIdentity(
            "SYNTH NDS",
            "TST0",
            "00",
            1,
            len(source_bytes),
            sha256_bytes(source_bytes),
        ),
        profile_id=None,
        supported=None,
        header=header,
        fat=(FatEntry(0, 0, 3), FatEntry(1, 3, 6)),
        fnt=FntTree(
            directories=(FntDirectory(0xF000, 1, 1, ""),),
            files=(FntFile(1, "Game/a.bin"),),
        ),
        arm9_overlays=(OverlayEntry(0, 0x02219440, 4, 0, 0, 0, 0, 0),),
        arm7_overlays=(),
        layout_mismatches=(),
    )
    return source, root, inspection


def patch_inspection(monkeypatch: pytest.MonkeyPatch, inspection: RomInspection) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.workspace.validate.inspect_rom",
        lambda *args, **kwargs: inspection,
    )


def test_load_workspace_manifest_round_trips(tmp_path: Path) -> None:
    _, root, _ = make_workspace(tmp_path)

    manifest = load_workspace_manifest(root / "manifests/workspace.json")

    assert manifest.profile_id is None
    assert manifest.files[0].path == "Game/a.bin"
    assert manifest.overlays[0].overlay_id == 0


def test_validate_workspace_detects_modified_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    patch_inspection(monkeypatch, inspection)
    (root / "modified/nitrofs/Game/a.bin").write_bytes(b"EDIT")

    result = validate_workspace(source, root)

    assert [(item.kind, item.identifier) for item in result.changes] == [
        ("nitrofs", "Game/a.bin")
    ]


def test_validate_workspace_rejects_wrong_source_rom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    source.write_bytes(b"different")
    patch_inspection(monkeypatch, inspection)

    with pytest.raises(WorkspaceError, match="source ROM"):
        validate_workspace(source, root)


def test_validate_workspace_rejects_tampered_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    patch_inspection(monkeypatch, inspection)
    (root / "original/decoded/nitrofs/Game/a.bin").write_bytes(b"TAMPER")

    with pytest.raises(WorkspaceError, match="original decoded"):
        validate_workspace(source, root)


def test_validate_workspace_rejects_missing_modified_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    patch_inspection(monkeypatch, inspection)
    (root / "modified/nitrofs/Game/a.bin").unlink()

    with pytest.raises(WorkspaceError, match="missing modified"):
        validate_workspace(source, root)


def test_load_workspace_manifest_rejects_unsafe_path(tmp_path: Path) -> None:
    _, root, _ = make_workspace(tmp_path)
    path = root / "manifests/workspace.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["files"][0]["path"] = "../evil.bin"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(WorkspaceError, match="unsafe"):
        load_workspace_manifest(path)


def test_validate_workspace_rejects_extra_modified_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    patch_inspection(monkeypatch, inspection)
    (root / "modified/nitrofs/extra.bin").write_bytes(b"extra")

    with pytest.raises(WorkspaceError, match="unmanifested"):
        validate_workspace(source, root)


def test_validate_workspace_accepts_declared_raw_and_overlay_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    patch_inspection(monkeypatch, inspection)
    layout = WorkspaceLayout.from_root(root)
    raw_original = (layout.original_raw_nitrofs / "Game/a.bin").read_bytes()
    raw_replacement = raw_original + b"TAIL"
    raw_path = layout.modified_raw_nitrofs / "Game/a.bin"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(raw_replacement)
    overlay_path = layout.modified_overlays / "overlay_000.bin"
    overlay_path.write_bytes(overlay_path.read_bytes() + b"GROW")
    write_build_overrides(
        layout.build_overrides,
        BuildOverrides(
            1,
            None,
            (
                RawNitroFsOverride(
                    1,
                    "Game/a.bin",
                    len(raw_original),
                    sha256_bytes(raw_original),
                    len(raw_replacement),
                    sha256_bytes(raw_replacement),
                ),
            ),
            (OverlayLayoutOverride(0, 4, 0, 8, 1, 0),),
        ),
    )

    result = validate_workspace(source, root)

    assert result.overrides is not None
    assert {(item.kind, item.identifier) for item in result.changes} == {
        ("nitrofs_raw", "Game/a.bin"),
        ("overlay", "0"),
    }


def test_validate_workspace_rejects_raw_override_with_stale_original_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    patch_inspection(monkeypatch, inspection)
    layout = WorkspaceLayout.from_root(root)
    replacement = b"RAW-TAIL"
    path = layout.modified_raw_nitrofs / "Game/a.bin"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(replacement)
    write_build_overrides(
        layout.build_overrides,
        BuildOverrides(
            1,
            None,
            (
                RawNitroFsOverride(
                    1,
                    "Game/a.bin",
                    3,
                    "f" * 64,
                    len(replacement),
                    sha256_bytes(replacement),
                ),
            ),
            (),
        ),
    )
    before = path.read_bytes()

    with pytest.raises(WorkspaceError, match="original raw override"):
        validate_workspace(source, root)

    assert path.read_bytes() == before


def test_validate_workspace_rejects_simultaneous_decoded_and_raw_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    patch_inspection(monkeypatch, inspection)
    layout = WorkspaceLayout.from_root(root)
    original = (layout.original_raw_nitrofs / "Game/a.bin").read_bytes()
    replacement = original + b"TAIL"
    path = layout.modified_raw_nitrofs / "Game/a.bin"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(replacement)
    (layout.modified_nitrofs / "Game/a.bin").write_bytes(b"EDIT")
    write_build_overrides(
        layout.build_overrides,
        BuildOverrides(
            1,
            None,
            (
                RawNitroFsOverride(
                    1,
                    "Game/a.bin",
                    len(original),
                    sha256_bytes(original),
                    len(replacement),
                    sha256_bytes(replacement),
                ),
            ),
            (),
        ),
    )

    with pytest.raises(WorkspaceError, match="simultaneous decoded and raw"):
        validate_workspace(source, root)


def test_validate_workspace_rejects_undeclared_overlay_growth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    patch_inspection(monkeypatch, inspection)
    layout = WorkspaceLayout.from_root(root)
    path = layout.modified_overlays / "overlay_000.bin"
    path.write_bytes(path.read_bytes() + b"GROW")

    with pytest.raises(WorkspaceError, match="size mismatch"):
        validate_workspace(source, root)


def test_validate_workspace_rejects_unmanifested_raw_override_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, root, inspection = make_workspace(tmp_path)
    patch_inspection(monkeypatch, inspection)
    layout = WorkspaceLayout.from_root(root)
    extra = layout.modified_raw_nitrofs / "extra.bin"
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_bytes(b"extra")

    with pytest.raises(WorkspaceError, match="unmanifested modified raw"):
        validate_workspace(source, root)
