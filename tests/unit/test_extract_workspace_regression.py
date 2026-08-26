import json
import stat
import struct
from pathlib import Path

import pytest

from nds_disassembly_toolkit.errors import RomFormatError, WorkspaceError
from nds_disassembly_toolkit.inspection import RomInspection
from nds_disassembly_toolkit.nds.fat import FatEntry
from nds_disassembly_toolkit.nds.fnt import FntDirectory, FntFile, FntTree
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.nds.overlays import OverlayEntry
from nds_disassembly_toolkit.profile import RomIdentity
from nds_disassembly_toolkit.workspace.extract import ExtractionOptions, extract_workspace


def make_blz_fixture() -> bytes:
    footer = struct.pack("<II", 14 | (8 << 24), 7)
    return bytes.fromhex("00 f0 41 42 43 10") + footer


def make_fixture(tmp_path: Path, *, unsafe_path: bool = False) -> tuple[Path, RomInspection]:
    rom = bytearray(0x400)
    rom[0x200:0x204] = b"ARM9"
    rom[0x204:0x208] = b"ARM7"
    blz = make_blz_fixture()
    lz10 = bytes.fromhex("10 09 00 00 10 41 42 43 30 02")
    plain = b"PLAIN"
    rom[0x300 : 0x300 + len(blz)] = blz
    rom[0x320 : 0x320 + len(lz10)] = lz10
    rom[0x340 : 0x340 + len(plain)] = plain
    rom_path = tmp_path / "fixture.nds"
    rom_path.write_bytes(rom)

    header = NdsHeader(
        title="SYNTH NDS",
        game_code="TST0",
        maker_code="00",
        revision=1,
        arm9_offset=0x200,
        arm9_entry_address=0,
        arm9_ram_address=0,
        arm9_size=4,
        arm7_offset=0x204,
        arm7_entry_address=0,
        arm7_ram_address=0,
        arm7_size=4,
        fnt_offset=0,
        fnt_size=0,
        fat_offset=0,
        fat_size=24,
        arm9_overlay_offset=0,
        arm9_overlay_size=32,
        arm7_overlay_offset=0,
        arm7_overlay_size=0,
        rom_size_field=len(rom),
    )
    path = "../evil.bin" if unsafe_path else "Game/a.bin"
    inspection = RomInspection(
        source_path=rom_path,
        identity=RomIdentity("SYNTH NDS", "TST0", "00", 1, len(rom), "a" * 64),
        profile_id=None,
        supported=None,
        header=header,
        fat=(
            FatEntry(0, 0x300, 0x300 + len(blz)),
            FatEntry(1, 0x320, 0x320 + len(lz10)),
            FatEntry(2, 0x340, 0x340 + len(plain)),
        ),
        fnt=FntTree(
            directories=(FntDirectory(0xF000, 1, 1, ""),),
            files=(FntFile(1, path), FntFile(2, "plain.bin")),
        ),
        arm9_overlays=(OverlayEntry(0, 0x02219440, 21, 2, 0, 0, 0, 0),),
        arm7_overlays=(),
        layout_mismatches=(),
    )
    return rom_path, inspection


def patch_inspection(monkeypatch: pytest.MonkeyPatch, inspection: RomInspection) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.workspace.extract.inspect_rom",
        lambda *args, **kwargs: inspection,
    )


def test_extract_workspace_writes_raw_decoded_and_modified_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rom_path, inspection = make_fixture(tmp_path)
    patch_inspection(monkeypatch, inspection)
    workspace = tmp_path / "workspace"

    manifest = extract_workspace(rom_path, ExtractionOptions(workspace))

    assert (workspace / "original/arm9.bin").read_bytes() == b"ARM9"
    assert (workspace / "modified/arm7.bin").read_bytes() == b"ARM7"
    assert (workspace / "original/raw/overlays/overlay_000.bin").read_bytes() == make_blz_fixture()
    assert (workspace / "original/decoded/overlays/overlay_000.bin").read_bytes() == b"ABC" * 7
    assert (workspace / "modified/overlays/overlay_000.bin").read_bytes() == b"ABC" * 7
    assert (workspace / "original/decoded/nitrofs/Game/a.bin").read_bytes() == b"ABCABCABC"
    assert (workspace / "modified/nitrofs/plain.bin").read_bytes() == b"PLAIN"
    assert len(manifest.files) == 2
    assert manifest.files[0].compression == "lz10"
    assert manifest.overlays[0].compression == "blz"
    payload = json.loads((workspace / "manifests/workspace.json").read_text())
    assert payload["profile_id"] is None
    assert not ((workspace / "original/arm9.bin").stat().st_mode & stat.S_IWUSR)


def test_extract_workspace_refuses_existing_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rom_path, inspection = make_fixture(tmp_path)
    patch_inspection(monkeypatch, inspection)
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(WorkspaceError, match="already exists"):
        extract_workspace(rom_path, ExtractionOptions(workspace))


def test_extract_workspace_force_replaces_existing_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rom_path, inspection = make_fixture(tmp_path)
    patch_inspection(monkeypatch, inspection)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "old.txt").write_text("old")

    extract_workspace(rom_path, ExtractionOptions(workspace, force=True))

    assert not (workspace / "old.txt").exists()
    assert (workspace / "manifests/workspace.json").is_file()


def test_extract_workspace_removes_staging_directory_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rom_path, inspection = make_fixture(tmp_path)
    patch_inspection(monkeypatch, inspection)
    monkeypatch.setattr(
        "nds_disassembly_toolkit.workspace.extract.decompress_lz10",
        lambda data: (_ for _ in ()).throw(RomFormatError("broken LZ10")),
    )
    workspace = tmp_path / "workspace"

    with pytest.raises(RomFormatError, match="broken LZ10"):
        extract_workspace(rom_path, ExtractionOptions(workspace))

    assert not workspace.exists()
    assert list(tmp_path.glob(".workspace.tmp-*")) == []


def test_extract_workspace_rejects_path_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rom_path, inspection = make_fixture(tmp_path, unsafe_path=True)
    patch_inspection(monkeypatch, inspection)
    workspace = tmp_path / "workspace"

    with pytest.raises(WorkspaceError, match="unsafe"):
        extract_workspace(rom_path, ExtractionOptions(workspace))

    assert not (tmp_path / "evil.bin").exists()


def test_extract_workspace_creates_empty_raw_override_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rom_path, inspection = make_fixture(tmp_path)
    patch_inspection(monkeypatch, inspection)
    workspace = tmp_path / "workspace"

    extract_workspace(rom_path, ExtractionOptions(workspace))

    assert (workspace / "modified/raw/nitrofs").is_dir()
    assert list((workspace / "modified/raw/nitrofs").rglob("*")) == []
    assert not (workspace / "manifests/build-overrides.json").exists()
