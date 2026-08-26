import struct
from pathlib import Path

import pytest

from nds_disassembly_toolkit.compression.lz10 import decompress_lz10
from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.inspection import RomInspection
from nds_disassembly_toolkit.nds.fat import parse_fat
from nds_disassembly_toolkit.nds.fnt import parse_fnt
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.nds.overlays import parse_arm9_overlays
from nds_disassembly_toolkit.profile import RomIdentity
from nds_disassembly_toolkit.workspace.extract import ExtractionOptions, extract_workspace
from nds_disassembly_toolkit.workspace.manifest import sha256_bytes
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout
from nds_disassembly_toolkit.workspace.overrides import (
    BuildOverrides,
    OverlayLayoutOverride,
    RawNitroFsOverride,
    write_build_overrides,
)
from nds_disassembly_toolkit.workspace.rebuild import RebuildOptions, rebuild_rom


def make_blz_fixture() -> bytes:
    footer = struct.pack("<II", 14 | (8 << 24), 7)
    return bytes.fromhex("00 f0 41 42 43 10") + footer


def make_rom(tmp_path: Path) -> tuple[Path, RomInspection]:
    rom = bytearray(b"\xff" * 0x2000)
    rom[0x00:0x0C] = b"SYNTH NDS\x00\x00\x00"
    rom[0x0C:0x10] = b"TST0"
    rom[0x10:0x12] = b"00"
    rom[0x1E] = 1
    struct.pack_into("<III", rom, 0x20, 0x200, 0x02000000, 0x02000000)
    struct.pack_into("<I", rom, 0x2C, 4)
    struct.pack_into("<III", rom, 0x30, 0x204, 0x02380000, 0x02380000)
    struct.pack_into("<I", rom, 0x3C, 4)

    fnt = bytearray(struct.pack("<IHH", 8, 1, 1))
    fnt.extend(bytes([5]) + b"a.bin")
    fnt.extend(bytes([5]) + b"b.bin")
    fnt.append(0)
    rom[0x400 : 0x400 + len(fnt)] = fnt
    struct.pack_into("<II", rom, 0x40, 0x400, len(fnt))
    struct.pack_into("<II", rom, 0x48, 0x500, 24)
    struct.pack_into("<II", rom, 0x50, 0x300, 32)
    struct.pack_into("<II", rom, 0x58, 0, 0)
    struct.pack_into("<I", rom, 0x80, len(rom))

    blz = make_blz_fixture()
    lz10 = bytes.fromhex("10 09 00 00 10 41 42 43 30 02")
    plain = b"PLAIN"
    rom[0x600 : 0x600 + len(blz)] = blz
    rom[0x800 : 0x800 + len(lz10)] = lz10
    rom[0xA00 : 0xA00 + len(plain)] = plain
    struct.pack_into("<II", rom, 0x500, 0x600, 0x600 + len(blz))
    struct.pack_into("<II", rom, 0x508, 0x800, 0x800 + len(lz10))
    struct.pack_into("<II", rom, 0x510, 0xA00, 0xA00 + len(plain))
    struct.pack_into("<8I", rom, 0x300, 0, 0x02219440, 21, 0, 0, 0, 0, 0x0100000E)
    rom[0x200:0x204] = b"ARM9"
    rom[0x204:0x208] = b"ARM7"

    path = tmp_path / "source.nds"
    path.write_bytes(rom)
    header = NdsHeader.from_bytes(rom)
    fat = parse_fat(rom, header)
    fnt_tree = parse_fnt(rom, header, len(fat))
    overlays = parse_arm9_overlays(rom, header)
    inspection = RomInspection(
        source_path=path,
        identity=RomIdentity(
            "SYNTH NDS",
            "TST0",
            "00",
            1,
            len(rom),
            sha256_bytes(bytes(rom)),
        ),
        profile_id=None,
        supported=None,
        header=header,
        fat=fat,
        fnt=fnt_tree,
        arm9_overlays=overlays,
        arm7_overlays=(),
        layout_mismatches=(),
    )
    return path, inspection


def make_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, RomInspection]:
    source, inspection = make_rom(tmp_path)
    monkeypatch.setattr(
        "nds_disassembly_toolkit.workspace.extract.inspect_rom",
        lambda *args, **kwargs: inspection,
    )
    monkeypatch.setattr(
        "nds_disassembly_toolkit.workspace.validate.inspect_rom",
        lambda *args, **kwargs: inspection,
    )
    workspace = tmp_path / "workspace"
    extract_workspace(source, ExtractionOptions(workspace))
    return source, workspace, inspection


def parse_rebuilt(path: Path) -> tuple[bytes, NdsHeader]:
    data = path.read_bytes()
    return data, NdsHeader.from_bytes(data)


def test_no_change_rebuild_is_exact_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, workspace, _ = make_workspace(tmp_path, monkeypatch)
    output = tmp_path / "rebuilt.nds"

    report = rebuild_rom(source, workspace, RebuildOptions(output))

    assert output.read_bytes() == source.read_bytes()
    assert report.exact_copy is True
    assert report.changes == ()
    assert output.with_suffix(".nds.build.json").is_file()


def test_rebuild_changed_lz10_file_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, workspace, _ = make_workspace(tmp_path, monkeypatch)
    changed = b"EDITED-LZ10"
    (workspace / "modified/nitrofs/a.bin").write_bytes(changed)
    output = tmp_path / "rebuilt.nds"

    report = rebuild_rom(source, workspace, RebuildOptions(output))

    data, header = parse_rebuilt(output)
    fat = parse_fat(data, header)
    assert decompress_lz10(data[fat[1].start : fat[1].end]) == changed
    assert report.exact_copy is False
    assert report.changes[0].encoding == "lz10"


def test_rebuild_changed_plain_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, workspace, _ = make_workspace(tmp_path, monkeypatch)
    changed = b"NEW-PLAIN-CONTENT"
    (workspace / "modified/nitrofs/b.bin").write_bytes(changed)
    output = tmp_path / "rebuilt.nds"

    rebuild_rom(source, workspace, RebuildOptions(output))

    data, header = parse_rebuilt(output)
    fat = parse_fat(data, header)
    assert data[fat[2].start : fat[2].end] == changed


def test_rebuild_changed_overlay_stores_uncompressed_and_clears_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, workspace, _ = make_workspace(tmp_path, monkeypatch)
    overlay_path = workspace / "modified/overlays/overlay_000.bin"
    modified = bytearray(overlay_path.read_bytes())
    modified[0] ^= 0xFF
    overlay_path.write_bytes(modified)
    output = tmp_path / "rebuilt.nds"

    report = rebuild_rom(source, workspace, RebuildOptions(output))

    data, header = parse_rebuilt(output)
    fat = parse_fat(data, header)
    overlay = parse_arm9_overlays(data, header)[0]
    assert fat[0].size == 21
    assert data[fat[0].start : fat[0].end] == bytes(modified)
    assert overlay.flags == 0
    assert overlay.compressed_size == 0
    assert report.changes[0].encoding == "uncompressed-overlay"


def test_rebuild_applies_same_size_arm9_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, workspace, _ = make_workspace(tmp_path, monkeypatch)
    (workspace / "modified/arm9.bin").write_bytes(b"EDIT")
    output = tmp_path / "rebuilt.nds"

    rebuild_rom(source, workspace, RebuildOptions(output))

    data, header = parse_rebuilt(output)
    assert data[header.arm9_offset : header.arm9_offset + header.arm9_size] == b"EDIT"


def test_rebuild_rejects_modified_arm_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, workspace, _ = make_workspace(tmp_path, monkeypatch)
    (workspace / "modified/arm9.bin").write_bytes(b"TOO-LONG")

    with pytest.raises(WorkspaceError, match="ARM9 size"):
        rebuild_rom(source, workspace, RebuildOptions(tmp_path / "rebuilt.nds"))


def test_rebuild_refuses_existing_output_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, workspace, _ = make_workspace(tmp_path, monkeypatch)
    output = tmp_path / "rebuilt.nds"
    output.write_bytes(b"existing")

    with pytest.raises(WorkspaceError, match="output already exists"):
        rebuild_rom(source, workspace, RebuildOptions(output))


def test_rebuild_force_replaces_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, workspace, _ = make_workspace(tmp_path, monkeypatch)
    output = tmp_path / "rebuilt.nds"
    output.write_bytes(b"existing")

    rebuild_rom(source, workspace, RebuildOptions(output, force=True))

    assert output.read_bytes() == source.read_bytes()


def test_rebuild_rejects_payloads_that_exceed_rom_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, workspace, _ = make_workspace(tmp_path, monkeypatch)
    (workspace / "modified/nitrofs/b.bin").write_bytes(b"X" * 0x3000)

    with pytest.raises(WorkspaceError, match="capacity"):
        rebuild_rom(source, workspace, RebuildOptions(tmp_path / "rebuilt.nds"))


def test_rebuild_applies_raw_and_overlay_layout_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, workspace, inspection = make_workspace(tmp_path, monkeypatch)
    layout = WorkspaceLayout.from_root(workspace)
    raw_original = (layout.original_raw_nitrofs / "a.bin").read_bytes()
    raw_replacement = raw_original + b"TAIL"
    raw_path = layout.modified_raw_nitrofs / "a.bin"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(raw_replacement)
    overlay_path = layout.modified_overlays / "overlay_000.bin"
    overlay_original = overlay_path.read_bytes()
    overlay_replacement = overlay_original + b"GROW"
    overlay_path.write_bytes(overlay_replacement)
    write_build_overrides(
        layout.build_overrides,
        BuildOverrides(
            1,
            None,
            (
                RawNitroFsOverride(
                    1,
                    "a.bin",
                    len(raw_original),
                    sha256_bytes(raw_original),
                    len(raw_replacement),
                    sha256_bytes(raw_replacement),
                ),
            ),
            (
                OverlayLayoutOverride(
                    0,
                    inspection.arm9_overlays[0].ram_size,
                    inspection.arm9_overlays[0].bss_size,
                    len(overlay_replacement),
                    1,
                    0,
                ),
            ),
        ),
    )
    output = tmp_path / "rebuilt-overrides.nds"

    report = rebuild_rom(source, workspace, RebuildOptions(output))

    data, header = parse_rebuilt(output)
    fat = parse_fat(data, header)
    overlay = parse_arm9_overlays(data, header)[0]
    assert data[fat[1].start : fat[1].end] == raw_replacement
    assert data[fat[0].start : fat[0].end] == overlay_replacement
    assert overlay.ram_size == len(overlay_replacement)
    assert overlay.bss_size == 1
    assert overlay.flags == 0
    assert {item.encoding for item in report.changes} == {
        "raw-override",
        "uncompressed-overlay",
    }
