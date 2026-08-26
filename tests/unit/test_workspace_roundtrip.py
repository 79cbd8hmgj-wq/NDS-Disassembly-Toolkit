import struct
from pathlib import Path

from nds_disassembly_toolkit.workspace.extract import ExtractionOptions, extract_workspace
from nds_disassembly_toolkit.workspace.rebuild import RebuildOptions, rebuild_rom


def make_blz_fixture() -> bytes:
    footer = struct.pack("<II", 14 | (8 << 24), 7)
    return bytes.fromhex("00 f0 41 42 43 10") + footer


def make_roundtrip_rom(path: Path) -> bytes:
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
    path.write_bytes(rom)
    return bytes(rom)


def test_profile_free_extract_rebuild_is_exact_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "source.nds"
    source_bytes = make_roundtrip_rom(source)
    workspace = tmp_path / "workspace"

    manifest = extract_workspace(source, ExtractionOptions(workspace))
    output = tmp_path / "rebuilt.nds"
    report = rebuild_rom(source, workspace, RebuildOptions(output))

    assert manifest.profile_id is None
    assert manifest.rom_size == len(source_bytes)
    assert output.read_bytes() == source_bytes
    assert report.exact_copy is True
    assert report.changes == ()
