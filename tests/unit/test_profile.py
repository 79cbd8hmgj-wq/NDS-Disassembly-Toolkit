import hashlib
import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit.errors import ProfileError, UnsupportedRomError
from nds_disassembly_toolkit.profile import (
    load_profile,
    read_rom_identity,
    sha256_file,
    validate_rom,
)


def make_identity_rom(path: Path, *, size: int = 0x200) -> bytes:
    data = bytearray(size)
    data[0x00:0x0C] = b"SYNTH NDS\x00\x00\x00"
    data[0x0C:0x10] = b"TST0"
    data[0x10:0x12] = b"00"
    data[0x1E] = 1
    path.write_bytes(data)
    return bytes(data)


def valid_profile_payload() -> dict[str, object]:
    return {
        "id": "synthetic_rev1",
        "sha256": "0" * 64,
        "size": 512,
        "title": "SYNTH NDS",
        "game_code": "TST0",
        "maker_code": "00",
        "revision": 1,
        "expected": {
            "arm9_offset": 512,
            "arm9_ram_address": 33554432,
            "arm9_size": 4,
            "arm7_offset": 516,
            "arm7_ram_address": 37224448,
            "arm7_size": 4,
            "fnt_offset": 1024,
            "fnt_size": 21,
            "fat_offset": 1280,
            "fat_size": 24,
            "nitrofs_file_count": 3,
            "directory_count": 1,
            "arm9_overlay_offset": 768,
            "arm9_overlay_size": 32,
            "arm7_overlay_offset": 0,
            "arm7_overlay_size": 0,
            "arm9_overlay_count": 1,
            "arm7_overlay_count": 0,
        },
    }


def test_load_profile_reads_game_neutral_values(tmp_path: Path) -> None:
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(valid_profile_payload()), encoding="utf-8")

    profile = load_profile(profile_path)

    assert profile.id == "synthetic_rev1"
    assert profile.game_code == "TST0"
    assert profile.expected.nitrofs_file_count == 3


def test_load_profile_rejects_bad_sha_length(tmp_path: Path) -> None:
    profile_path = tmp_path / "bad.json"
    payload = valid_profile_payload()
    payload["sha256"] = "abc"
    profile_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProfileError, match="sha256"):
        load_profile(profile_path)


def test_read_rom_identity_reads_header_fields_and_hash(tmp_path: Path) -> None:
    rom_path = tmp_path / "test.nds"
    data = make_identity_rom(rom_path)

    identity = read_rom_identity(rom_path)

    assert identity.title == "SYNTH NDS"
    assert identity.game_code == "TST0"
    assert identity.maker_code == "00"
    assert identity.revision == 1
    assert identity.size == len(data)
    assert identity.sha256 == hashlib.sha256(data).hexdigest()


def test_validate_rom_rejects_hash_mismatch(tmp_path: Path) -> None:
    rom_path = tmp_path / "test.nds"
    data = make_identity_rom(rom_path)
    payload = valid_profile_payload()
    payload["sha256"] = "f" * 64
    payload["size"] = len(data)
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(payload), encoding="utf-8")
    profile = load_profile(profile_path)

    with pytest.raises(UnsupportedRomError, match="sha256"):
        validate_rom(rom_path, profile)


def test_sha256_file_matches_hashlib(tmp_path: Path) -> None:
    path = tmp_path / "blob.bin"
    path.write_bytes(b"Nintendo DS" * 1000)

    assert sha256_file(path, chunk_size=17) == hashlib.sha256(path.read_bytes()).hexdigest()
