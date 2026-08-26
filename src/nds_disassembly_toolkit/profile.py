from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
from pathlib import Path
from typing import Any

from nds_disassembly_toolkit.errors import ProfileError, UnsupportedRomError


@dataclass(frozen=True)
class LayoutExpectations:
    arm9_offset: int
    arm9_ram_address: int
    arm9_size: int
    arm7_offset: int
    arm7_ram_address: int
    arm7_size: int
    fnt_offset: int
    fnt_size: int
    fat_offset: int
    fat_size: int
    arm9_overlay_offset: int
    arm9_overlay_size: int
    arm7_overlay_offset: int
    arm7_overlay_size: int
    nitrofs_file_count: int
    directory_count: int
    arm9_overlay_count: int
    arm7_overlay_count: int


@dataclass(frozen=True)
class RomProfile:
    id: str
    sha256: str
    size: int
    title: str
    game_code: str
    maker_code: str
    revision: int
    expected: LayoutExpectations


@dataclass(frozen=True)
class RomIdentity:
    title: str
    game_code: str
    maker_code: str
    revision: int
    size: int
    sha256: str


def _require_mapping(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileError(f"{name} must be an object")
    return value


def _decode_ascii(raw: bytes) -> str:
    try:
        return raw.split(b"\x00", 1)[0].decode("ascii", errors="strict").rstrip()
    except UnicodeDecodeError as exc:
        raise UnsupportedRomError("ROM identity fields are not valid ASCII") from exc


def load_profile(path: Path) -> RomProfile:
    try:
        payload = _require_mapping(json.loads(path.read_text(encoding="utf-8")), "profile")
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"cannot load profile {path}: {exc}") from exc

    try:
        sha256 = str(payload["sha256"]).lower()
        game_code = str(payload["game_code"])
        maker_code = str(payload["maker_code"])
        revision = int(payload["revision"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProfileError(f"invalid profile field: {exc}") from exc

    if len(sha256) != 64 or any(ch not in "0123456789abcdef" for ch in sha256):
        raise ProfileError("sha256 must be 64 lowercase hexadecimal characters")
    if len(game_code) != 4:
        raise ProfileError("game_code must contain exactly 4 characters")
    if len(maker_code) != 2:
        raise ProfileError("maker_code must contain exactly 2 characters")
    if not 0 <= revision <= 255:
        raise ProfileError("revision must fit in one byte")

    expected_payload = _require_mapping(payload.get("expected"), "expected")
    expected_names = {field.name for field in fields(LayoutExpectations)}
    missing_expected = sorted(expected_names - expected_payload.keys())
    if missing_expected:
        raise ProfileError(f"expected is missing fields: {', '.join(missing_expected)}")

    try:
        return RomProfile(
            id=str(payload["id"]),
            sha256=sha256,
            size=int(payload["size"]),
            title=str(payload["title"]),
            game_code=game_code,
            maker_code=maker_code,
            revision=revision,
            expected=LayoutExpectations(
                **{name: int(expected_payload[name]) for name in expected_names}
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProfileError(f"invalid profile field: {exc}") from exc


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def read_rom_identity(path: Path) -> RomIdentity:
    size = path.stat().st_size
    with path.open("rb") as handle:
        header = handle.read(0x20)
    if len(header) < 0x20:
        raise UnsupportedRomError(f"ROM is too small for an NDS header: {len(header)} bytes")
    return RomIdentity(
        title=_decode_ascii(header[0x00:0x0C]),
        game_code=_decode_ascii(header[0x0C:0x10]),
        maker_code=_decode_ascii(header[0x10:0x12]),
        revision=header[0x1E],
        size=size,
        sha256=sha256_file(path),
    )


def validate_rom(path: Path, profile: RomProfile) -> RomIdentity:
    identity = read_rom_identity(path)
    comparisons = {
        "title": (identity.title, profile.title),
        "game code": (identity.game_code, profile.game_code),
        "maker code": (identity.maker_code, profile.maker_code),
        "revision": (identity.revision, profile.revision),
        "size": (identity.size, profile.size),
        "sha256": (identity.sha256, profile.sha256),
    }
    for label, (actual, expected) in comparisons.items():
        if actual != expected:
            raise UnsupportedRomError(
                f"unsupported ROM: {label} mismatch; expected {expected!r}, got {actual!r}"
            )
    return identity
