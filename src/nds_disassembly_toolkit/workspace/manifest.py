from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.workspace.paths import ensure_unique_relative_paths


@dataclass(frozen=True)
class ExtractedFile:
    file_id: int
    path: str
    raw_size: int
    decoded_size: int
    compression: str
    raw_sha256: str
    decoded_sha256: str


@dataclass(frozen=True)
class ExtractedOverlay:
    overlay_id: int
    file_id: int
    ram_address: int
    ram_size: int
    bss_size: int
    raw_size: int
    decoded_size: int
    raw_sha256: str
    decoded_sha256: str
    compression: str


@dataclass(frozen=True)
class WorkspaceManifest:
    format_version: int
    profile_id: str | None
    rom_sha256: str
    rom_size: int
    arm9_sha256: str
    arm7_sha256: str
    files: tuple[ExtractedFile, ...]
    overlays: tuple[ExtractedOverlay, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "profile_id": self.profile_id,
            "rom_sha256": self.rom_sha256,
            "rom_size": self.rom_size,
            "arm9_sha256": self.arm9_sha256,
            "arm7_sha256": self.arm7_sha256,
            "files": [asdict(item) for item in sorted(self.files, key=lambda item: item.file_id)],
            "overlays": [
                asdict(item) for item in sorted(self.overlays, key=lambda item: item.overlay_id)
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json_atomic(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise WorkspaceError(f"{label} must be a JSON object")
    return value


def _require_array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise WorkspaceError(f"{label} must be a JSON array")
    return value


def _require_hash(value: object, label: str) -> str:
    result = str(value).lower()
    if len(result) != 64 or any(char not in "0123456789abcdef" for char in result):
        raise WorkspaceError(f"{label} must be a 64-character SHA-256 value")
    return result


def _optional_profile_id(value: object) -> str | None:
    if value is None:
        return None
    result = str(value)
    if not result:
        raise WorkspaceError("profile_id must be null or a nonempty string")
    return result


def load_workspace_manifest(path: Path) -> WorkspaceManifest:
    try:
        payload = _require_object(
            json.loads(path.read_text(encoding="utf-8")),
            "workspace manifest",
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"cannot load workspace manifest {path}: {exc}") from exc

    try:
        format_version = int(payload["format_version"])
        profile_id = _optional_profile_id(payload.get("profile_id"))
        rom_sha256 = _require_hash(payload["rom_sha256"], "rom_sha256")
        rom_size = int(payload["rom_size"])
        arm9_sha256 = _require_hash(payload["arm9_sha256"], "arm9_sha256")
        arm7_sha256 = _require_hash(payload["arm7_sha256"], "arm7_sha256")
        file_payloads = _require_array(payload["files"], "files")
        overlay_payloads = _require_array(payload["overlays"], "overlays")
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkspaceError(f"invalid workspace manifest field: {exc}") from exc

    if format_version != 1:
        raise WorkspaceError(f"unsupported workspace format version: {format_version}")
    if rom_size <= 0:
        raise WorkspaceError("rom_size must be positive")

    files: list[ExtractedFile] = []
    file_ids: set[int] = set()
    paths: list[str] = []
    for index, value in enumerate(file_payloads):
        item = _require_object(value, f"files[{index}]")
        try:
            entry = ExtractedFile(
                file_id=int(item["file_id"]),
                path=str(item["path"]),
                raw_size=int(item["raw_size"]),
                decoded_size=int(item["decoded_size"]),
                compression=str(item["compression"]),
                raw_sha256=_require_hash(item["raw_sha256"], f"files[{index}].raw_sha256"),
                decoded_sha256=_require_hash(
                    item["decoded_sha256"], f"files[{index}].decoded_sha256"
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkspaceError(f"invalid files[{index}] field: {exc}") from exc
        if entry.file_id < 0 or entry.file_id in file_ids:
            raise WorkspaceError(f"duplicate or invalid file ID: {entry.file_id}")
        if entry.raw_size < 0 or entry.decoded_size < 0:
            raise WorkspaceError(f"files[{index}] sizes must be nonnegative")
        if entry.compression not in {"none", "lz10"}:
            raise WorkspaceError(f"unsupported file compression: {entry.compression}")
        file_ids.add(entry.file_id)
        paths.append(entry.path)
        files.append(entry)
    try:
        ensure_unique_relative_paths(paths)
    except ValueError as exc:
        raise WorkspaceError(str(exc)) from exc

    overlays: list[ExtractedOverlay] = []
    overlay_ids: set[int] = set()
    overlay_file_ids: set[int] = set()
    for index, value in enumerate(overlay_payloads):
        item = _require_object(value, f"overlays[{index}]")
        try:
            entry = ExtractedOverlay(
                overlay_id=int(item["overlay_id"]),
                file_id=int(item["file_id"]),
                ram_address=int(item["ram_address"]),
                ram_size=int(item["ram_size"]),
                bss_size=int(item["bss_size"]),
                raw_size=int(item["raw_size"]),
                decoded_size=int(item["decoded_size"]),
                raw_sha256=_require_hash(
                    item["raw_sha256"], f"overlays[{index}].raw_sha256"
                ),
                decoded_sha256=_require_hash(
                    item["decoded_sha256"], f"overlays[{index}].decoded_sha256"
                ),
                compression=str(item["compression"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WorkspaceError(f"invalid overlays[{index}] field: {exc}") from exc
        if entry.overlay_id < 0 or entry.overlay_id in overlay_ids:
            raise WorkspaceError(f"duplicate or invalid overlay ID: {entry.overlay_id}")
        if entry.file_id < 0 or entry.file_id in overlay_file_ids:
            raise WorkspaceError(f"duplicate or invalid overlay file ID: {entry.file_id}")
        if min(entry.ram_size, entry.bss_size, entry.raw_size, entry.decoded_size) < 0:
            raise WorkspaceError(f"overlays[{index}] sizes must be nonnegative")
        if entry.decoded_size != entry.ram_size:
            raise WorkspaceError(
                f"overlay {entry.overlay_id} decoded size {entry.decoded_size} "
                f"does not equal RAM size {entry.ram_size}"
            )
        if entry.compression not in {"none", "blz"}:
            raise WorkspaceError(f"unsupported overlay compression: {entry.compression}")
        overlay_ids.add(entry.overlay_id)
        overlay_file_ids.add(entry.file_id)
        overlays.append(entry)

    return WorkspaceManifest(
        format_version=format_version,
        profile_id=profile_id,
        rom_sha256=rom_sha256,
        rom_size=rom_size,
        arm9_sha256=arm9_sha256,
        arm7_sha256=arm7_sha256,
        files=tuple(sorted(files, key=lambda item: item.file_id)),
        overlays=tuple(sorted(overlays, key=lambda item: item.overlay_id)),
    )
