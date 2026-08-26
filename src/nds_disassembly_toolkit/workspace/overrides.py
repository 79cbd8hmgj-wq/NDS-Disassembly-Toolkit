from __future__ import annotations

import json
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.workspace.paths import safe_relative_path

_HEX_DIGITS = frozenset("0123456789abcdef")


def _require_sha256(value: str, label: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(character not in _HEX_DIGITS for character in normalized):
        raise WorkspaceError(f"{label} must be a lowercase SHA-256 value")
    return normalized


def _optional_profile_id(value: object) -> str | None:
    if value is None:
        return None
    result = str(value)
    if not result:
        raise WorkspaceError("build override profile_id must be null or a nonempty string")
    return result


@dataclass(frozen=True)
class RawNitroFsOverride:
    file_id: int
    path: str
    expected_size: int
    expected_sha256: str
    replacement_size: int
    replacement_sha256: str

    def validate(self) -> None:
        if isinstance(self.file_id, bool) or self.file_id < 0:
            raise WorkspaceError("raw override file ID must be nonnegative")
        try:
            safe_relative_path(self.path)
        except ValueError as exc:
            raise WorkspaceError(str(exc)) from exc
        if min(self.expected_size, self.replacement_size) < 0:
            raise WorkspaceError("raw override sizes must be nonnegative")
        expected = _require_sha256(self.expected_sha256, "expected raw SHA-256")
        replacement = _require_sha256(self.replacement_sha256, "replacement raw SHA-256")
        if self.expected_size == self.replacement_size and expected == replacement:
            raise WorkspaceError("raw override replacement must change size or content")


@dataclass(frozen=True)
class OverlayLayoutOverride:
    overlay_id: int
    expected_ram_size: int
    expected_bss_size: int
    replacement_ram_size: int
    replacement_bss_size: int
    replacement_flags: int

    def validate(self) -> None:
        if isinstance(self.overlay_id, bool) or self.overlay_id < 0:
            raise WorkspaceError("overlay override ID must be nonnegative")
        if (
            min(
                self.expected_ram_size,
                self.expected_bss_size,
                self.replacement_ram_size,
                self.replacement_bss_size,
            )
            < 0
        ):
            raise WorkspaceError("overlay override geometry must be nonnegative")
        if self.expected_ram_size == 0 or self.replacement_ram_size == 0:
            raise WorkspaceError("overlay RAM sizes must be positive")
        if self.replacement_flags != 0:
            raise WorkspaceError("overlay replacement flags must be zero")
        if (
            self.expected_ram_size,
            self.expected_bss_size,
        ) == (
            self.replacement_ram_size,
            self.replacement_bss_size,
        ):
            raise WorkspaceError("overlay replacement geometry must change")
        if self.replacement_ram_size < self.expected_ram_size:
            raise WorkspaceError("overlay replacement RAM size cannot shrink")
        if (
            self.replacement_ram_size + self.replacement_bss_size
            <= self.expected_ram_size + self.expected_bss_size
        ):
            raise WorkspaceError(
                "overlay replacement RAM plus BSS geometry must expand the allocation"
            )


@dataclass(frozen=True)
class BuildOverrides:
    format_version: int
    profile_id: str | None
    raw_nitrofs: tuple[RawNitroFsOverride, ...]
    overlays: tuple[OverlayLayoutOverride, ...]

    def validate(self) -> None:
        if self.format_version != 1:
            raise WorkspaceError(
                f"unsupported build override format version: {self.format_version}"
            )
        _optional_profile_id(self.profile_id)
        raw_ids: set[int] = set()
        raw_paths: set[str] = set()
        for raw_override in self.raw_nitrofs:
            raw_override.validate()
            if raw_override.file_id in raw_ids:
                raise WorkspaceError(f"duplicate raw override file ID: {raw_override.file_id}")
            if raw_override.path in raw_paths:
                raise WorkspaceError(f"duplicate raw override path: {raw_override.path}")
            raw_ids.add(raw_override.file_id)
            raw_paths.add(raw_override.path)
        overlay_ids: set[int] = set()
        for overlay_override in self.overlays:
            overlay_override.validate()
            if overlay_override.overlay_id in overlay_ids:
                raise WorkspaceError(
                    f"duplicate overlay override ID: {overlay_override.overlay_id}"
                )
            overlay_ids.add(overlay_override.overlay_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "profile_id": self.profile_id,
            "raw_nitrofs": [
                asdict(item) for item in sorted(self.raw_nitrofs, key=lambda item: item.file_id)
            ],
            "overlays": [
                asdict(item) for item in sorted(self.overlays, key=lambda item: item.overlay_id)
            ],
        }


def _require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise WorkspaceError(f"{label} must be a JSON object")
    return value


def _require_array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise WorkspaceError(f"{label} must be a JSON array")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkspaceError(f"{label} must be an integer")
    return value


def load_build_overrides(path: Path) -> BuildOverrides | None:
    if not path.exists():
        return None
    try:
        root = _require_object(json.loads(path.read_text(encoding="utf-8")), "build overrides")
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"cannot load build overrides {path}: {exc}") from exc
    try:
        raw = tuple(
            RawNitroFsOverride(
                file_id=_integer(item["file_id"], f"raw_nitrofs[{index}].file_id"),
                path=str(item["path"]),
                expected_size=_integer(
                    item["expected_size"], f"raw_nitrofs[{index}].expected_size"
                ),
                expected_sha256=str(item["expected_sha256"]),
                replacement_size=_integer(
                    item["replacement_size"],
                    f"raw_nitrofs[{index}].replacement_size",
                ),
                replacement_sha256=str(item["replacement_sha256"]),
            )
            for index, value in enumerate(_require_array(root.get("raw_nitrofs"), "raw_nitrofs"))
            for item in (_require_object(value, f"raw_nitrofs[{index}]"),)
        )
        overlays = tuple(
            OverlayLayoutOverride(
                overlay_id=_integer(item["overlay_id"], f"overlays[{index}].overlay_id"),
                expected_ram_size=_integer(
                    item["expected_ram_size"], f"overlays[{index}].expected_ram_size"
                ),
                expected_bss_size=_integer(
                    item["expected_bss_size"], f"overlays[{index}].expected_bss_size"
                ),
                replacement_ram_size=_integer(
                    item["replacement_ram_size"],
                    f"overlays[{index}].replacement_ram_size",
                ),
                replacement_bss_size=_integer(
                    item["replacement_bss_size"],
                    f"overlays[{index}].replacement_bss_size",
                ),
                replacement_flags=_integer(
                    item["replacement_flags"], f"overlays[{index}].replacement_flags"
                ),
            )
            for index, value in enumerate(_require_array(root.get("overlays"), "overlays"))
            for item in (_require_object(value, f"overlays[{index}]"),)
        )
        result = BuildOverrides(
            format_version=_integer(root["format_version"], "format_version"),
            profile_id=_optional_profile_id(root.get("profile_id")),
            raw_nitrofs=tuple(sorted(raw, key=lambda item: item.file_id)),
            overlays=tuple(sorted(overlays, key=lambda item: item.overlay_id)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkspaceError(f"invalid build override field: {exc}") from exc
    result.validate()
    return result


def write_build_overrides(path: Path, overrides: BuildOverrides) -> None:
    overrides.validate()
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        prefix=f".{path.name}.tmp-", dir=path.parent, delete=False
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(
                (json.dumps(overrides.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")
            )
            handle.flush()
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
