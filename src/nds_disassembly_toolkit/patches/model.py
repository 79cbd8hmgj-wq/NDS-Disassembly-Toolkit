from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.errors import WorkspaceError


@dataclass(frozen=True)
class BinaryPatch:
    patch_id: str
    target: str
    offset: int
    expected: bytes
    replacement: bytes
    rationale: str


@dataclass(frozen=True)
class PatchSet:
    format_version: int
    profile_id: str | None
    patches: tuple[BinaryPatch, ...]


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


def _optional_profile_id(value: object) -> str | None:
    if value is None:
        return None
    result = str(value)
    if not result:
        raise WorkspaceError("profile_id must be null or a nonempty string")
    return result


def _decode_hex(value: object, label: str) -> bytes:
    text = str(value)
    if len(text) == 0 or len(text) % 2 != 0:
        raise WorkspaceError(f"{label} must contain a nonempty even-length hex string")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise WorkspaceError(f"{label} is not valid hexadecimal") from exc


def load_patch_set(path: Path) -> PatchSet:
    try:
        payload = _require_object(
            json.loads(path.read_text(encoding="utf-8")),
            "patch document",
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"cannot load patch file {path}: {exc}") from exc

    try:
        format_version = _integer(payload["format_version"], "format_version")
        profile_id = _optional_profile_id(payload.get("profile_id"))
        raw_patches = _require_array(payload["patches"], "patches")
    except KeyError as exc:
        raise WorkspaceError(f"invalid patch document field: {exc}") from exc

    if format_version != 1:
        raise WorkspaceError(f"unsupported patch format version: {format_version}")
    if not raw_patches:
        raise WorkspaceError("patches must be a nonempty array")

    patches: list[BinaryPatch] = []
    seen_ids: set[str] = set()
    for index, value in enumerate(raw_patches):
        item = _require_object(value, f"patches[{index}]")
        try:
            patch_id = str(item["id"])
            patch_type = str(item["type"])
            target = str(item["target"])
            offset = _integer(item["offset"], f"patches[{index}].offset")
            expected = _decode_hex(item["expected"], f"patches[{index}].expected")
            replacement = _decode_hex(item["replacement"], f"patches[{index}].replacement")
            rationale = str(item.get("rationale", ""))
        except KeyError as exc:
            raise WorkspaceError(f"invalid patches[{index}] field: {exc}") from exc

        if not patch_id or patch_id in seen_ids:
            raise WorkspaceError(f"duplicate or empty patch ID: {patch_id!r}")
        if patch_type != "binary_replace":
            raise WorkspaceError(f"unsupported patch type: {patch_type}")
        if offset < 0:
            raise WorkspaceError(f"patch {patch_id} offset must be nonnegative")
        if len(expected) != len(replacement):
            raise WorkspaceError(
                f"patch {patch_id} expected and replacement must be the same length"
            )

        seen_ids.add(patch_id)
        patches.append(
            BinaryPatch(
                patch_id=patch_id,
                target=target,
                offset=offset,
                expected=expected,
                replacement=replacement,
                rationale=rationale,
            )
        )

    return PatchSet(
        format_version=format_version,
        profile_id=profile_id,
        patches=tuple(patches),
    )
