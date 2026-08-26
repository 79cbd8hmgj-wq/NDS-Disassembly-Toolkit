from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.source_patch import SourceHook, encode_hook, load_source_patch_manifest


TARGET_HASH = hashlib.sha256(b"target").hexdigest()


def _payload() -> dict[str, object]:
    return {
        "format_version": 1,
        "target": "overlay:7",
        "runtime_address": 0x0221A000,
        "max_size": 0x100,
        "mode": "arm",
        "expected_runtime_sha256": TARGET_HASH,
        "sources": ["src/injected.c"],
        "definitions": {"known_helper": 0x02065BF4},
        "hooks": [],
    }


def _write(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "source-patch.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_manifest_allows_profile_free_patch(tmp_path: Path) -> None:
    manifest = load_source_patch_manifest(_write(tmp_path, _payload()))

    assert manifest.profile_id is None
    assert manifest.target == "overlay:7"
    assert manifest.sources == ("src/injected.c",)
    assert manifest.definitions == (("known_helper", 0x02065BF4),)


def test_manifest_preserves_optional_consumer_profile_id(tmp_path: Path) -> None:
    payload = _payload()
    payload["profile_id"] = "example_rev0"

    manifest = load_source_patch_manifest(_write(tmp_path, payload))

    assert manifest.profile_id == "example_rev0"


def test_manifest_rejects_source_path_traversal(tmp_path: Path) -> None:
    payload = _payload()
    payload["sources"] = ["../escape.c"]

    with pytest.raises(WorkspaceError, match="unsafe path"):
        load_source_patch_manifest(_write(tmp_path, payload))


def test_manifest_rejects_cross_state_hook_without_veneer(tmp_path: Path) -> None:
    payload = _payload()
    payload["mode"] = "thumb"
    payload["hooks"] = [
        {
            "id": "entry",
            "runtime_address": 0x0221B000,
            "expected": "000000ea",
            "symbol": "entry",
            "link": True,
            "mode": "arm",
        }
    ]

    with pytest.raises(WorkspaceError, match="interworking veneer"):
        load_source_patch_manifest(_write(tmp_path, payload))


def _hook(*, mode: str, link: bool, size: int, address: int) -> SourceHook:
    return SourceHook("hook", address, b"\x00" * size, "entry", link, mode)


def test_arm_and_thumb_hook_encodings_match_verified_vectors() -> None:
    assert encode_hook(
        _hook(mode="arm", link=False, size=4, address=0x0221B000), 0x0221A000
    ) == bytes.fromhex("fefbffea")
    assert encode_hook(
        _hook(mode="arm", link=True, size=4, address=0x0221B000), 0x0221A000
    ) == bytes.fromhex("fefbffeb")
    assert encode_hook(
        _hook(mode="thumb", link=False, size=2, address=0x1000), 0x1100
    ) == bytes.fromhex("7ee0")
    assert encode_hook(
        _hook(mode="thumb", link=True, size=4, address=0x1000), 0x1100
    ) == bytes.fromhex("00f07ef8")


def test_hook_encoding_rejects_unaligned_or_wrong_guard_size() -> None:
    with pytest.raises(WorkspaceError, match="aligned"):
        encode_hook(_hook(mode="thumb", link=False, size=2, address=0x1000), 0x1101)
    with pytest.raises(WorkspaceError, match="guard length"):
        encode_hook(_hook(mode="arm", link=True, size=2, address=0x0221B000), 0x0221A000)
