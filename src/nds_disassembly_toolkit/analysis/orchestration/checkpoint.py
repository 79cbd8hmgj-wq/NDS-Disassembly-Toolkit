from __future__ import annotations

import hashlib
import json
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.orchestration.model import (
    CHECKPOINT_SCHEMA_VERSION,
    EmulatorKind,
)
from nds_disassembly_toolkit.errors import RuntimeCheckpointError

_HEX_DIGITS = frozenset("0123456789abcdef")


class CheckpointBackend(Protocol):
    def save_state(self, destination: Path) -> None: ...

    def load_state(self, source: Path) -> None: ...


class CheckpointPredicate(Protocol):
    def evaluate(self, context: object) -> bool: ...


@dataclass(frozen=True, slots=True)
class CheckpointContext:
    checkpoint_root: Path
    emulator: EmulatorKind
    rom_sha256: str
    backend: CheckpointBackend
    battery_save: Path | None = None

    def __post_init__(self) -> None:
        if len(self.rom_sha256) != 64 or any(
            character not in _HEX_DIGITS for character in self.rom_sha256
        ):
            raise ValueError("ROM SHA-256 must be 64 lowercase hexadecimal characters")


@dataclass(frozen=True, slots=True)
class CheckpointMemoryFingerprint:
    address: int
    length: int
    sha256: str


@dataclass(frozen=True, slots=True)
class CheckpointMetadata:
    schema_version: int
    name: str
    emulator: EmulatorKind
    rom_sha256: str
    state_filename: str
    state_sha256: str
    battery_save_filename: str | None = None
    battery_save_sha256: str | None = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise RuntimeCheckpointError(f"cannot read checkpoint state: {path}") from exc
    return digest.hexdigest()


def _validate_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or Path(name).name != name
    ):
        raise RuntimeCheckpointError("checkpoint name must be one safe path component")


def _metadata_json(metadata: CheckpointMetadata) -> dict[str, object]:
    return {
        "schema_version": metadata.schema_version,
        "name": metadata.name,
        "emulator": metadata.emulator.value,
        "rom_sha256": metadata.rom_sha256,
        "state_filename": metadata.state_filename,
        "state_sha256": metadata.state_sha256,
        "battery_save_filename": metadata.battery_save_filename,
        "battery_save_sha256": metadata.battery_save_sha256,
    }


def _store_metadata(path: Path, metadata: CheckpointMetadata) -> None:
    temporary = path / "checkpoint.json.tmp"
    temporary.write_text(
        json.dumps(_metadata_json(metadata), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path / "checkpoint.json")


def _load_metadata(path: Path) -> CheckpointMetadata:
    try:
        payload = json.loads((path / "checkpoint.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeCheckpointError("checkpoint metadata is missing or malformed") from exc
    if not isinstance(payload, dict):
        raise RuntimeCheckpointError("checkpoint metadata must be a JSON object")
    try:
        schema_version = int(payload["schema_version"])
        name = str(payload["name"])
        emulator = EmulatorKind(str(payload["emulator"]))
        rom_sha256 = str(payload["rom_sha256"])
        state_filename = str(payload["state_filename"])
        state_sha256 = str(payload["state_sha256"])
        battery_filename_value = payload.get("battery_save_filename")
        battery_hash_value = payload.get("battery_save_sha256")
        battery_save_filename = (
            None if battery_filename_value is None else str(battery_filename_value)
        )
        battery_save_sha256 = (
            None if battery_hash_value is None else str(battery_hash_value)
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeCheckpointError("checkpoint metadata is incomplete or invalid") from exc
    if schema_version != CHECKPOINT_SCHEMA_VERSION:
        raise RuntimeCheckpointError(
            f"unsupported checkpoint schema version: {schema_version}"
        )
    _validate_name(name)
    _validate_name(state_filename)
    if battery_save_filename is not None:
        _validate_name(battery_save_filename)
    if (battery_save_filename is None) != (battery_save_sha256 is None):
        raise RuntimeCheckpointError("checkpoint battery-save metadata is incomplete")
    return CheckpointMetadata(
        schema_version=schema_version,
        name=name,
        emulator=emulator,
        rom_sha256=rom_sha256,
        state_filename=state_filename,
        state_sha256=state_sha256,
        battery_save_filename=battery_save_filename,
        battery_save_sha256=battery_save_sha256,
    )


def create_checkpoint(
    context: CheckpointContext,
    name: str,
    *,
    verification_regions: tuple[CheckpointMemoryFingerprint, ...] = (),
) -> Path:
    del verification_regions
    _validate_name(name)
    root = context.checkpoint_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = root / name
    if destination.exists():
        raise RuntimeCheckpointError(f"checkpoint already exists: {name}")

    temporary = root / f".{name}.tmp-{secrets.token_hex(8)}"
    temporary.mkdir()
    try:
        state = temporary / "state.bin"
        context.backend.save_state(state)
        if not state.is_file():
            raise RuntimeCheckpointError("backend did not create checkpoint state")
        battery_save_filename: str | None = None
        battery_save_sha256: str | None = None
        if context.battery_save is not None:
            source = context.battery_save.expanduser().resolve()
            if source.is_file():
                battery_save_filename = "battery-save.bin"
                battery_destination = temporary / battery_save_filename
                shutil.copyfile(source, battery_destination)
                battery_save_sha256 = _sha256(battery_destination)

        metadata = CheckpointMetadata(
            schema_version=CHECKPOINT_SCHEMA_VERSION,
            name=name,
            emulator=context.emulator,
            rom_sha256=context.rom_sha256,
            state_filename="state.bin",
            state_sha256=_sha256(state),
            battery_save_filename=battery_save_filename,
            battery_save_sha256=battery_save_sha256,
        )
        _store_metadata(temporary, metadata)
        temporary.replace(destination)
    except BaseException:
        if temporary.exists():
            for child in temporary.iterdir():
                if child.is_file():
                    child.unlink()
            temporary.rmdir()
        raise
    return destination


def validate_checkpoint(
    path: Path,
    context: CheckpointContext,
) -> CheckpointMetadata:
    resolved = path.expanduser().resolve()
    metadata = _load_metadata(resolved)
    if metadata.rom_sha256 != context.rom_sha256:
        raise RuntimeCheckpointError("checkpoint ROM identity does not match")
    if metadata.emulator is not context.emulator:
        raise RuntimeCheckpointError("checkpoint emulator does not match")
    state = resolved / metadata.state_filename
    if _sha256(state) != metadata.state_sha256:
        raise RuntimeCheckpointError("checkpoint state hash does not match")
    if metadata.battery_save_filename is not None:
        battery = resolved / metadata.battery_save_filename
        if _sha256(battery) != metadata.battery_save_sha256:
            raise RuntimeCheckpointError("checkpoint battery-save hash does not match")
    return metadata


def restore_checkpoint(
    context: CheckpointContext,
    path: Path,
    *,
    predicates: tuple[CheckpointPredicate, ...] = (),
) -> None:
    metadata = validate_checkpoint(path, context)
    resolved = path.expanduser().resolve()
    state = resolved / metadata.state_filename
    if (
        metadata.battery_save_filename is not None
        and context.battery_save is not None
    ):
        destination = context.battery_save.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved / metadata.battery_save_filename, destination)
    context.backend.load_state(state)
    for predicate in predicates:
        if not predicate.evaluate(context):
            raise RuntimeCheckpointError("checkpoint restore verification failed")
