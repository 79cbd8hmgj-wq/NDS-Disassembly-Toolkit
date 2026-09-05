from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration import EmulatorKind
from nds_disassembly_toolkit.analysis.orchestration.checkpoint import (
    CheckpointContext,
    create_checkpoint,
    restore_checkpoint,
    validate_checkpoint,
)
from nds_disassembly_toolkit.errors import RuntimeCheckpointError


@dataclass
class FakeBackend:
    state: bytes = b"state-v1"
    loaded: bytes | None = None

    def save_state(self, destination: Path) -> None:
        destination.write_bytes(self.state)

    def load_state(self, source: Path) -> None:
        self.loaded = source.read_bytes()


@dataclass
class FakePredicate:
    satisfied: bool

    def evaluate(self, context: object) -> bool:
        return self.satisfied


def _context(tmp_path: Path, *, emulator: EmulatorKind = EmulatorKind.MELONDS) -> CheckpointContext:
    return CheckpointContext(
        checkpoint_root=tmp_path / "checkpoints",
        emulator=emulator,
        rom_sha256="1" * 64,
        backend=FakeBackend(),
    )


def test_checkpoint_name_rejects_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(RuntimeCheckpointError, match="name"):
        create_checkpoint(_context(tmp_path), "../escape")


def test_checkpoint_round_trip_validates_state_hash(tmp_path: Path) -> None:
    context = _context(tmp_path)
    path = create_checkpoint(context, "baseline")
    metadata = validate_checkpoint(path, context)

    assert metadata.emulator is EmulatorKind.MELONDS
    assert metadata.rom_sha256 == "1" * 64
    assert (path / "state.bin").is_file()

    (path / "state.bin").write_bytes(b"tampered")
    with pytest.raises(RuntimeCheckpointError, match="hash"):
        validate_checkpoint(path, context)


def test_checkpoint_rejects_wrong_rom_or_emulator(tmp_path: Path) -> None:
    path = create_checkpoint(_context(tmp_path), "baseline")

    wrong_rom = CheckpointContext(
        checkpoint_root=tmp_path / "checkpoints",
        emulator=EmulatorKind.MELONDS,
        rom_sha256="2" * 64,
        backend=FakeBackend(),
    )
    with pytest.raises(RuntimeCheckpointError, match="ROM"):
        validate_checkpoint(path, wrong_rom)

    wrong_emulator = _context(tmp_path, emulator=EmulatorKind.DESMUME)
    with pytest.raises(RuntimeCheckpointError, match="emulator"):
        validate_checkpoint(path, wrong_emulator)


def test_restore_requires_post_restore_predicates(tmp_path: Path) -> None:
    context = _context(tmp_path)
    path = create_checkpoint(context, "baseline")

    with pytest.raises(RuntimeCheckpointError, match="verification"):
        restore_checkpoint(context, path, predicates=(FakePredicate(False),))

    restore_checkpoint(context, path, predicates=(FakePredicate(True),))
    backend = context.backend
    assert isinstance(backend, FakeBackend)
    assert backend.loaded == b"state-v1"



def test_checkpoint_hashes_and_restores_battery_save(tmp_path: Path) -> None:
    battery = tmp_path / "runtime.sav"
    battery.write_bytes(b"battery-v1")
    context = CheckpointContext(
        checkpoint_root=tmp_path / "checkpoints",
        emulator=EmulatorKind.MELONDS,
        rom_sha256="1" * 64,
        backend=FakeBackend(),
        battery_save=battery,
    )

    path = create_checkpoint(context, "baseline")
    metadata = validate_checkpoint(path, context)

    assert metadata.battery_save_sha256 is not None
    assert (path / "battery-save.bin").read_bytes() == b"battery-v1"

    battery.write_bytes(b"changed-runtime-save")
    restore_checkpoint(context, path)
    assert battery.read_bytes() == b"battery-v1"

    (path / "battery-save.bin").write_bytes(b"tampered")
    with pytest.raises(RuntimeCheckpointError, match="battery"):
        validate_checkpoint(path, context)
