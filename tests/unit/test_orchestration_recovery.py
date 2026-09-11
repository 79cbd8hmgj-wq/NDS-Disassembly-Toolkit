from __future__ import annotations

import os
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration import (
    EmulatorKind,
    LaunchSpec,
    RuntimeLifecycleState,
    RuntimeSessionRecord,
)
from nds_disassembly_toolkit.analysis.orchestration.checkpoint import (
    CheckpointContext,
    create_checkpoint,
)
from nds_disassembly_toolkit.analysis.orchestration.process import (
    create_session,
    process_is_owned,
    spawn_owned_process,
    stop_owned_process,
)
from nds_disassembly_toolkit.analysis.orchestration.recovery import (
    recover_session_from_checkpoint,
    relaunch_dead_session,
)
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeRecoveryError


def _rom(tmp_path: Path) -> Path:
    path = tmp_path / "game.nds"
    path.write_bytes(b"NDS\x00fixture")
    return path


_SLEEPER = "import time; time.sleep(60)"


@dataclass
class FakeRecoveryBackend:
    argv: tuple[str, ...] = (sys.executable, "-c", _SLEEPER)

    @property
    def capabilities(self) -> object:
        raise NotImplementedError

    def build_launch_spec(self, **kwargs: object) -> LaunchSpec:
        return LaunchSpec(argv=self.argv)


def _kill_and_wait(record: RuntimeSessionRecord, *, timeout: float = 5.0) -> None:
    pid = record.pid
    assert pid is not None
    os.kill(pid, signal.SIGKILL)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # A SIGKILL'd child is a zombie (still answers kill(pid, 0)) until
        # reaped; process_is_owned() already treats that correctly as dead
        # (its executable can no longer be resolved), so poll that instead
        # of a raw signal-0 probe.
        if not process_is_owned(record):
            return
        time.sleep(0.01)
    raise AssertionError("test process did not die in time")


def test_relaunch_refuses_when_process_is_still_alive(tmp_path: Path) -> None:
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    running = spawn_owned_process(session, LaunchSpec(argv=(sys.executable, "-c", _SLEEPER)))
    try:
        with pytest.raises(RuntimeRecoveryError, match="still alive"):
            relaunch_dead_session(running, FakeRecoveryBackend())
    finally:
        stop_owned_process(running, grace_seconds=1.0)


def test_relaunch_spawns_a_fresh_process_after_death(tmp_path: Path) -> None:
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    running = spawn_owned_process(session, LaunchSpec(argv=(sys.executable, "-c", _SLEEPER)))
    original_pid = running.pid
    assert original_pid is not None
    _kill_and_wait(running)
    assert process_is_owned(running) is False

    recovered = relaunch_dead_session(running, FakeRecoveryBackend())
    try:
        assert recovered.pid is not None
        assert recovered.pid != original_pid
        assert process_is_owned(recovered) is True
        assert recovered.lifecycle is RuntimeLifecycleState.LAUNCHING
        # session identity is preserved across the relaunch
        assert recovered.session_id == running.session_id
        assert recovered.session_root == running.session_root
        assert recovered.debugger_port == running.debugger_port
    finally:
        stop_owned_process(recovered, grace_seconds=1.0)


def test_relaunch_refuses_a_deliberately_closed_session(tmp_path: Path) -> None:
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    running = spawn_owned_process(session, LaunchSpec(argv=(sys.executable, "-c", _SLEEPER)))
    closed = stop_owned_process(running, grace_seconds=1.0)

    with pytest.raises(RuntimeRecoveryError, match="deliberately closed"):
        relaunch_dead_session(closed, FakeRecoveryBackend())


def test_relaunch_works_from_a_failed_lifecycle_state(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.orchestration.process import mark_session_failed

    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    running = spawn_owned_process(session, LaunchSpec(argv=(sys.executable, "-c", _SLEEPER)))
    pid = running.pid
    assert pid is not None
    _kill_and_wait(running)
    failed = mark_session_failed(running)
    assert failed is not None
    assert failed.lifecycle is RuntimeLifecycleState.FAILED

    recovered = relaunch_dead_session(failed, FakeRecoveryBackend())
    try:
        assert process_is_owned(recovered) is True
    finally:
        stop_owned_process(recovered, grace_seconds=1.0)


@dataclass
class FakeCheckpointBackend:
    state: bytes = b"known-good-state"
    loaded: bytes | None = None

    def save_state(self, destination: Path) -> None:
        destination.write_bytes(self.state)

    def load_state(self, source: Path) -> None:
        self.loaded = source.read_bytes()


def test_recover_session_from_checkpoint_relaunches_and_restores(tmp_path: Path) -> None:
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    running = spawn_owned_process(session, LaunchSpec(argv=(sys.executable, "-c", _SLEEPER)))
    pid = running.pid
    assert pid is not None
    _kill_and_wait(running)

    checkpoint_backend = FakeCheckpointBackend()
    checkpoint_context = CheckpointContext(
        checkpoint_root=running.session_root / "checkpoints",
        emulator=EmulatorKind.MELONDS,
        rom_sha256=running.rom_sha256,
        backend=checkpoint_backend,
    )
    checkpoint_path = create_checkpoint(checkpoint_context, "last-good")

    recovered = recover_session_from_checkpoint(
        running,
        FakeRecoveryBackend(),
        checkpoint_context=checkpoint_context,
        checkpoint_path=checkpoint_path,
    )
    try:
        assert process_is_owned(recovered) is True
        assert checkpoint_backend.loaded == b"known-good-state"
    finally:
        stop_owned_process(recovered, grace_seconds=1.0)
