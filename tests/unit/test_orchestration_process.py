from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration import (
    EmulatorKind,
    LaunchSpec,
    RuntimeLifecycleState,
)
from nds_disassembly_toolkit.analysis.orchestration.process import (
    allocate_loopback_port,
    create_session,
    load_session,
    process_is_owned,
    spawn_owned_process,
    stop_owned_process,
)
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeOwnershipError


def _rom(tmp_path: Path) -> Path:
    path = tmp_path / "game.nds"
    path.write_bytes(b"NDS\x00fixture")
    return path


def test_create_session_uses_unique_directory_and_atomic_manifest(tmp_path: Path) -> None:
    first = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    second = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=tmp_path / "game.nds",
        cpu=RuntimeCpu.ARM9,
    )

    assert first.session_id != second.session_id
    assert len(first.session_id) == 32
    assert all(character in "0123456789abcdef" for character in first.session_id)
    assert first.session_root == tmp_path / first.session_id
    for name in ("saves", "checkpoints", "traces", "cases", "failure"):
        assert (first.session_root / name).is_dir()
    manifest = first.session_root / "session.json"
    assert json.loads(manifest.read_text(encoding="utf-8"))["session_id"] == first.session_id
    assert not (first.session_root / "session.json.tmp").exists()
    assert load_session(first.session_root) == first


def test_allocate_loopback_port_returns_bindable_ephemeral_port() -> None:
    port = allocate_loopback_port()
    assert 1 <= port <= 65535
    with socket.socket() as peer:
        peer.bind(("127.0.0.1", port))


def test_spawned_process_is_owned_and_logs_are_isolated(tmp_path: Path) -> None:
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    launch = LaunchSpec(
        argv=(
            sys.executable,
            "-c",
            "import os,time; print(os.environ['NDS_TEST_TOKEN'], flush=True); time.sleep(60)",
        ),
        environment=(("NDS_TEST_TOKEN", "owned"),),
    )

    running = spawn_owned_process(session, launch)
    try:
        assert running.lifecycle is RuntimeLifecycleState.LAUNCHING
        assert running.pid is not None
        assert running.process_group is not None
        assert running.process_start_identity
        assert process_is_owned(running) is True
        for _ in range(100):
            stdout = running.session_root / "emulator.stdout.log"
            if stdout.exists() and "owned" in stdout.read_text(encoding="utf-8"):
                break
            time.sleep(0.01)
        assert "owned" in stdout.read_text(encoding="utf-8")
    finally:
        closed = stop_owned_process(running, grace_seconds=1.0)
    assert closed.lifecycle is RuntimeLifecycleState.CLOSED
    assert not process_is_owned(closed)


def test_stop_refuses_pid_identity_mismatch(tmp_path: Path) -> None:
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    running = spawn_owned_process(
        session,
        LaunchSpec(argv=(sys.executable, "-c", "import time; time.sleep(60)")),
    )
    assert running.process_start_identity is not None
    bad = running.__class__(
        **{
            field: (
                "definitely-not-the-real-start-id"
                if field == "process_start_identity"
                else getattr(running, field)
            )
            for field in running.__dataclass_fields__
        }
    )
    try:
        assert process_is_owned(bad) is False
        with pytest.raises(RuntimeOwnershipError, match="ownership"):
            stop_owned_process(bad, grace_seconds=0.1)
        assert running.pid is not None
        os.kill(running.pid, 0)
    finally:
        stop_owned_process(running, grace_seconds=1.0)


def test_stop_owned_process_does_not_signal_unrelated_process(tmp_path: Path) -> None:
    import subprocess

    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    running = spawn_owned_process(
        session,
        LaunchSpec(argv=(sys.executable, "-c", "import time; time.sleep(60)")),
    )
    try:
        stop_owned_process(running, grace_seconds=1.0)
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)
