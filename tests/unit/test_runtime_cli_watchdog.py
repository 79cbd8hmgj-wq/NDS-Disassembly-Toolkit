from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.runtime_cli as runtime_cli
from nds_disassembly_toolkit.analysis.orchestration import (
    EmulatorKind,
    LaunchSpec,
    RuntimeSessionRecord,
)
from nds_disassembly_toolkit.analysis.orchestration.process import (
    create_session,
    process_is_owned,
    spawn_owned_process,
    stop_owned_process,
)
from nds_disassembly_toolkit.analysis.orchestration.watchdog import (
    load_heartbeat,
    load_watchdog_lease,
    stop_watchdog,
)
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.cli import build_parser

_SLEEPER = "import time; time.sleep(120)"


def _rom(tmp_path: Path) -> Path:
    path = tmp_path / "game.nds"
    path.write_bytes(b"NDS\x00fixture")
    return path


def _running_session(tmp_path: Path) -> RuntimeSessionRecord:
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    return spawn_owned_process(session, LaunchSpec(argv=(sys.executable, "-c", _SLEEPER)))


def test_watchdog_parser_accepts_all_subcommands() -> None:
    parser = build_parser()
    start = parser.parse_args(
        ["runtime", "watchdog", "start", "root", "--interval", "5", "--checkpoint", "last-good"]
    )
    assert start.runtime_watchdog_command == "start"
    assert start.interval == 5.0
    assert start.checkpoint == "last-good"

    stop = parser.parse_args(["runtime", "watchdog", "stop", "root"])
    assert stop.runtime_watchdog_command == "stop"

    status = parser.parse_args(["runtime", "watchdog", "status", "root"])
    assert status.runtime_watchdog_command == "status"

    run = parser.parse_args(["runtime", "watchdog", "run", "root", "--max-ticks", "3"])
    assert run.runtime_watchdog_command == "run"
    assert run.max_ticks == 3


def test_watchdog_status_with_no_heartbeat_reports_none(tmp_path: Path) -> None:
    arguments = build_parser().parse_args(["runtime", "watchdog", "status", str(tmp_path)])
    assert runtime_cli.run_runtime_command(arguments) == 0


def test_watchdog_stop_with_no_lease_is_a_no_op(tmp_path: Path) -> None:
    arguments = build_parser().parse_args(["runtime", "watchdog", "stop", str(tmp_path)])
    assert runtime_cli.run_runtime_command(arguments) == 0


def test_watchdog_run_bounded_ticks_reports_healthy_heartbeat(tmp_path: Path) -> None:
    running = _running_session(tmp_path)
    try:
        arguments = build_parser().parse_args(
            [
                "runtime",
                "watchdog",
                "run",
                str(running.session_root),
                "--interval",
                "0.01",
                "--max-ticks",
                "3",
            ]
        )
        assert runtime_cli.run_runtime_command(arguments) == 0

        heartbeat = load_heartbeat(running.session_root)
        assert heartbeat is not None
        assert heartbeat.process_alive is True
        assert heartbeat.healthy is True
    finally:
        stop_owned_process(running, grace_seconds=1.0)


def test_watchdog_run_relaunches_a_dead_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running = _running_session(tmp_path)
    original_pid = running.pid
    assert original_pid is not None
    os.kill(original_pid, signal.SIGKILL)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and process_is_owned(running):
        time.sleep(0.01)
    assert process_is_owned(running) is False

    class RelaunchBackend:
        def build_launch_spec(self, **kwargs: object) -> LaunchSpec:
            return LaunchSpec(argv=(sys.executable, "-c", _SLEEPER))

    monkeypatch.setattr(runtime_cli, "_managed_backend", lambda kind: RelaunchBackend())

    arguments = build_parser().parse_args(
        [
            "runtime",
            "watchdog",
            "run",
            str(running.session_root),
            "--interval",
            "0.02",
            "--max-ticks",
            "6",
        ]
    )
    assert runtime_cli.run_runtime_command(arguments) == 0

    recovered = runtime_cli.load_session(running.session_root)
    assert recovered.pid is not None
    assert recovered.pid != original_pid
    assert process_is_owned(recovered) is True
    stop_owned_process(recovered, grace_seconds=1.0)


def test_watchdog_start_stop_full_daemon_lifecycle(tmp_path: Path) -> None:
    running = _running_session(tmp_path)
    try:
        start_arguments = build_parser().parse_args(
            [
                "runtime",
                "watchdog",
                "start",
                str(running.session_root),
                "--interval",
                "0.05",
            ]
        )
        assert runtime_cli.run_runtime_command(start_arguments) == 0

        lease = load_watchdog_lease(running.session_root)
        assert lease is not None

        heartbeat = None
        for _ in range(200):
            heartbeat = load_heartbeat(running.session_root)
            if heartbeat is not None:
                break
            time.sleep(0.02)
        assert heartbeat is not None
        assert heartbeat.healthy is True

        assert stop_watchdog(running.session_root, grace_seconds=2.0) is True
        assert load_watchdog_lease(running.session_root) is None
    finally:
        stop_owned_process(runtime_cli.load_session(running.session_root), grace_seconds=1.0)
