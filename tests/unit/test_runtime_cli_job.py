from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.runtime_cli as runtime_cli
from nds_disassembly_toolkit.analysis.orchestration import EmulatorKind
from nds_disassembly_toolkit.analysis.orchestration.process import create_session
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.cli import build_parser


def _rom(tmp_path: Path) -> Path:
    path = tmp_path / "game.nds"
    path.write_bytes(b"NDS\x00fixture")
    return path


def test_job_parser_accepts_start_status_stop_and_remainder_args() -> None:
    parser = build_parser()
    start = parser.parse_args(
        ["runtime", "job", "start", "job-root", "--", "session", "info", "some-session"]
    )
    assert start.runtime_job_command == "start"
    assert start.job_root == Path("job-root")
    # argparse.REMAINDER consumes the "--" separator itself
    assert start.command == ["session", "info", "some-session"]

    status = parser.parse_args(["runtime", "job", "status", "job-root"])
    assert status.runtime_job_command == "status"

    stop = parser.parse_args(["runtime", "job", "stop", "job-root"])
    assert stop.runtime_job_command == "stop"


def test_job_start_requires_a_wrapped_subcommand(tmp_path: Path) -> None:
    arguments = build_parser().parse_args(["runtime", "job", "start", str(tmp_path / "job")])
    with pytest.raises(ValueError, match="wrapped subcommand"):
        runtime_cli.run_runtime_command(arguments)


def test_job_status_with_no_job_raises(tmp_path: Path) -> None:
    arguments = build_parser().parse_args(["runtime", "job", "status", str(tmp_path)])
    with pytest.raises(ValueError, match="no job recorded"):
        runtime_cli.run_runtime_command(arguments)


def test_job_stop_with_no_job_is_a_no_op(tmp_path: Path) -> None:
    arguments = build_parser().parse_args(["runtime", "job", "stop", str(tmp_path)])
    assert runtime_cli.run_runtime_command(arguments) == 0


def test_job_start_returns_immediately_and_status_reports_completion(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The core deficiency this addresses: a long-running runtime
    subcommand must not block the calling agent. We wrap a cheap-but-real
    subcommand (session info) so the whole start -> poll -> completed cycle
    runs against a real detached process rather than mocks."""
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    job_root = tmp_path / "job"

    start_arguments = build_parser().parse_args(
        [
            "runtime",
            "job",
            "start",
            str(job_root),
            "--",
            "session",
            "info",
            str(session.session_root),
        ]
    )
    start_return = runtime_cli.run_runtime_command(start_arguments)
    assert start_return == 0
    capsys.readouterr()

    status_arguments = build_parser().parse_args(["runtime", "job", "status", str(job_root)])

    status_payload = None
    for _ in range(300):
        runtime_cli.run_runtime_command(status_arguments)
        status_payload = json.loads(capsys.readouterr().out)
        # The child briefly still holds its PID after writing the result
        # file and before fully exiting; wait for both to settle.
        if status_payload["status"] == "completed" and status_payload["running"] is False:
            break
        time.sleep(0.02)

    assert status_payload is not None
    assert status_payload["status"] == "completed"
    assert status_payload["running"] is False
    assert status_payload["result"]["session_id"] == session.session_id
    assert status_payload["argv"] == ["session", "info", str(session.session_root)]


def test_job_start_refuses_to_reuse_a_job_root(tmp_path: Path) -> None:
    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    job_root = tmp_path / "job"
    args = [
        "runtime",
        "job",
        "start",
        str(job_root),
        "--",
        "session",
        "info",
        str(session.session_root),
    ]
    arguments = build_parser().parse_args(args)
    assert runtime_cli.run_runtime_command(arguments) == 0

    with pytest.raises(ValueError, match="already has a job"):
        runtime_cli.run_runtime_command(build_parser().parse_args(args))


def test_job_stop_terminates_a_running_job(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from nds_disassembly_toolkit.analysis.orchestration import LaunchSpec
    from nds_disassembly_toolkit.analysis.orchestration.process import (
        spawn_owned_process,
        stop_owned_process,
    )

    session = create_session(
        tmp_path,
        emulator=EmulatorKind.MELONDS,
        executable=Path(sys.executable),
        rom=_rom(tmp_path),
        cpu=RuntimeCpu.ARM9,
    )
    # Keep the wrapped session's own process alive so the watchdog job stays
    # healthy and never attempts a relaunch - this test is only about
    # `job stop` terminating the job process itself.
    running = spawn_owned_process(
        session, LaunchSpec(argv=(sys.executable, "-c", "import time; time.sleep(120)"))
    )
    job_root = tmp_path / "job"

    # Wrap the watchdog's own "run" loop (bounded only by SIGTERM, not by
    # max-ticks) so there is a genuinely long-lived job process to stop.
    start_arguments = build_parser().parse_args(
        [
            "runtime",
            "job",
            "start",
            str(job_root),
            "--",
            "watchdog",
            "run",
            str(running.session_root),
            "--interval",
            "0.02",
        ]
    )
    try:
        assert runtime_cli.run_runtime_command(start_arguments) == 0
        capsys.readouterr()

        stop_arguments = build_parser().parse_args(["runtime", "job", "stop", str(job_root)])
        assert runtime_cli.run_runtime_command(stop_arguments) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["stopped"] is True
    finally:
        stop_owned_process(running, grace_seconds=1.0)
