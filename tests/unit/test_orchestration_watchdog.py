from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration.watchdog import (
    HeartbeatRecord,
    WatchdogLease,
    check_health,
    load_heartbeat,
    load_watchdog_lease,
    run_watchdog_loop,
    stop_watchdog,
    store_watchdog_lease,
    watchdog_is_owned,
    write_heartbeat,
)
from nds_disassembly_toolkit.errors import RuntimeOrchestrationError


def test_heartbeat_is_healthy_only_when_every_probe_passes() -> None:
    assert HeartbeatRecord(1.0, True, True, True, 0).healthy is True
    assert HeartbeatRecord(1.0, False, True, True, 0).healthy is False
    assert HeartbeatRecord(1.0, True, False, True, 0).healthy is False
    assert HeartbeatRecord(1.0, True, True, False, 0).healthy is False
    # a probe that was never configured (None) does not block health
    assert HeartbeatRecord(1.0, True, None, None, 0).healthy is True


def test_heartbeat_round_trips_through_json(tmp_path: Path) -> None:
    record = HeartbeatRecord(
        timestamp=123.5,
        process_alive=True,
        window_ready=False,
        debugger_reachable=None,
        consecutive_failures=2,
    )
    write_heartbeat(tmp_path, record)
    loaded = load_heartbeat(tmp_path)
    assert loaded == record


def test_load_heartbeat_returns_none_when_absent(tmp_path: Path) -> None:
    assert load_heartbeat(tmp_path) is None


def test_check_health_treats_a_raising_probe_as_failed() -> None:
    def boom() -> bool:
        raise RuntimeError("probe crashed")

    record = check_health(process_alive=boom)
    assert record.process_alive is False
    assert record.healthy is False


def test_check_health_skips_unconfigured_probes() -> None:
    record = check_health(process_alive=lambda: True)
    assert record.window_ready is None
    assert record.debugger_reachable is None
    assert record.healthy is True


def test_check_health_tracks_consecutive_failures_across_calls() -> None:
    first = check_health(process_alive=lambda: False, previous_consecutive_failures=0)
    assert first.consecutive_failures == 1
    second = check_health(
        process_alive=lambda: False,
        previous_consecutive_failures=first.consecutive_failures,
    )
    assert second.consecutive_failures == 2
    recovered = check_health(
        process_alive=lambda: True,
        previous_consecutive_failures=second.consecutive_failures,
    )
    assert recovered.consecutive_failures == 0


def test_run_watchdog_loop_persists_heartbeat_every_tick(tmp_path: Path) -> None:
    ticks_seen: list[int] = []

    def check(previous_failures: int) -> HeartbeatRecord:
        ticks_seen.append(previous_failures)
        return HeartbeatRecord(1.0, True, True, True, 0)

    sleeps: list[float] = []
    ticks = run_watchdog_loop(
        session_root=tmp_path,
        check=check,
        interval=5.0,
        max_ticks=3,
        sleep=sleeps.append,
    )

    assert ticks == 3
    assert len(ticks_seen) == 3
    assert sleeps == [5.0, 5.0]  # no sleep after the final tick
    assert load_heartbeat(tmp_path) is not None


def test_run_watchdog_loop_calls_on_unhealthy_only_when_unhealthy(tmp_path: Path) -> None:
    healthy_then_dead = iter([True, True, False, False])

    def check(previous_failures: int) -> HeartbeatRecord:
        alive = next(healthy_then_dead)
        return check_health(
            process_alive=lambda: alive,
            previous_consecutive_failures=previous_failures,
        )

    unhealthy_calls: list[HeartbeatRecord] = []
    run_watchdog_loop(
        session_root=tmp_path,
        check=check,
        on_unhealthy=unhealthy_calls.append,
        interval=0.001,
        max_ticks=4,
        sleep=lambda _seconds: None,
    )

    assert len(unhealthy_calls) == 2
    assert unhealthy_calls[0].consecutive_failures == 1
    assert unhealthy_calls[1].consecutive_failures == 2


def test_run_watchdog_loop_stops_immediately_when_should_stop_is_true(
    tmp_path: Path,
) -> None:
    calls = {"n": 0}

    def check(previous_failures: int) -> HeartbeatRecord:
        calls["n"] += 1
        return HeartbeatRecord(1.0, True, None, None, 0)

    ticks = run_watchdog_loop(
        session_root=tmp_path,
        check=check,
        interval=1.0,
        should_stop=lambda: True,
        sleep=lambda _seconds: pytest.fail("must not sleep when already stopped"),
    )

    assert ticks == 0
    assert calls["n"] == 0


def test_run_watchdog_loop_rejects_non_positive_interval(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="interval"):
        run_watchdog_loop(
            session_root=tmp_path,
            check=lambda previous: HeartbeatRecord(1.0, True, None, None, 0),
            interval=0,
        )


def test_watchdog_lease_round_trips(tmp_path: Path) -> None:
    lease = WatchdogLease(
        pid=1234,
        process_group=1234,
        start_identity="abc",
        executable=Path("/usr/bin/python3"),
    )
    store_watchdog_lease(tmp_path, lease)
    assert load_watchdog_lease(tmp_path) == lease


def test_load_watchdog_lease_returns_none_when_absent(tmp_path: Path) -> None:
    assert load_watchdog_lease(tmp_path) is None


def test_stop_watchdog_is_a_no_op_when_no_lease_exists(tmp_path: Path) -> None:
    assert stop_watchdog(tmp_path) is False


def test_stop_watchdog_terminates_the_owned_process(tmp_path: Path) -> None:
    import subprocess

    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        start_new_session=True,
    )
    try:
        for _ in range(200):
            try:
                text = Path(f"/proc/{process.pid}/stat").read_text(encoding="utf-8")
                close = text.rfind(")")
                fields = text[close + 2 :].split()
                start_identity = fields[19]
                break
            except (OSError, IndexError):
                time.sleep(0.01)
        else:
            raise AssertionError("could not read process start identity")

        lease = WatchdogLease(
            pid=process.pid,
            process_group=os.getpgid(process.pid),
            start_identity=start_identity,
            executable=Path(sys.executable).resolve(),
        )
        store_watchdog_lease(tmp_path, lease)
        assert watchdog_is_owned(lease) is True

        assert stop_watchdog(tmp_path, grace_seconds=1.0) is True
        assert watchdog_is_owned(lease) is False
        assert load_watchdog_lease(tmp_path) is None
    finally:
        with __import__("contextlib").suppress(Exception):
            process.kill()
            process.wait(timeout=5)


def test_stop_watchdog_raises_when_signalling_an_owned_process_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = WatchdogLease(
        pid=os.getpid(),
        process_group=os.getpgid(0),
        start_identity="whatever",
        executable=Path("/usr/bin/fake"),
    )
    store_watchdog_lease(tmp_path, lease)
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.watchdog.watchdog_is_owned",
        lambda lease: True,
    )

    def deny_signal(pgid: int, sig: int) -> None:
        raise OSError("operation not permitted")

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.watchdog.os.killpg",
        deny_signal,
    )

    with pytest.raises(RuntimeOrchestrationError, match="failed to signal"):
        stop_watchdog(tmp_path)


def test_stop_watchdog_refuses_to_signal_a_pid_reused_by_another_process(
    tmp_path: Path,
) -> None:
    fake_lease = WatchdogLease(
        pid=os.getpid(),
        process_group=os.getpgid(0),
        start_identity="definitely-not-the-real-start-identity",
        executable=Path("/usr/bin/nonexistent-fake-watchdog"),
    )
    store_watchdog_lease(tmp_path, fake_lease)

    # ownership cannot be proven, so this must be a silent no-op, never a
    # real signal to whatever process now happens to hold that lease
    assert stop_watchdog(tmp_path) is False
    assert load_watchdog_lease(tmp_path) is None
