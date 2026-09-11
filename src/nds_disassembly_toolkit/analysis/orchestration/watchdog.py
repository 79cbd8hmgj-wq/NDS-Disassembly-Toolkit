from __future__ import annotations

import json
import os
import signal
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration.process import (
    _linux_process_executable,
    _linux_process_start_identity,
)
from nds_disassembly_toolkit.errors import RuntimeOrchestrationError

_HEARTBEAT_FILENAME = "heartbeat.json"
_WATCHDOG_LEASE_FILENAME = "watchdog.json"


@dataclass(frozen=True, slots=True)
class HeartbeatRecord:
    """One point-in-time health observation of a managed runtime session."""

    timestamp: float
    process_alive: bool
    window_ready: bool | None
    debugger_reachable: bool | None
    consecutive_failures: int

    @property
    def healthy(self) -> bool:
        if not self.process_alive:
            return False
        if self.window_ready is False:
            return False
        return self.debugger_reachable is not False


def _heartbeat_path(session_root: Path) -> Path:
    return session_root / _HEARTBEAT_FILENAME


def write_heartbeat(session_root: Path, record: HeartbeatRecord) -> None:
    path = _heartbeat_path(session_root)
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload = {
        "timestamp": record.timestamp,
        "process_alive": record.process_alive,
        "window_ready": record.window_ready,
        "debugger_reachable": record.debugger_reachable,
        "consecutive_failures": record.consecutive_failures,
        "healthy": record.healthy,
    }
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_heartbeat(session_root: Path) -> HeartbeatRecord | None:
    path = _heartbeat_path(session_root)
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return HeartbeatRecord(
        timestamp=float(payload["timestamp"]),
        process_alive=bool(payload["process_alive"]),
        window_ready=(
            None if payload["window_ready"] is None else bool(payload["window_ready"])
        ),
        debugger_reachable=(
            None
            if payload["debugger_reachable"] is None
            else bool(payload["debugger_reachable"])
        ),
        consecutive_failures=int(payload["consecutive_failures"]),
    )


def check_health(
    *,
    process_alive: Callable[[], bool],
    window_ready: Callable[[], bool] | None = None,
    debugger_reachable: Callable[[], bool] | None = None,
    previous_consecutive_failures: int = 0,
    now: Callable[[], float] = time.time,
) -> HeartbeatRecord:
    """Run the configured probes once and return the resulting heartbeat.

    Each probe is independently optional (some sessions have no window to
    check, e.g. a headless melonDS session) and independently best-effort: a
    probe callable that raises is treated as a failed check rather than
    propagating, since a broken health check must never crash the watchdog
    loop that depends on it.
    """

    def _safe(probe: Callable[[], bool] | None) -> bool | None:
        if probe is None:
            return None
        try:
            return bool(probe())
        except Exception:
            return False

    alive = _safe(process_alive)
    record = HeartbeatRecord(
        timestamp=now(),
        process_alive=bool(alive),
        window_ready=_safe(window_ready),
        debugger_reachable=_safe(debugger_reachable),
        consecutive_failures=0,
    )
    failures = 0 if record.healthy else previous_consecutive_failures + 1
    return HeartbeatRecord(
        timestamp=record.timestamp,
        process_alive=record.process_alive,
        window_ready=record.window_ready,
        debugger_reachable=record.debugger_reachable,
        consecutive_failures=failures,
    )


def run_watchdog_loop(
    *,
    session_root: Path,
    check: Callable[[int], HeartbeatRecord],
    on_unhealthy: Callable[[HeartbeatRecord], None] | None = None,
    interval: float,
    should_stop: Callable[[], bool] = lambda: False,
    max_ticks: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Poll ``check`` on a fixed interval, persisting a heartbeat every tick
    and invoking ``on_unhealthy`` whenever the observed state is unhealthy.

    ``check`` receives the previous tick's consecutive-failure count so
    callers can build backoff or "only recover after N failures" policies
    without the loop itself needing to know about recovery semantics.

    Returns the number of ticks executed. Bounded by ``max_ticks`` (for
    tests and bounded scenarios) and/or ``should_stop()`` (for a real
    daemon watching for a shutdown signal); an unbounded loop with a
    should_stop that always answers False runs until interrupted.
    """
    if interval <= 0:
        raise ValueError("watchdog interval must be positive")
    ticks = 0
    consecutive_failures = 0
    while not should_stop() and (max_ticks is None or ticks < max_ticks):
        heartbeat = check(consecutive_failures)
        consecutive_failures = heartbeat.consecutive_failures
        write_heartbeat(session_root, heartbeat)
        if not heartbeat.healthy and on_unhealthy is not None:
            on_unhealthy(heartbeat)
        ticks += 1
        if should_stop() or (max_ticks is not None and ticks >= max_ticks):
            break
        sleep(interval)
    return ticks


@dataclass(frozen=True, slots=True)
class WatchdogLease:
    pid: int
    process_group: int
    start_identity: str
    executable: Path


def _lease_path(session_root: Path) -> Path:
    return session_root / _WATCHDOG_LEASE_FILENAME


def store_watchdog_lease(session_root: Path, lease: WatchdogLease) -> None:
    path = _lease_path(session_root)
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload = {
        "pid": lease.pid,
        "process_group": lease.process_group,
        "start_identity": lease.start_identity,
        "executable": str(lease.executable),
    }
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_watchdog_lease(session_root: Path) -> WatchdogLease | None:
    path = _lease_path(session_root)
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return WatchdogLease(
        pid=int(payload["pid"]),
        process_group=int(payload["process_group"]),
        start_identity=str(payload["start_identity"]),
        executable=Path(str(payload["executable"])),
    )


def remove_watchdog_lease(session_root: Path) -> None:
    with suppress(FileNotFoundError):
        _lease_path(session_root).unlink()


def watchdog_is_owned(lease: WatchdogLease) -> bool:
    if _linux_process_start_identity(lease.pid) != lease.start_identity:
        return False
    executable = _linux_process_executable(lease.pid)
    if executable is None or executable != lease.executable:
        return False
    try:
        return os.getpgid(lease.pid) == lease.process_group
    except OSError:
        return False


def stop_watchdog(
    session_root: Path,
    *,
    grace_seconds: float = 2.0,
) -> bool:
    """Stop an owned watchdog daemon for this session, if one is running.

    Returns False (a no-op) when no lease exists or the lease is no longer
    owned by a live process bearing the recorded identity - the same
    ownership-proof discipline used for managed emulator processes and X11
    displays, so this can never signal an unrelated reused PID.
    """
    lease = load_watchdog_lease(session_root)
    if lease is None:
        return False
    if not watchdog_is_owned(lease):
        remove_watchdog_lease(session_root)
        return False
    try:
        os.killpg(lease.process_group, signal.SIGTERM)
    except OSError as exc:
        raise RuntimeOrchestrationError(
            "failed to signal owned watchdog process"
        ) from exc
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if not watchdog_is_owned(lease):
            break
        time.sleep(0.01)
    if watchdog_is_owned(lease):
        with suppress(OSError):
            os.killpg(lease.process_group, signal.SIGKILL)
    remove_watchdog_lease(session_root)
    return True
