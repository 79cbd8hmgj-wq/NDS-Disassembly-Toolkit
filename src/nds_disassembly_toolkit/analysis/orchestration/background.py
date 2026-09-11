from __future__ import annotations

import os
import signal
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration.process import (
    _linux_process_executable,
    _linux_process_start_identity,
)
from nds_disassembly_toolkit.errors import RuntimeLaunchError, RuntimeOrchestrationError


@dataclass(frozen=True, slots=True)
class DetachedProcessLease:
    pid: int
    process_group: int
    start_identity: str
    executable: Path


def spawn_detached_process(
    argv: list[str],
    *,
    log_path: Path,
    establish_timeout: float = 5.0,
) -> DetachedProcessLease:
    """Launch ``argv`` as a fully detached background process (its own
    session and process group, stdout/stderr redirected to ``log_path``) and
    prove ownership of the resulting PID before returning.

    This is the same ownership-establishment discipline used for managed
    emulator processes (``process.spawn_owned_process``) and managed X11
    displays (``x11.start_x11_display``): a caller must never assume a freshly
    launched PID is really its own child without checking, since a PID can be
    reused by an unrelated process the instant the real child exits.
    """
    if establish_timeout <= 0:
        raise ValueError("establish_timeout must be positive")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("ab") as log:
            process = subprocess.Popen(
                argv,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
    except OSError as exc:
        raise RuntimeLaunchError(f"failed to launch detached process: {exc}") from exc

    start_identity: str | None = None
    process_group: int | None = None
    deadline = time.monotonic() + establish_timeout
    while time.monotonic() < deadline:
        start_identity = _linux_process_start_identity(process.pid)
        try:
            process_group = os.getpgid(process.pid)
        except OSError:
            process_group = None
        if start_identity is not None and process_group is not None:
            break
        if process.poll() is not None:
            break
        time.sleep(0.001)

    if start_identity is None or process_group is None:
        with suppress(OSError):
            process.terminate()
        raise RuntimeLaunchError("detached process exited before ownership was established")

    resolved_executable = Path(argv[0])
    if resolved_executable.is_absolute() or "/" in argv[0]:
        resolved_executable = resolved_executable.resolve()
    else:
        # argv[0] was a bare command name resolved via PATH by the shell/exec;
        # read back what actually got exec'd instead of guessing.
        actual = _linux_process_executable(process.pid)
        resolved_executable = actual if actual is not None else resolved_executable

    return DetachedProcessLease(
        pid=process.pid,
        process_group=process_group,
        start_identity=start_identity,
        executable=resolved_executable,
    )


def detached_process_is_owned(lease: DetachedProcessLease) -> bool:
    if _linux_process_start_identity(lease.pid) != lease.start_identity:
        return False
    executable = _linux_process_executable(lease.pid)
    if executable is None or executable != lease.executable:
        return False
    try:
        return os.getpgid(lease.pid) == lease.process_group
    except OSError:
        return False


def stop_detached_process(
    lease: DetachedProcessLease,
    *,
    grace_seconds: float = 2.0,
) -> bool:
    """Stop an owned detached process. Returns False (a no-op) if ownership
    of the lease's PID can no longer be proven, so this can never signal an
    unrelated process that has since reused the same PID."""
    if grace_seconds < 0:
        raise ValueError("grace_seconds must be non-negative")
    if not detached_process_is_owned(lease):
        return False
    try:
        os.killpg(lease.process_group, signal.SIGTERM)
    except OSError as exc:
        raise RuntimeOrchestrationError("failed to signal owned detached process") from exc
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if not detached_process_is_owned(lease):
            return True
        time.sleep(0.01)
    if detached_process_is_owned(lease):
        with suppress(OSError):
            os.killpg(lease.process_group, signal.SIGKILL)
    return True
