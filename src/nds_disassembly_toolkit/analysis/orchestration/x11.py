from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration.model import RuntimeSessionRecord
from nds_disassembly_toolkit.analysis.orchestration.process import (
    _linux_process_executable,
    _linux_process_start_identity,
)
from nds_disassembly_toolkit.errors import RuntimeDisplayError, RuntimeInputError


@dataclass(frozen=True, slots=True)
class X11Helpers:
    xvfb: Path | None
    xdotool: Path | None


@dataclass(frozen=True, slots=True)
class X11DisplayLease:
    display_number: int
    pid: int
    process_group: int
    start_identity: str
    executable: Path

    @property
    def display(self) -> str:
        return f":{self.display_number}"


def find_x11_helpers() -> X11Helpers:
    xvfb = shutil.which("Xvfb")
    xdotool = shutil.which("xdotool")
    return X11Helpers(
        xvfb=None if xvfb is None else Path(xvfb),
        xdotool=None if xdotool is None else Path(xdotool),
    )


def sanitize_x11_environment(
    environment: Mapping[str, str],
    *,
    display: str,
) -> dict[str, str]:
    result = dict(environment)
    result["DISPLAY"] = display
    result["SDL_VIDEODRIVER"] = "x11"
    return result


def allocate_display_number(
    *,
    socket_dir: Path = Path("/tmp/.X11-unix"),
    start: int = 100,
    stop: int = 199,
) -> int:
    if start < 0 or stop < start:
        raise ValueError("invalid X11 display range")
    for number in range(start, stop + 1):
        if not (socket_dir / f"X{number}").exists():
            return number
    raise RuntimeDisplayError("no free X11 display number is available")


def start_x11_display(
    *,
    socket_dir: Path = Path("/tmp/.X11-unix"),
    start: int = 100,
    stop: int = 199,
) -> X11DisplayLease:
    helpers = find_x11_helpers()
    if helpers.xvfb is None:
        raise RuntimeDisplayError("Xvfb is required for a managed X11 display")
    number = allocate_display_number(socket_dir=socket_dir, start=start, stop=stop)
    process = subprocess.Popen(
        [
            str(helpers.xvfb),
            f":{number}",
            "-screen",
            "0",
            "1024x768x24",
            "-nolisten",
            "tcp",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    start_identity: str | None = None
    process_group: int | None = None
    for _ in range(100):
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
        raise RuntimeDisplayError("Xvfb exited before ownership was established")
    return X11DisplayLease(
        display_number=number,
        pid=process.pid,
        process_group=process_group,
        start_identity=start_identity,
        executable=helpers.xvfb.resolve(),
    )


def _lease_is_owned(lease: X11DisplayLease) -> bool:
    if _linux_process_start_identity(lease.pid) != lease.start_identity:
        return False
    executable = _linux_process_executable(lease.pid)
    if executable is None or executable != lease.executable:
        return False
    try:
        return os.getpgid(lease.pid) == lease.process_group
    except OSError:
        return False


def stop_x11_display(
    lease: X11DisplayLease,
    *,
    grace_seconds: float = 1.0,
) -> None:
    if not _lease_is_owned(lease):
        raise RuntimeDisplayError("Xvfb ownership could not be proven")
    os.killpg(lease.process_group, signal.SIGTERM)
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if _linux_process_start_identity(lease.pid) is None:
            return
        time.sleep(0.01)
    if _lease_is_owned(lease):
        os.killpg(lease.process_group, signal.SIGKILL)



class X11HostDriver:
    """Argument-array X11 input bound to one verified emulator window."""

    def __init__(self, *, xdotool: Path) -> None:
        self.xdotool = xdotool

    def _window_pid(self, window_id: str) -> int | None:
        completed = subprocess.run(
            [str(self.xdotool), "getwindowpid", window_id],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            return None
        try:
            return int(completed.stdout.strip())
        except ValueError:
            return None

    def _require_owned_window(self, session: RuntimeSessionRecord) -> str:
        pid = session.pid
        window_id = session.window_id
        if pid is None or window_id is None:
            raise RuntimeInputError("managed session has no owned emulator window")
        if self._window_pid(window_id) != pid:
            raise RuntimeInputError("window is not owned by the managed emulator process")
        return window_id

    def send_key(self, session: RuntimeSessionRecord, host_key: str) -> None:
        if not host_key:
            raise RuntimeInputError("host key must not be empty")
        window_id = self._require_owned_window(session)
        subprocess.run(
            [str(self.xdotool), "key", "--window", window_id, host_key],
            check=True,
        )
