from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration.input import WindowGeometry
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


_DISPLAY_LEASE_FILENAME = "x11-display.json"


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



def _display_lease_path(session_root: Path) -> Path:
    return session_root / "display.json"


def store_x11_display_lease(
    session_root: Path,
    lease: X11DisplayLease,
) -> None:
    path = _display_lease_path(session_root)
    temporary = path.with_suffix(".json.tmp")
    payload = {
        "display_number": lease.display_number,
        "pid": lease.pid,
        "process_group": lease.process_group,
        "start_identity": lease.start_identity,
        "executable": str(lease.executable),
    }
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def load_x11_display_lease(session_root: Path) -> X11DisplayLease | None:
    path = _display_lease_path(session_root)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("display lease must be an object")
        return X11DisplayLease(
            display_number=int(payload["display_number"]),
            pid=int(payload["pid"]),
            process_group=int(payload["process_group"]),
            start_identity=str(payload["start_identity"]),
            executable=Path(str(payload["executable"])).resolve(),
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeDisplayError("managed X11 display lease is invalid") from exc


def remove_x11_display_lease(session_root: Path) -> None:
    with suppress(FileNotFoundError):
        _display_lease_path(session_root).unlink()


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

    def __init__(
        self,
        *,
        xdotool: Path,
        capture_tool: Path | None = None,
        display: str | None = None,
    ) -> None:
        self.xdotool = xdotool
        self.capture_tool = capture_tool
        self.display = display

    def _display_environment(
        self,
        session: RuntimeSessionRecord | None = None,
    ) -> dict[str, str]:
        display = self.display
        if session is not None and session.display is not None:
            display = session.display
        if display is None:
            raise RuntimeInputError("managed X11 operation requires a DISPLAY")
        environment = os.environ.copy()
        environment["DISPLAY"] = display
        return environment

    def _window_pid(self, window_id: str) -> int | None:
        completed = subprocess.run(
            [str(self.xdotool), "getwindowpid", window_id],
            check=False,
            capture_output=True,
            text=True,
            env=(
                None
                if self.display is None
                else {**os.environ, "DISPLAY": self.display}
            ),
        )
        if completed.returncode != 0:
            return None
        try:
            return int(completed.stdout.strip())
        except ValueError:
            return None

    def wait_for_window(
        self,
        session: RuntimeSessionRecord,
        *,
        timeout: float,
    ) -> str:
        if timeout <= 0:
            raise RuntimeInputError("window discovery timeout must be positive")
        if session.pid is None:
            raise RuntimeInputError("managed session has no emulator process")
        environment = self._display_environment(session)
        deadline = time.monotonic() + timeout
        while True:
            completed = subprocess.run(
                [
                    str(self.xdotool),
                    "search",
                    "--onlyvisible",
                    "--pid",
                    str(session.pid),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            if completed.returncode == 0:
                candidates = [
                    line.strip()
                    for line in completed.stdout.splitlines()
                    if line.strip()
                ]
                for window_id in candidates:
                    if self._window_pid(window_id) == session.pid:
                        return window_id
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.01, remaining))
        raise RuntimeInputError("owned emulator window did not become ready")

    def window_geometry(self, session: RuntimeSessionRecord) -> WindowGeometry:
        window_id = self._require_owned_window(session)
        completed = subprocess.run(
            [
                str(self.xdotool),
                "getwindowgeometry",
                "--shell",
                window_id,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._display_environment(session),
        )
        if completed.returncode != 0:
            raise RuntimeInputError("failed to query owned emulator window geometry")
        values: dict[str, int] = {}
        for line in completed.stdout.splitlines():
            name, separator, raw_value = line.partition("=")
            if not separator or name not in {"X", "Y", "WIDTH", "HEIGHT"}:
                continue
            try:
                values[name] = int(raw_value, 0)
            except ValueError as exc:
                raise RuntimeInputError(
                    "owned emulator window geometry is malformed"
                ) from exc
        if set(values) != {"X", "Y", "WIDTH", "HEIGHT"}:
            raise RuntimeInputError("owned emulator window geometry is incomplete")
        try:
            return WindowGeometry(
                x=values["X"],
                y=values["Y"],
                width=values["WIDTH"],
                height=values["HEIGHT"],
            )
        except ValueError as exc:
            raise RuntimeInputError("owned emulator window geometry is invalid") from exc

    def window_is_owned(self, session: RuntimeSessionRecord) -> bool:
        pid = session.pid
        window_id = session.window_id
        if pid is None or window_id is None:
            return False
        return self._window_pid(window_id) == pid

    def _require_owned_window(self, session: RuntimeSessionRecord) -> str:
        window_id = session.window_id
        if window_id is None or not self.window_is_owned(session):
            raise RuntimeInputError("window is not owned by the managed emulator process")
        return window_id

    def _focus_owned_window(self, session: RuntimeSessionRecord) -> str:
        window_id = self._require_owned_window(session)
        subprocess.run(
            [str(self.xdotool), "windowfocus", "--sync", window_id],
            check=True,
            env=self._display_environment(session),
        )
        return window_id

    def key_down(self, session: RuntimeSessionRecord, host_key: str) -> None:
        if not host_key:
            raise RuntimeInputError("host key must not be empty")
        self._focus_owned_window(session)
        subprocess.run(
            [str(self.xdotool), "keydown", host_key],
            check=True,
            env=self._display_environment(session),
        )

    def key_up(self, session: RuntimeSessionRecord, host_key: str) -> None:
        if not host_key:
            raise RuntimeInputError("host key must not be empty")
        self._focus_owned_window(session)
        subprocess.run(
            [str(self.xdotool), "keyup", host_key],
            check=True,
            env=self._display_environment(session),
        )

    def send_key(self, session: RuntimeSessionRecord, host_key: str) -> None:
        if not host_key:
            raise RuntimeInputError("host key must not be empty")
        self._focus_owned_window(session)
        subprocess.run(
            [str(self.xdotool), "key", host_key],
            check=True,
            env=self._display_environment(session),
        )


    def move_pointer(
        self,
        session: RuntimeSessionRecord,
        x: int,
        y: int,
    ) -> None:
        window_id = self._require_owned_window(session)
        subprocess.run(
            [
                str(self.xdotool),
                "mousemove",
                "--window",
                window_id,
                str(x),
                str(y),
            ],
            check=True,
            env=self._display_environment(session),
        )

    def pointer_down(
        self,
        session: RuntimeSessionRecord,
        *,
        button: int = 1,
    ) -> None:
        self._require_owned_window(session)
        if button <= 0:
            raise RuntimeInputError("pointer button must be positive")
        subprocess.run(
            [str(self.xdotool), "mousedown", str(button)],
            check=True,
            env=self._display_environment(session),
        )

    def pointer_up(
        self,
        session: RuntimeSessionRecord,
        *,
        button: int = 1,
    ) -> None:
        self._require_owned_window(session)
        if button <= 0:
            raise RuntimeInputError("pointer button must be positive")
        subprocess.run(
            [str(self.xdotool), "mouseup", str(button)],
            check=True,
            env=self._display_environment(session),
        )

    def capture_window(
        self,
        session: RuntimeSessionRecord,
        destination: Path,
    ) -> None:
        window_id = self._require_owned_window(session)
        if self.capture_tool is None:
            raise RuntimeInputError("X11 capture tool is unavailable")
        destination.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                str(self.capture_tool),
                "-window",
                window_id,
                str(destination),
            ],
            check=True,
            env=self._display_environment(session),
        )
