from __future__ import annotations

import shutil
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol, cast

from nds_disassembly_toolkit.analysis.orchestration.model import (
    DoctorCheckResult,
    DoctorReport,
    EmulatorCapabilities,
    EmulatorKind,
    LaunchSpec,
)
from nds_disassembly_toolkit.analysis.orchestration.x11 import CAPTURE_TOOL_CANDIDATES
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeOrchestrationError


class _DoctorBackend(Protocol):
    @property
    def kind(self) -> EmulatorKind: ...

    @property
    def capabilities(self) -> EmulatorCapabilities: ...

    def build_launch_spec(
        self,
        *,
        executable: Path,
        rom: Path,
        cpu: RuntimeCpu,
        debugger_host: str,
        debugger_port: int,
        session_root: Path,
        display: str | None,
    ) -> LaunchSpec: ...

    def connect_debugger(
        self,
        *,
        cpu: RuntimeCpu,
        host: str,
        port: int,
        timeout: float = 5.0,
    ) -> object: ...


def _emulator_names(kind: EmulatorKind) -> tuple[str, ...]:
    if kind is EmulatorKind.MELONDS:
        return ("melonDS", "melonds")
    return ("desmume", "desmume-cli")


def discover_emulator_executable(kind: EmulatorKind) -> Path | None:
    for name in _emulator_names(kind):
        resolved = shutil.which(name)
        if resolved is not None:
            return Path(resolved)
    return None


def _discover_capture_tool() -> Path | None:
    for name in CAPTURE_TOOL_CANDIDATES:
        resolved = shutil.which(name)
        if resolved is not None:
            return Path(resolved)
    return None


def _run_live_probe(
    backend: _DoctorBackend,
    executable: Path,
    rom: Path,
    *,
    require: frozenset[str],
    timeout: float,
) -> list[DoctorCheckResult]:
    """Actually launch the emulator, connect the debugger, and prove the RSP
    handshake works, instead of trusting the backend's static capability
    flags. Always tears the process (and any X11 display it opened) back
    down, whether the probe succeeded or not.
    """
    from nds_disassembly_toolkit.analysis.orchestration.process import (
        create_session,
        spawn_owned_process,
        stop_owned_process,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import (
        X11HostDriver,
        find_x11_helpers,
        start_x11_display,
        stop_x11_display,
    )

    checks: list[DoctorCheckResult] = []
    needs_window = bool(require & {"window_input", "touchscreen_input"})
    cpu = RuntimeCpu.ARM9
    deadline = time.monotonic() + timeout

    with tempfile.TemporaryDirectory(prefix="nds-doctor-") as raw_session_root:
        session_root = Path(raw_session_root)
        display_lease = None
        running = None
        try:
            record = create_session(
                session_root,
                emulator=backend.kind,
                executable=executable,
                rom=rom,
                cpu=cpu,
            )
            display: str | None = None
            if needs_window and backend.capabilities.window_input:
                helpers = find_x11_helpers()
                if helpers.xvfb is not None:
                    display_lease = start_x11_display()
                    display = display_lease.display

            launch = backend.build_launch_spec(
                executable=record.emulator_executable,
                rom=record.rom_path,
                cpu=record.cpu,
                debugger_host=record.debugger_host,
                debugger_port=record.debugger_port,
                session_root=record.session_root,
                display=display,
            )
            running = spawn_owned_process(record, launch)
            checks.append(
                DoctorCheckResult(
                    name="live_launch",
                    passed=True,
                    detail="emulator process launched and ownership was proven",
                )
            )

            if display is not None and backend.capabilities.window_input:
                helpers = find_x11_helpers()
                if helpers.xdotool is None:
                    checks.append(
                        DoctorCheckResult(
                            name="live_window",
                            passed=False,
                            detail="xdotool unavailable; cannot confirm managed window",
                        )
                    )
                else:
                    try:
                        driver = X11HostDriver(xdotool=helpers.xdotool, display=display)
                        remaining = max(deadline - time.monotonic(), 0.1)
                        driver.wait_for_window(running, timeout=remaining)
                        checks.append(
                            DoctorCheckResult(
                                name="live_window",
                                passed=True,
                                detail="managed emulator window appeared",
                            )
                        )
                    except Exception as exc:
                        checks.append(
                            DoctorCheckResult(name="live_window", passed=False, detail=str(exc))
                        )

            try:
                remaining = max(deadline - time.monotonic(), 0.5)
                debugger = backend.connect_debugger(
                    cpu=cpu,
                    host=record.debugger_host,
                    port=record.debugger_port,
                    timeout=remaining,
                )
                try:
                    cast(Any, debugger).snapshot()
                    checks.append(
                        DoctorCheckResult(
                            name="live_debugger_handshake",
                            passed=True,
                            detail="RSP register snapshot succeeded",
                        )
                    )
                finally:
                    close = getattr(debugger, "close", None)
                    if callable(close):
                        close()
            except Exception as exc:
                checks.append(
                    DoctorCheckResult(
                        name="live_debugger_handshake", passed=False, detail=str(exc)
                    )
                )
        except (RuntimeOrchestrationError, OSError) as exc:
            checks.append(DoctorCheckResult(name="live_launch", passed=False, detail=str(exc)))
        finally:
            if running is not None:
                with suppress(Exception):
                    stop_owned_process(running, grace_seconds=2.0)
            if display_lease is not None:
                with suppress(Exception):
                    stop_x11_display(display_lease)
    return checks


def run_doctor(
    backend: _DoctorBackend,
    *,
    rom: Path | None,
    require: frozenset[str],
    destructive: bool = False,
    live_probe_timeout: float = 10.0,
) -> DoctorReport:
    checks: list[DoctorCheckResult] = []

    executable = discover_emulator_executable(backend.kind)
    checks.append(
        DoctorCheckResult(
            name="emulator",
            passed=executable is not None,
            detail=(
                "emulator executable found"
                if executable is not None
                else "emulator executable not found"
            ),
        )
    )

    if rom is not None:
        checks.append(
            DoctorCheckResult(
                name="rom",
                passed=rom.is_file(),
                detail="ROM is readable" if rom.is_file() else "ROM does not exist",
            )
        )

    needs_window = bool(
        require
        & {
            "window_input",
            "touchscreen_input",
            "screenshot",
            "save_state",
        }
    )
    if needs_window:
        xvfb = shutil.which("Xvfb")
        xdotool = shutil.which("xdotool")
        checks.append(
            DoctorCheckResult(
                name="xvfb",
                passed=xvfb is not None,
                detail="Xvfb available" if xvfb is not None else "Xvfb not found",
            )
        )
        checks.append(
            DoctorCheckResult(
                name="xdotool",
                passed=xdotool is not None,
                detail="xdotool available" if xdotool is not None else "xdotool not found",
            )
        )

    if "screenshot" in require:
        capture_tool = _discover_capture_tool()
        checks.append(
            DoctorCheckResult(
                name="capture_tool",
                passed=capture_tool is not None,
                detail=(
                    f"capture tool available: {capture_tool}"
                    if capture_tool is not None
                    else f"no capture tool found (tried: {', '.join(CAPTURE_TOOL_CANDIDATES)})"
                ),
            )
        )

    capability_map = {
        "debugger_arm9": backend.capabilities.debugger_arm9,
        "debugger_arm7": backend.capabilities.debugger_arm7,
        "managed_launch": backend.capabilities.managed_launch,
        "save_state": backend.capabilities.save_state,
        "battery_save_isolation": backend.capabilities.battery_save_isolation,
        "window_input": backend.capabilities.window_input,
        "touchscreen_input": backend.capabilities.touchscreen_input,
        "screenshot": backend.capabilities.screenshot,
    }
    for name in sorted(require):
        supported = capability_map.get(name)
        checks.append(
            DoctorCheckResult(
                name=f"capability:{name}",
                passed=supported is True,
                detail=(
                    "supported"
                    if supported is True
                    else "unsupported or unknown capability"
                ),
            )
        )

    if destructive:
        if executable is None:
            checks.append(
                DoctorCheckResult(
                    name="live_launch",
                    passed=False,
                    detail="cannot live-probe: emulator executable not found",
                )
            )
        elif rom is None:
            checks.append(
                DoctorCheckResult(
                    name="live_launch",
                    passed=False,
                    detail="cannot live-probe: no ROM provided",
                )
            )
        else:
            checks.extend(
                _run_live_probe(
                    backend,
                    executable,
                    rom,
                    require=require,
                    timeout=live_probe_timeout,
                )
            )

    return DoctorReport(emulator=backend.kind, checks=tuple(checks))
