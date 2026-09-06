from __future__ import annotations

import shutil
from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.orchestration.model import (
    DoctorCheckResult,
    DoctorReport,
    EmulatorCapabilities,
    EmulatorKind,
)


class _DoctorBackend(Protocol):
    @property
    def kind(self) -> EmulatorKind: ...

    @property
    def capabilities(self) -> EmulatorCapabilities: ...


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


def run_doctor(
    backend: _DoctorBackend,
    *,
    rom: Path | None,
    require: frozenset[str],
    destructive: bool = False,
) -> DoctorReport:
    del destructive
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

    return DoctorReport(emulator=backend.kind, checks=tuple(checks))
