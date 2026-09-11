from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Any

from nds_disassembly_toolkit.analysis.orchestration.input import (
    DSButton,
    ScreenLayoutProfile,
    ScreenViewport,
    WindowGeometry,
)
from nds_disassembly_toolkit.analysis.orchestration.model import (
    DebuggerHandshakeMode,
    EmulatorCapabilities,
    EmulatorKind,
    LaunchSpec,
)
from nds_disassembly_toolkit.analysis.runtime.desmume import DeSmuMESession
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.errors import (
    RuntimeCheckpointError,
    RuntimeInputError,
    RuntimeLaunchError,
)


class DeSmuMEBackend:
    def __init__(self) -> None:
        self._runtime_record: Any | None = None
        self._host_driver: Any | None = None
        self._debugger: Any | None = None

    @property
    def kind(self) -> EmulatorKind:
        return EmulatorKind.DESMUME

    @property
    def capabilities(self) -> EmulatorCapabilities:
        return EmulatorCapabilities(
            debugger_arm9=True,
            debugger_arm7=False,
            managed_launch=True,
            save_state=True,
            battery_save_isolation=True,
            window_input=True,
            touchscreen_input=True,
            screenshot=False,
            debugger_handshake_mode=DebuggerHandshakeMode.DIRECT,
        )

    @staticmethod
    def _isolated_rom_path(rom: Path, session_root: Path) -> Path:
        """A per-session path DeSmuME can open so its adjacent battery-save
        file (same basename, .dsv extension) never collides with another
        session sharing the same source ROM."""
        return session_root / "rom" / rom.name

    def battery_save_path(self, rom: Path, session_root: Path) -> Path:
        isolated_rom = self._isolated_rom_path(rom, session_root)
        return isolated_rom.with_suffix(".dsv")

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
    ) -> LaunchSpec:
        if cpu is not RuntimeCpu.ARM9:
            raise RuntimeLaunchError("DeSmuME managed launch supports ARM9 debugging only")
        if debugger_host != "127.0.0.1":
            raise RuntimeLaunchError("managed DeSmuME debugger must use loopback")
        isolated_rom = self._isolated_rom_path(rom, session_root)
        isolated_rom.parent.mkdir(parents=True, exist_ok=True)
        if not isolated_rom.exists():
            try:
                os.symlink(rom, isolated_rom)
            except OSError:
                # Cross-device or a sandbox without symlink permission: fall
                # back to a real copy so isolation still holds.
                shutil.copyfile(rom, isolated_rom)
        environment = [
            ("XDG_CONFIG_HOME", str(session_root / "config")),
            ("XDG_DATA_HOME", str(session_root / "data")),
        ]
        if display is not None:
            environment.extend(
                [
                    ("DISPLAY", display),
                    ("SDL_VIDEODRIVER", "x11"),
                ]
            )
        return LaunchSpec(
            argv=(
                str(executable),
                "--arm9gdb",
                str(debugger_port),
                "--disable-sound",
                "--nojoy",
                str(isolated_rom),
            ),
            environment=tuple(environment),
            cwd=session_root,
        )

    def connect_debugger(
        self,
        *,
        cpu: RuntimeCpu,
        host: str,
        port: int,
        timeout: float = 5.0,
    ) -> DeSmuMESession:
        return DeSmuMESession.connect(cpu=cpu, host=host, port=port, timeout=timeout)


    def bind_managed_session(
        self,
        record: Any,
        host_driver: Any,
        debugger: Any | None = None,
    ) -> None:
        self._runtime_record = record
        self._host_driver = host_driver
        self._debugger = debugger

    def _bound_runtime(self) -> tuple[Any, Any, Any]:
        if (
            self._runtime_record is None
            or self._host_driver is None
            or self._debugger is None
        ):
            raise RuntimeInputError(
                "DeSmuME save-state operation requires a bound managed session"
            )
        return self._runtime_record, self._host_driver, self._debugger

    def _slot_directory(self) -> Path:
        record, _, _ = self._bound_runtime()
        return Path(record.session_root) / "config" / "desmume"

    @staticmethod
    def _slot_snapshot(directory: Path) -> dict[Path, tuple[int, int]]:
        if not directory.exists():
            return {}
        return {
            path: (path.stat().st_mtime_ns, path.stat().st_size)
            for path in directory.glob("*.ds1")
            if path.is_file()
        }

    def _trigger_slot_save(self) -> Path:
        record, host, debugger = self._bound_runtime()
        directory = self._slot_directory()
        directory.mkdir(parents=True, exist_ok=True)
        before = self._slot_snapshot(directory)

        def action() -> Path:
            host.key_down(record, "Shift_R")
            try:
                host.key_down(record, "F1")
                host.key_up(record, "F1")
            finally:
                host.key_up(record, "Shift_R")
            deadline = time.monotonic() + 5.0
            while True:
                after = self._slot_snapshot(directory)
                changed = sorted(
                    path
                    for path, identity in after.items()
                    if before.get(path) != identity
                )
                if len(changed) == 1:
                    return changed[0]
                if len(changed) > 1:
                    raise RuntimeCheckpointError(
                        "DeSmuME changed multiple managed save-state slot files"
                    )
                if time.monotonic() >= deadline:
                    raise RuntimeCheckpointError(
                        "DeSmuME did not create or update managed save-state slot 1"
                    )
                time.sleep(0.01)

        return Path(debugger.run_host_action(action))

    def save_state(self, destination: Path) -> None:
        slot = self._trigger_slot_save()
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(slot, destination)

    def load_state(self, source: Path) -> None:
        record, host, debugger = self._bound_runtime()
        if not source.is_file():
            raise RuntimeCheckpointError("checkpoint state file does not exist")
        slot = self._trigger_slot_save()
        temporary = slot.with_suffix(slot.suffix + ".tmp")
        shutil.copyfile(source, temporary)
        temporary.replace(slot)
        def load_action() -> None:
            host.send_key(record, "F1")
            time.sleep(0.05)

        debugger.run_host_action(load_action)


    def host_key_for(self, button: DSButton) -> str:
        mapping = {
            DSButton.A: "x",
            DSButton.B: "z",
            DSButton.SELECT: "Shift_R",
            DSButton.START: "Return",
            DSButton.RIGHT: "Right",
            DSButton.LEFT: "Left",
            DSButton.UP: "Up",
            DSButton.DOWN: "Down",
            DSButton.R: "w",
            DSButton.L: "q",
            DSButton.X: "s",
            DSButton.Y: "a",
        }
        return mapping[button]

    def layout_profile(self, geometry: WindowGeometry) -> ScreenLayoutProfile:
        if geometry.width != 256 or geometry.height != 384:
            raise RuntimeInputError(
                "managed DeSmuME CLI input requires exact 256x384 window geometry"
            )
        return ScreenLayoutProfile(
            window=geometry,
            lower_screen=ScreenViewport(0, 192, 256, 192),
        )
