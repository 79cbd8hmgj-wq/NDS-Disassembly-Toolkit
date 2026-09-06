from __future__ import annotations

from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration.model import (
    DebuggerHandshakeMode,
    EmulatorCapabilities,
    EmulatorKind,
    LaunchSpec,
)
from nds_disassembly_toolkit.analysis.runtime.desmume import DeSmuMESession
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeCheckpointError, RuntimeLaunchError


class DeSmuMEBackend:
    @property
    def kind(self) -> EmulatorKind:
        return EmulatorKind.DESMUME

    @property
    def capabilities(self) -> EmulatorCapabilities:
        return EmulatorCapabilities(
            debugger_arm9=True,
            debugger_arm7=False,
            managed_launch=True,
            save_state=False,
            battery_save_isolation=False,
            window_input=False,
            touchscreen_input=False,
            screenshot=False,
            debugger_handshake_mode=DebuggerHandshakeMode.DIRECT,
        )

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
                str(rom),
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


    def save_state(self, destination: Path) -> None:
        del destination
        raise RuntimeCheckpointError("DeSmuME managed save-state support is not available yet")

    def load_state(self, source: Path) -> None:
        del source
        raise RuntimeCheckpointError("DeSmuME managed save-state support is not available yet")
