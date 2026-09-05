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
from nds_disassembly_toolkit.errors import RuntimeCheckpointError


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
        del cpu, debugger_host, debugger_port, session_root
        environment = () if display is None else (("DISPLAY", display),)
        return LaunchSpec(
            argv=(str(executable), str(rom)),
            environment=environment,
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
