from __future__ import annotations

import json
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration.input import (
    DSButton,
    ScreenLayoutProfile,
    WindowGeometry,
)
from nds_disassembly_toolkit.analysis.orchestration.model import (
    DebuggerHandshakeMode,
    EmulatorCapabilities,
    EmulatorKind,
    LaunchSpec,
)
from nds_disassembly_toolkit.analysis.orchestration.process import allocate_loopback_port
from nds_disassembly_toolkit.analysis.runtime.melonds import MelonDSSession
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.errors import (
    RuntimeCheckpointError,
    RuntimeInputError,
    RuntimeLaunchError,
)


class MelonDSBackend:
    @property
    def kind(self) -> EmulatorKind:
        return EmulatorKind.MELONDS

    @property
    def capabilities(self) -> EmulatorCapabilities:
        return EmulatorCapabilities(
            debugger_arm9=True,
            debugger_arm7=True,
            managed_launch=True,
            save_state=False,
            battery_save_isolation=False,
            window_input=False,
            touchscreen_input=False,
            screenshot=False,
            debugger_handshake_mode=DebuggerHandshakeMode.INITIAL_ACK,
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
        if debugger_host != "127.0.0.1":
            raise RuntimeLaunchError("managed melonDS debugger must use loopback")

        other_port = allocate_loopback_port(debugger_host)
        arm9_port = debugger_port if cpu is RuntimeCpu.ARM9 else other_port
        arm7_port = debugger_port if cpu is RuntimeCpu.ARM7 else other_port
        config_root = session_root / "config"
        melon_config_root = config_root / "melonDS"
        melon_config_root.mkdir(parents=True, exist_ok=True)
        saves = session_root / "saves"
        checkpoints = session_root / "checkpoints"
        saves.mkdir(parents=True, exist_ok=True)
        checkpoints.mkdir(parents=True, exist_ok=True)
        config_path = melon_config_root / "melonDS.toml"
        config_path.write_text(
            "\n".join(
                (
                    "[Instance0]",
                    f"SaveFilePath = {json.dumps(str(saves))}",
                    f"SavestatePath = {json.dumps(str(checkpoints))}",
                    "",
                    "[Instance0.Gdb]",
                    "Enabled = true",
                    "",
                    "[Instance0.Gdb.ARM9]",
                    f"Port = {arm9_port}",
                    f"BreakOnStartup = {'true' if cpu is RuntimeCpu.ARM9 else 'false'}",
                    "",
                    "[Instance0.Gdb.ARM7]",
                    f"Port = {arm7_port}",
                    f"BreakOnStartup = {'true' if cpu is RuntimeCpu.ARM7 else 'false'}",
                    "",
                )
            ),
            encoding="utf-8",
        )

        environment = [("XDG_CONFIG_HOME", str(config_root))]
        if display is not None:
            environment.extend(
                [
                    ("DISPLAY", display),
                    ("SDL_VIDEODRIVER", "x11"),
                ]
            )
        return LaunchSpec(
            argv=(str(executable), str(rom)),
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
    ) -> MelonDSSession:
        return MelonDSSession.connect(cpu=cpu, host=host, port=port, timeout=timeout)


    def save_state(self, destination: Path) -> None:
        del destination
        raise RuntimeCheckpointError("melonDS managed save-state support is not available yet")

    def load_state(self, source: Path) -> None:
        del source
        raise RuntimeCheckpointError("melonDS managed save-state support is not available yet")


    def host_key_for(self, button: DSButton) -> str:
        del button
        raise RuntimeInputError(
            "managed melonDS input profile is not guaranteed by this backend"
        )

    def layout_profile(self, geometry: WindowGeometry) -> ScreenLayoutProfile:
        del geometry
        raise RuntimeInputError(
            "managed melonDS layout profile is not guaranteed by this backend"
        )
