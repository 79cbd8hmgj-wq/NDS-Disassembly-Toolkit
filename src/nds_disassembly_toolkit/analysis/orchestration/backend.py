from __future__ import annotations

from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.orchestration.model import (
    EmulatorCapabilities,
    EmulatorKind,
    LaunchSpec,
)
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu


class EmulatorBackend(Protocol):
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

    def save_state(self, destination: Path) -> None: ...

    def load_state(self, source: Path) -> None: ...
