from __future__ import annotations

from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.orchestration.input import WindowGeometry
from nds_disassembly_toolkit.analysis.orchestration.model import RuntimeSessionRecord


class HostAutomationDriver(Protocol):
    def start_display(self, session: RuntimeSessionRecord) -> str: ...

    def stop_display(self, session: RuntimeSessionRecord) -> None: ...

    def wait_for_window(
        self,
        session: RuntimeSessionRecord,
        *,
        timeout: float,
    ) -> str: ...

    def bind_window(self, session: RuntimeSessionRecord, window_id: str) -> None: ...

    def window_geometry(self, session: RuntimeSessionRecord) -> WindowGeometry: ...

    def send_key(
        self,
        session: RuntimeSessionRecord,
        host_key: str,
    ) -> None: ...

    def move_pointer(
        self,
        session: RuntimeSessionRecord,
        x: int,
        y: int,
    ) -> None: ...

    def pointer_down(
        self,
        session: RuntimeSessionRecord,
        *,
        button: int = 1,
    ) -> None: ...

    def pointer_up(
        self,
        session: RuntimeSessionRecord,
        *,
        button: int = 1,
    ) -> None: ...

    def capture_window(
        self,
        session: RuntimeSessionRecord,
        destination: Path,
    ) -> None: ...
