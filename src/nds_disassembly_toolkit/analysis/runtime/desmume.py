from __future__ import annotations

from contextlib import suppress
from typing import Self

from nds_disassembly_toolkit.analysis.runtime.melonds import MelonDSSession
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.analysis.runtime.rsp import RSPClient


class DeSmuMESession(MelonDSSession):
    """DeSmuME GDB-RSP adapter using the shared toolkit transport."""

    @classmethod
    def connect(
        cls,
        *,
        cpu: RuntimeCpu,
        host: str = "127.0.0.1",
        port: int | None = None,
        timeout: float = 5.0,
    ) -> Self:
        resolved_port = cpu.default_port if port is None else port
        client = RSPClient.connect(host, resolved_port, timeout=timeout)
        try:
            capabilities = client.negotiate()
        except BaseException:
            with suppress(Exception):
                client.close()
            raise
        return cls(cpu, client, capabilities)
