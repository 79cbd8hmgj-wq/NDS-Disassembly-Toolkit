from __future__ import annotations

from dataclasses import dataclass

import pytest

from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.analysis.runtime.desmume import DeSmuMESession
from nds_disassembly_toolkit.analysis.runtime.rsp import RSPCapabilities, RSPStopReply


def _register_blob(*, pc: int = 0x02000100, cpsr: int = 0x13) -> bytes:
    values = list(range(39))
    values[13] = 0x023FFF00
    values[14] = 0x02000080
    values[15] = pc
    values[16] = cpsr
    return b"".join(value.to_bytes(4, "little") for value in values)


@dataclass
class FakeRSPClient:
    registers: bytes = _register_blob()

    def __post_init__(self) -> None:
        self.capabilities = RSPCapabilities((("hwbreak", True),), packet_size=0x47B)
        self.calls: list[tuple[object, ...]] = []
        self.closed = False

    def initial_ack_handshake(self) -> None:
        self.calls.append(("initial_ack_handshake",))

    def negotiate(self) -> RSPCapabilities:
        self.calls.append(("negotiate",))
        return self.capabilities

    def read_registers(self) -> bytes:
        self.calls.append(("read_registers",))
        return self.registers

    def read_memory(self, address: int, length: int) -> bytes:
        self.calls.append(("read_memory", address, length))
        return bytes(range(length))

    def write_memory(self, address: int, data: bytes) -> None:
        self.calls.append(("write_memory", address, data))

    def insert_breakpoint(self, kind: int, address: int, length: int) -> None:
        self.calls.append(("insert", kind, address, length))

    def remove_breakpoint(self, kind: int, address: int, length: int) -> None:
        self.calls.append(("remove", kind, address, length))

    def continue_execution(self) -> RSPStopReply:
        self.calls.append(("continue",))
        return RSPStopReply(signal=5, raw="S05")

    def step(self) -> RSPStopReply:
        self.calls.append(("step",))
        return RSPStopReply(signal=5, raw="S05")

    def interrupt(self) -> None:
        self.calls.append(("interrupt",))

    def detach(self) -> None:
        self.calls.append(("detach",))
        self.closed = True

    def close(self) -> None:
        self.calls.append(("close",))
        self.closed = True


def test_desmume_connect_skips_initial_ack(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeRSPClient()
    calls: list[tuple[str, int, float]] = []

    def fake_connect(host: str, port: int, *, timeout: float = 5.0) -> FakeRSPClient:
        calls.append((host, port, timeout))
        return client

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.runtime.desmume.RSPClient.connect",
        fake_connect,
    )

    session = DeSmuMESession.connect(cpu=RuntimeCpu.ARM9, port=39001)

    assert calls == [("127.0.0.1", 39001, 5.0)]
    assert ("initial_ack_handshake",) not in client.calls
    assert client.calls[0] == ("negotiate",)
    assert session.capabilities.packet_size == 0x47B


def test_desmume_snapshot_uses_canonical_arm_registers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeRSPClient()

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.runtime.desmume.RSPClient.connect",
        lambda host, port, *, timeout=5.0: client,
    )

    session = DeSmuMESession.connect(cpu=RuntimeCpu.ARM9, port=39002)
    snapshot = session.snapshot()

    assert snapshot.pc == 0x02000100
    assert snapshot.cpsr == 0x13
    assert snapshot.registers.value("sp") == 0x023FFF00


def test_desmume_connect_closes_client_when_negotiation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeRSPClient()

    def fail() -> RSPCapabilities:
        client.calls.append(("negotiate",))
        raise RuntimeError("boom")

    client.negotiate = fail  # type: ignore[method-assign]
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.runtime.desmume.RSPClient.connect",
        lambda host, port, *, timeout=5.0: client,
    )

    with pytest.raises(RuntimeError, match="boom"):
        DeSmuMESession.connect(cpu=RuntimeCpu.ARM9, port=39003)

    assert ("close",) in client.calls



def test_write_memory_delegates_to_rsp_client() -> None:
    client = FakeRSPClient()
    session = DeSmuMESession(
        RuntimeCpu.ARM9,
        client,
        client.capabilities,
    )

    session.write_memory(0x02000100, b"\x01\xab")

    assert client.calls[-1] == ("write_memory", 0x02000100, b"\x01\xab")
