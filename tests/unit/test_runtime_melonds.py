from __future__ import annotations

from dataclasses import dataclass

import pytest

from nds_disassembly_toolkit.analysis import InstructionSet
from nds_disassembly_toolkit.analysis.runtime import (
    BreakpointKind,
    MelonDSSession,
    RuntimeCpu,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.rsp import RSPCapabilities, RSPStopReply
from nds_disassembly_toolkit.errors import RuntimeConnectionError, RuntimeProtocolError


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


def test_connect_uses_cpu_default_ports_and_negotiates(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int, float]] = []
    client = FakeRSPClient()

    def fake_connect(host: str, port: int, *, timeout: float = 5.0) -> FakeRSPClient:
        calls.append((host, port, timeout))
        return client

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.runtime.melonds.RSPClient.connect",
        fake_connect,
    )

    arm9 = MelonDSSession.connect(cpu=RuntimeCpu.ARM9)
    assert calls == [("127.0.0.1", 3333, 5.0)]
    assert arm9.capabilities.packet_size == 0x47B
    assert client.calls == [("initial_ack_handshake",), ("negotiate",)]


def test_connect_uses_arm7_default_and_honors_override(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int, float]] = []

    def fake_connect(host: str, port: int, *, timeout: float = 5.0) -> FakeRSPClient:
        calls.append((host, port, timeout))
        return FakeRSPClient()

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.runtime.melonds.RSPClient.connect",
        fake_connect,
    )

    MelonDSSession.connect(cpu=RuntimeCpu.ARM7)
    MelonDSSession.connect(cpu=RuntimeCpu.ARM7, host="localhost", port=4444, timeout=1.5)
    assert calls == [
        ("127.0.0.1", 3334, 5.0),
        ("localhost", 4444, 1.5),
    ]


def test_connect_cleanup_does_not_mask_negotiation_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingClient(FakeRSPClient):
        def negotiate(self) -> RSPCapabilities:
            self.calls.append(("negotiate",))
            raise RuntimeProtocolError("negotiation failed")

        def close(self) -> None:
            self.calls.append(("close",))
            raise RuntimeConnectionError("cleanup failed")

    client = FailingClient()

    def fake_connect(host: str, port: int, *, timeout: float = 5.0) -> FailingClient:
        return client

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.runtime.melonds.RSPClient.connect",
        fake_connect,
    )

    with pytest.raises(RuntimeProtocolError, match="negotiation failed"):
        MelonDSSession.connect(cpu=RuntimeCpu.ARM9)

    assert client.calls == [
        ("initial_ack_handshake",),
        ("negotiate",),
        ("close",),
    ]


def test_snapshot_maps_melonds_register_blob_and_thumb_state() -> None:
    client = FakeRSPClient(registers=_register_blob(pc=0x02000102, cpsr=0x33))
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    snapshot = session.snapshot()
    assert snapshot.pc == 0x02000102
    assert snapshot.cpsr == 0x33
    assert snapshot.instruction_set is InstructionSet.THUMB
    assert snapshot.registers.value("r0") == 0
    assert snapshot.registers.value("r12") == 12
    assert snapshot.registers.value("sp") == 0x023FFF00
    assert snapshot.registers.value("lr") == 0x02000080
    assert snapshot.registers.value("sp_usr") == 17
    assert snapshot.registers.value("spsr_und") == 38
    assert snapshot.stop.kind is StopReasonKind.UNKNOWN


def test_snapshot_rejects_truncated_register_blob() -> None:
    client = FakeRSPClient(registers=b"\x00" * 64)
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    with pytest.raises(RuntimeProtocolError, match="register payload"):
        session.snapshot()


def test_read_memory_delegates_to_rsp_client() -> None:
    client = FakeRSPClient()
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    assert session.read_memory(0x02000000, 4) == b"\x00\x01\x02\x03"
    assert client.calls[-1] == ("read_memory", 0x02000000, 4)


def test_step_classifies_stop_and_captures_snapshot() -> None:
    client = FakeRSPClient()
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    snapshot = session.step()
    assert snapshot.stop.kind is StopReasonKind.STEP
    assert snapshot.stop.signal == 5
    assert snapshot.stop.raw == "S05"
    assert client.calls[-2:] == [("step",), ("read_registers",)]


def test_step_does_not_misclassify_non_trap_signal() -> None:
    class SignalClient(FakeRSPClient):
        def step(self) -> RSPStopReply:
            self.calls.append(("step",))
            return RSPStopReply(signal=11, raw="S0b")

    client = SignalClient()
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    snapshot = session.step()
    assert snapshot.stop.kind is StopReasonKind.SIGNAL
    assert snapshot.stop.signal == 11


def test_continue_classifies_generic_signal_stop() -> None:
    client = FakeRSPClient()
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    snapshot = session.continue_execution()
    assert snapshot.stop.kind is StopReasonKind.SIGNAL
    assert snapshot.stop.signal == 5


def test_run_until_breakpoint_installs_and_removes_temporary_condition() -> None:
    client = FakeRSPClient()
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    snapshot = session.run_until_breakpoint(0x02001234, length=4)
    assert snapshot.stop.kind is StopReasonKind.BREAKPOINT
    assert snapshot.stop.address == 0x02001234
    assert client.calls == [
        ("insert", 1, 0x02001234, 4),
        ("continue",),
        ("read_registers",),
        ("remove", 1, 0x02001234, 4),
    ]


def test_run_until_breakpoint_does_not_misclassify_unrelated_signal() -> None:
    class SignalClient(FakeRSPClient):
        def continue_execution(self) -> RSPStopReply:
            self.calls.append(("continue",))
            return RSPStopReply(signal=2, raw="S02")

    client = SignalClient()
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    snapshot = session.run_until_breakpoint(0x02001234, length=4)
    assert snapshot.stop.kind is StopReasonKind.SIGNAL
    assert snapshot.stop.signal == 2
    assert snapshot.stop.address is None
    assert client.calls[-1] == ("remove", 1, 0x02001234, 4)


@pytest.mark.parametrize(
    ("kind", "rsp_kind"),
    [
        (BreakpointKind.WRITE, 2),
        (BreakpointKind.READ, 3),
        (BreakpointKind.ACCESS, 4),
    ],
)
def test_run_until_watchpoint_maps_semantic_kind(
    kind: BreakpointKind,
    rsp_kind: int,
) -> None:
    client = FakeRSPClient()
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    snapshot = session.run_until_watchpoint(kind, 0x02100000, length=4)
    assert snapshot.stop.kind is StopReasonKind.WATCHPOINT
    assert snapshot.stop.address == 0x02100000
    assert client.calls[0] == ("insert", rsp_kind, 0x02100000, 4)
    assert client.calls[-1] == ("remove", rsp_kind, 0x02100000, 4)


def test_temporary_cleanup_error_does_not_mask_snapshot_failure() -> None:
    class FailingClient(FakeRSPClient):
        def read_registers(self) -> bytes:
            self.calls.append(("read_registers",))
            raise RuntimeProtocolError("snapshot failed")

        def remove_breakpoint(self, kind: int, address: int, length: int) -> None:
            self.calls.append(("remove", kind, address, length))
            raise RuntimeConnectionError("cleanup failed")

    client = FailingClient()
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    with pytest.raises(RuntimeProtocolError, match="snapshot failed"):
        session.run_until_breakpoint(0x02001234, length=4)

    assert client.calls[-1] == ("remove", 1, 0x02001234, 4)


def test_context_cleanup_error_does_not_mask_primary_failure() -> None:
    class FailingDetachClient(FakeRSPClient):
        def detach(self) -> None:
            self.calls.append(("detach",))
            raise RuntimeConnectionError("detach failed")

    client = FailingDetachClient()
    session = MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities)

    with pytest.raises(ValueError, match="primary failure"), session:
        raise ValueError("primary failure")

    assert client.calls == [("detach",)]


def test_context_manager_detaches_session() -> None:
    client = FakeRSPClient()
    with MelonDSSession(RuntimeCpu.ARM9, client, client.capabilities):
        pass
    assert client.calls == [("detach",)]
    assert client.closed
