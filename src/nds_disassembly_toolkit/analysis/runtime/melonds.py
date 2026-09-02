from __future__ import annotations

from contextlib import suppress
from typing import Protocol, Self

from nds_disassembly_toolkit.analysis.runtime.model import (
    BreakpointKind,
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.rsp import (
    RSPCapabilities,
    RSPClient,
    RSPStopReply,
)
from nds_disassembly_toolkit.errors import RuntimeProtocolError

_MELONDS_REGISTER_NAMES = (
    *(f"r{index}" for index in range(13)),
    "sp",
    "lr",
    "pc",
    "cpsr",
    "sp_usr",
    "lr_usr",
    "r8_fiq",
    "r9_fiq",
    "r10_fiq",
    "r11_fiq",
    "r12_fiq",
    "sp_fiq",
    "lr_fiq",
    "sp_irq",
    "lr_irq",
    "sp_svc",
    "lr_svc",
    "sp_abt",
    "lr_abt",
    "sp_und",
    "lr_und",
    "spsr_fiq",
    "spsr_irq",
    "spsr_svc",
    "spsr_abt",
    "spsr_und",
)

_BREAKPOINT_KIND_TO_RSP = {
    BreakpointKind.CODE: 1,
    BreakpointKind.WRITE: 2,
    BreakpointKind.READ: 3,
    BreakpointKind.ACCESS: 4,
}
_TRAP_SIGNAL = 5
_EXPECTED_TRAP_KINDS = frozenset(
    {
        StopReasonKind.BREAKPOINT,
        StopReasonKind.WATCHPOINT,
        StopReasonKind.STEP,
    }
)


class _RSPClientLike(Protocol):
    def initial_ack_handshake(self) -> None: ...

    def negotiate(self) -> RSPCapabilities: ...

    def read_registers(self) -> bytes: ...

    def read_memory(self, address: int, length: int) -> bytes: ...

    def insert_breakpoint(self, kind: int, address: int, length: int) -> None: ...

    def remove_breakpoint(self, kind: int, address: int, length: int) -> None: ...

    def continue_execution(self) -> RSPStopReply: ...

    def step(self) -> RSPStopReply: ...

    def interrupt(self) -> None: ...

    def detach(self) -> None: ...

    def close(self) -> None: ...


class MelonDSSession:
    def __init__(
        self,
        cpu: RuntimeCpu,
        client: _RSPClientLike,
        capabilities: RSPCapabilities,
    ) -> None:
        self._cpu = cpu
        self._client = client
        self._capabilities = capabilities
        self._closed = False

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
            client.initial_ack_handshake()
            capabilities = client.negotiate()
        except BaseException:
            with suppress(Exception):
                client.close()
            raise
        return cls(cpu, client, capabilities)

    @property
    def cpu(self) -> RuntimeCpu:
        return self._cpu

    @property
    def capabilities(self) -> RSPCapabilities:
        return self._capabilities

    @staticmethod
    def _decode_registers(payload: bytes) -> RegisterSnapshot:
        minimum_size = len(_MELONDS_REGISTER_NAMES) * 4
        if len(payload) < minimum_size or len(payload) % 4:
            raise RuntimeProtocolError(
                "melonDS returned an invalid register payload length"
            )
        values: dict[str, int] = {}
        word_count = len(payload) // 4
        for index in range(word_count):
            start = index * 4
            name = (
                _MELONDS_REGISTER_NAMES[index]
                if index < len(_MELONDS_REGISTER_NAMES)
                else f"reg_{index}"
            )
            values[name] = int.from_bytes(payload[start : start + 4], "little")
        return RegisterSnapshot.from_mapping(values)

    @staticmethod
    def _stop_from_reply(
        reply: RSPStopReply,
        kind: StopReasonKind,
        *,
        address: int | None = None,
    ) -> RuntimeStop:
        if reply.exited:
            return RuntimeStop(
                StopReasonKind.EXITED,
                signal=reply.signal,
                raw=reply.raw,
            )

        resolved_kind = kind
        resolved_address = address
        if kind in _EXPECTED_TRAP_KINDS and reply.signal != _TRAP_SIGNAL:
            resolved_kind = (
                StopReasonKind.SIGNAL
                if reply.signal is not None
                else StopReasonKind.UNKNOWN
            )
            resolved_address = None
        return RuntimeStop(
            resolved_kind,
            signal=reply.signal,
            address=resolved_address,
            raw=reply.raw,
        )

    def snapshot(self, stop: RuntimeStop | None = None) -> RuntimeSnapshot:
        registers = self._decode_registers(self._client.read_registers())
        return RuntimeSnapshot(
            cpu=self._cpu,
            registers=registers,
            stop=stop if stop is not None else RuntimeStop(StopReasonKind.UNKNOWN),
        )

    def read_memory(self, address: int, length: int) -> bytes:
        return self._client.read_memory(address, length)

    def add_breakpoint(
        self,
        kind: BreakpointKind,
        address: int,
        *,
        length: int = 4,
    ) -> None:
        self._client.insert_breakpoint(_BREAKPOINT_KIND_TO_RSP[kind], address, length)

    def remove_breakpoint(
        self,
        kind: BreakpointKind,
        address: int,
        *,
        length: int = 4,
    ) -> None:
        self._client.remove_breakpoint(_BREAKPOINT_KIND_TO_RSP[kind], address, length)

    def continue_execution(self) -> RuntimeSnapshot:
        reply = self._client.continue_execution()
        stop_kind = StopReasonKind.SIGNAL if reply.signal is not None else StopReasonKind.UNKNOWN
        return self.snapshot(self._stop_from_reply(reply, stop_kind))

    def step(self) -> RuntimeSnapshot:
        reply = self._client.step()
        return self.snapshot(self._stop_from_reply(reply, StopReasonKind.STEP))

    def run_until_breakpoint(
        self,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        self.add_breakpoint(BreakpointKind.CODE, address, length=length)
        try:
            reply = self._client.continue_execution()
            stop = self._stop_from_reply(
                reply,
                StopReasonKind.BREAKPOINT,
                address=address,
            )
            snapshot = self.snapshot(stop)
        except BaseException:
            with suppress(Exception):
                self.remove_breakpoint(BreakpointKind.CODE, address, length=length)
            raise
        self.remove_breakpoint(BreakpointKind.CODE, address, length=length)
        return snapshot

    def run_until_watchpoint(
        self,
        kind: BreakpointKind,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        if kind is BreakpointKind.CODE:
            raise ValueError("watchpoint kind must be read, write, or access")
        self.add_breakpoint(kind, address, length=length)
        try:
            reply = self._client.continue_execution()
            stop = self._stop_from_reply(
                reply,
                StopReasonKind.WATCHPOINT,
                address=address,
            )
            snapshot = self.snapshot(stop)
        except BaseException:
            with suppress(Exception):
                self.remove_breakpoint(kind, address, length=length)
            raise
        self.remove_breakpoint(kind, address, length=length)
        return snapshot

    def interrupt(self) -> None:
        self._client.interrupt()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._client.detach()

    def __enter__(self) -> MelonDSSession:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type is None:
            self.close()
            return
        with suppress(Exception):
            self.close()
