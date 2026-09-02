from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Protocol, Self

from nds_disassembly_toolkit.errors import (
    RuntimeConnectionError,
    RuntimeProtocolError,
    RuntimeTimeoutError,
)

_MAX_PACKET_PAYLOAD = 64 * 1024
_MEMORY_CHUNK_SIZE = 0x400
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class _SocketLike(Protocol):
    def settimeout(self, value: float) -> None: ...

    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RSPCapabilities:
    features: tuple[tuple[str, str | bool], ...]
    packet_size: int | None = None

    def supports(self, name: str) -> bool:
        for feature, value in self.features:
            if feature == name:
                return value is not False
        return False

    def value(self, name: str) -> str | bool | None:
        for feature, value in self.features:
            if feature == name:
                return value
        return None


@dataclass(frozen=True, slots=True)
class RSPStopReply:
    signal: int | None = None
    exited: bool = False
    exit_code: int | None = None
    fields: tuple[tuple[str, str], ...] = ()
    raw: str = ""


class RSPClient:
    def __init__(self, peer: _SocketLike, *, timeout: float = 5.0) -> None:
        if timeout <= 0:
            raise ValueError("runtime timeout must be positive")
        self._peer = peer
        self._peer.settimeout(timeout)
        self._receive_buffer = bytearray()
        self._no_ack = False
        self._closed = False

    @classmethod
    def connect(
        cls,
        host: str,
        port: int,
        *,
        timeout: float = 5.0,
    ) -> Self:
        if not host:
            raise ValueError("runtime host must not be empty")
        if not 1 <= port <= 65535:
            raise ValueError("runtime port must be between 1 and 65535")
        if timeout <= 0:
            raise ValueError("runtime timeout must be positive")
        try:
            peer = socket.create_connection((host, port), timeout=timeout)
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeTimeoutError(
                f"timed out connecting to runtime debugger at {host}:{port}"
            ) from exc
        except OSError as exc:
            raise RuntimeConnectionError(
                f"cannot connect to runtime debugger at {host}:{port}"
            ) from exc
        return cls(peer, timeout=timeout)

    @staticmethod
    def _checksum(payload: bytes) -> int:
        return sum(payload) & 0xFF

    @classmethod
    def _frame(cls, payload: str) -> bytes:
        try:
            encoded = payload.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("RSP command payload must be ASCII") from exc
        if len(encoded) > _MAX_PACKET_PAYLOAD:
            raise ValueError("RSP command payload is too large")
        return b"$" + encoded + f"#{cls._checksum(encoded):02x}".encode("ascii")

    def _send(self, data: bytes) -> None:
        if self._closed:
            raise RuntimeConnectionError("runtime debugger connection is closed")
        try:
            self._peer.sendall(data)
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeTimeoutError("runtime debugger send timed out") from exc
        except OSError as exc:
            raise RuntimeConnectionError("runtime debugger send failed") from exc

    def _read_from_peer(self) -> None:
        if self._closed:
            raise RuntimeConnectionError("runtime debugger connection is closed")
        try:
            chunk = self._peer.recv(4096)
        except (socket.timeout, TimeoutError) as exc:
            raise RuntimeTimeoutError("runtime debugger receive timed out") from exc
        except OSError as exc:
            raise RuntimeConnectionError("runtime debugger receive failed") from exc
        if not chunk:
            raise RuntimeConnectionError("runtime debugger closed the connection")
        self._receive_buffer.extend(chunk)

    def _read_byte(self) -> int:
        if not self._receive_buffer:
            self._read_from_peer()
        value = self._receive_buffer[0]
        del self._receive_buffer[0]
        return value

    def _read_ack(self) -> None:
        acknowledgement = self._read_byte()
        if acknowledgement == ord("+"):
            return
        if acknowledgement == ord("-"):
            raise RuntimeProtocolError("runtime debugger rejected the RSP packet")
        raise RuntimeProtocolError("runtime debugger returned an invalid RSP acknowledgement")

    def _receive_packet(self) -> str:
        while self._read_byte() != ord("$"):
            pass

        transmitted = bytearray()
        while True:
            value = self._read_byte()
            if value == ord("#"):
                break
            transmitted.append(value)
            if len(transmitted) > _MAX_PACKET_PAYLOAD:
                raise RuntimeProtocolError("runtime debugger RSP packet is too large")

        checksum_bytes = bytes((self._read_byte(), self._read_byte()))
        try:
            checksum_text = checksum_bytes.decode("ascii")
            expected = int(checksum_text, 16)
        except (UnicodeDecodeError, ValueError) as exc:
            if not self._no_ack:
                self._send(b"-")
            raise RuntimeProtocolError("runtime debugger returned an invalid RSP checksum") from exc

        actual = self._checksum(bytes(transmitted))
        if actual != expected:
            if not self._no_ack:
                self._send(b"-")
            raise RuntimeProtocolError("runtime debugger RSP checksum mismatch")

        if not self._no_ack:
            self._send(b"+")

        decoded = bytearray()
        index = 0
        while index < len(transmitted):
            value = transmitted[index]
            if value == 0x7D:
                index += 1
                if index >= len(transmitted):
                    raise RuntimeProtocolError("runtime debugger returned truncated RSP escaping")
                decoded.append(transmitted[index] ^ 0x20)
            else:
                decoded.append(value)
            index += 1
        try:
            return decoded.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RuntimeProtocolError("runtime debugger returned non-ASCII RSP data") from exc

    @staticmethod
    def _raise_peer_error(response: str) -> None:
        if (
            len(response) >= 3
            and response[0] == "E"
            and response[1] in _HEX_DIGITS
            and response[2] in _HEX_DIGITS
        ):
            raise RuntimeProtocolError(f"runtime debugger returned RSP error {response}")

    def command(self, payload: str) -> str:
        self._send(self._frame(payload))
        if not self._no_ack:
            self._read_ack()
        response = self._receive_packet()
        self._raise_peer_error(response)
        return response

    def negotiate(self) -> RSPCapabilities:
        response = self.command("qSupported")
        feature_values: dict[str, str | bool] = {}
        packet_size: int | None = None
        for token in response.split(";"):
            if not token:
                continue
            if token.endswith("+"):
                feature_values[token[:-1]] = True
                continue
            if token.endswith("-"):
                feature_values[token[:-1]] = False
                continue
            if "=" in token:
                name, value = token.split("=", 1)
                feature_values[name] = value
                if name == "PacketSize":
                    try:
                        packet_size = int(value, 16)
                    except ValueError as exc:
                        raise RuntimeProtocolError(
                            "runtime debugger returned invalid PacketSize"
                        ) from exc
                continue
            feature_values[token] = True

        capabilities = RSPCapabilities(
            features=tuple(sorted(feature_values.items())),
            packet_size=packet_size,
        )
        if capabilities.supports("QStartNoAckMode"):
            if self.command("QStartNoAckMode") != "OK":
                raise RuntimeProtocolError("runtime debugger rejected no-ack mode")
            self._no_ack = True
        return capabilities

    @staticmethod
    def _decode_hex(response: str, *, kind: str) -> bytes:
        if len(response) % 2:
            raise RuntimeProtocolError(f"runtime debugger returned odd-length {kind} data")
        try:
            return bytes.fromhex(response)
        except ValueError as exc:
            raise RuntimeProtocolError(
                f"runtime debugger returned invalid hexadecimal {kind} data"
            ) from exc

    def read_registers(self) -> bytes:
        return self._decode_hex(self.command("g"), kind="register")

    def read_memory(self, address: int, length: int) -> bytes:
        if address < 0:
            raise ValueError("memory address must be non-negative")
        if length < 0:
            raise ValueError("memory length must be non-negative")
        if length == 0:
            return b""
        chunks: list[bytes] = []
        consumed = 0
        while consumed < length:
            chunk_length = min(_MEMORY_CHUNK_SIZE, length - consumed)
            chunk_address = address + consumed
            response = self.command(f"m{chunk_address:x},{chunk_length:x}")
            chunk = self._decode_hex(response, kind="memory")
            if len(chunk) != chunk_length:
                raise RuntimeProtocolError(
                    "runtime debugger returned an unexpected memory length"
                )
            chunks.append(chunk)
            consumed += chunk_length
        return b"".join(chunks)

    @staticmethod
    def _validate_breakpoint(kind: int, address: int, length: int) -> None:
        if kind not in range(5):
            raise ValueError("RSP breakpoint kind must be between 0 and 4")
        if address < 0:
            raise ValueError("breakpoint address must be non-negative")
        if length <= 0:
            raise ValueError("breakpoint length must be positive")

    def insert_breakpoint(self, kind: int, address: int, length: int) -> None:
        self._validate_breakpoint(kind, address, length)
        response = self.command(f"Z{kind},{address:x},{length:x}")
        if response != "OK":
            raise RuntimeProtocolError("runtime debugger rejected breakpoint insertion")

    def remove_breakpoint(self, kind: int, address: int, length: int) -> None:
        self._validate_breakpoint(kind, address, length)
        response = self.command(f"z{kind},{address:x},{length:x}")
        if response != "OK":
            raise RuntimeProtocolError("runtime debugger rejected breakpoint removal")

    @staticmethod
    def _parse_stop(response: str) -> RSPStopReply:
        if len(response) >= 3 and response[0] == "S":
            try:
                signal = int(response[1:3], 16)
            except ValueError as exc:
                raise RuntimeProtocolError("runtime debugger returned invalid stop signal") from exc
            return RSPStopReply(signal=signal, raw=response)

        if len(response) >= 3 and response[0] == "T":
            try:
                signal = int(response[1:3], 16)
            except ValueError as exc:
                raise RuntimeProtocolError("runtime debugger returned invalid stop signal") from exc
            fields: list[tuple[str, str]] = []
            for token in response[3:].split(";"):
                if not token:
                    continue
                if ":" not in token:
                    raise RuntimeProtocolError("runtime debugger returned invalid stop metadata")
                name, value = token.split(":", 1)
                fields.append((name, value))
            return RSPStopReply(signal=signal, fields=tuple(fields), raw=response)

        if len(response) >= 3 and response[0] in {"W", "X"}:
            try:
                code = int(response[1:3], 16)
            except ValueError as exc:
                raise RuntimeProtocolError("runtime debugger returned invalid exit status") from exc
            if response[0] == "W":
                return RSPStopReply(exited=True, exit_code=code, raw=response)
            return RSPStopReply(signal=code, exited=True, raw=response)

        raise RuntimeProtocolError(f"runtime debugger returned invalid stop reply: {response}")

    def continue_execution(self) -> RSPStopReply:
        return self._parse_stop(self.command("c"))

    def step(self) -> RSPStopReply:
        return self._parse_stop(self.command("s"))

    def interrupt(self) -> None:
        self._send(b"\x03")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._peer.close()

    def detach(self) -> None:
        try:
            if self.command("D") != "OK":
                raise RuntimeProtocolError("runtime debugger rejected detach")
        finally:
            self.close()

    def __enter__(self) -> RSPClient:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
