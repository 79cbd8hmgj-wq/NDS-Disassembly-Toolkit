from __future__ import annotations

from collections import deque

import pytest

from nds_disassembly_toolkit.analysis.runtime.rsp import RSPClient
from nds_disassembly_toolkit.errors import RuntimeProtocolError


def _packet(payload: str) -> bytes:
    encoded = payload.encode("ascii")
    checksum = sum(encoded) & 0xFF
    return b"$" + encoded + f"#{checksum:02x}".encode("ascii")


class FakeSocket:
    def __init__(self, incoming: list[bytes]) -> None:
        self.incoming = deque(incoming)
        self.sent: list[bytes] = []
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, size: int) -> bytes:
        if not self.incoming:
            return b""
        chunk = self.incoming.popleft()
        if len(chunk) <= size:
            return chunk
        self.incoming.appendleft(chunk[size:])
        return chunk[:size]

    def close(self) -> None:
        self.closed = True


def test_command_frames_request_and_acknowledges_fragmented_response() -> None:
    sock = FakeSocket([b"+", b"$O", b"K#", b"9a"])
    client = RSPClient(sock)

    assert client.command("qSupported") == "OK"
    assert sock.sent == [b"$qSupported#37", b"+"]


def test_command_rejects_bad_response_checksum() -> None:
    sock = FakeSocket([b"+", b"$OK#00"])
    client = RSPClient(sock)

    with pytest.raises(RuntimeProtocolError, match="checksum"):
        client.command("qSupported")
    assert sock.sent[-1] == b"-"


def test_command_turns_peer_error_into_protocol_error() -> None:
    sock = FakeSocket([b"+", _packet("E01")])
    client = RSPClient(sock)

    with pytest.raises(RuntimeProtocolError, match="E01"):
        client.command("g")


def test_negotiate_parses_features_and_enters_no_ack_mode() -> None:
    supported = "PacketSize=47b;qXfer:features:read+;hwbreak+;QStartNoAckMode+"
    sock = FakeSocket(
        [
            b"+",
            _packet(supported),
            b"+",
            _packet("OK"),
            _packet("1122"),
        ]
    )
    client = RSPClient(sock)

    capabilities = client.negotiate()
    assert capabilities.packet_size == 0x47B
    assert capabilities.supports("qXfer:features:read")
    assert capabilities.supports("hwbreak")
    assert capabilities.supports("QStartNoAckMode")

    assert client.command("g") == "1122"
    assert sock.sent == [
        b"$qSupported#37",
        b"+",
        b"$QStartNoAckMode#b0",
        b"+",
        b"$g#67",
    ]


def test_read_registers_decodes_hex_payload() -> None:
    sock = FakeSocket([b"+", _packet("78563412")])
    client = RSPClient(sock)

    assert client.read_registers() == bytes.fromhex("78563412")


def test_read_memory_chunks_large_requests() -> None:
    first = bytes(range(256)) * 4
    second = bytes(range(256))
    sock = FakeSocket(
        [
            b"+",
            _packet(first.hex()),
            b"+",
            _packet(second.hex()),
        ]
    )
    client = RSPClient(sock)

    assert client.read_memory(0x02000000, 0x500) == first + second
    assert sock.sent[0] == _packet("m2000000,400")
    assert sock.sent[2] == _packet("m2000400,100")


def test_breakpoint_watchpoint_and_remove_packets() -> None:
    sock = FakeSocket(
        [
            b"+",
            _packet("OK"),
            b"+",
            _packet("OK"),
            b"+",
            _packet("OK"),
            b"+",
            _packet("OK"),
        ]
    )
    client = RSPClient(sock)

    client.insert_breakpoint(1, 0x02001234, 4)
    client.insert_breakpoint(2, 0x02100000, 4)
    client.remove_breakpoint(1, 0x02001234, 4)
    client.remove_breakpoint(2, 0x02100000, 4)

    packets = [data for data in sock.sent if data.startswith(b"$")]
    assert packets == [
        _packet("Z1,2001234,4"),
        _packet("Z2,2100000,4"),
        _packet("z1,2001234,4"),
        _packet("z2,2100000,4"),
    ]


def test_continue_and_step_parse_signal_stop_replies() -> None:
    sock = FakeSocket([b"+", _packet("S05"), b"+", _packet("T05thread:1;")])
    client = RSPClient(sock)

    continued = client.continue_execution()
    stepped = client.step()

    assert continued.signal == 5
    assert not continued.exited
    assert continued.fields == ()
    assert stepped.signal == 5
    assert stepped.fields == (("thread", "1"),)
    packets = [data for data in sock.sent if data.startswith(b"$")]
    assert packets == [_packet("c"), _packet("s")]


def test_exit_reply_is_preserved() -> None:
    sock = FakeSocket([b"+", _packet("W00")])
    client = RSPClient(sock)

    reply = client.continue_execution()
    assert reply.exited
    assert reply.exit_code == 0
    assert reply.signal is None


def test_detach_closes_socket_after_ok() -> None:
    sock = FakeSocket([b"+", _packet("OK")])
    client = RSPClient(sock)

    client.detach()
    assert sock.closed
    assert sock.sent[0] == _packet("D")
