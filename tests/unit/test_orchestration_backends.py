from __future__ import annotations

from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration import (
    DebuggerHandshakeMode,
    EmulatorKind,
)
from nds_disassembly_toolkit.analysis.orchestration.desmume_backend import DeSmuMEBackend
from nds_disassembly_toolkit.analysis.orchestration.melonds_backend import MelonDSBackend
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu


def test_backends_expose_explicit_debugger_dialects() -> None:
    melon = MelonDSBackend()
    desmume = DeSmuMEBackend()

    assert melon.kind is EmulatorKind.MELONDS
    assert desmume.kind is EmulatorKind.DESMUME
    assert melon.capabilities.debugger_handshake_mode is DebuggerHandshakeMode.INITIAL_ACK
    assert desmume.capabilities.debugger_handshake_mode is DebuggerHandshakeMode.DIRECT


def test_backend_launch_specs_do_not_use_shell_strings(tmp_path: Path) -> None:
    rom = tmp_path / "game.nds"
    rom.write_bytes(b"fixture")

    melon = MelonDSBackend()
    spec = melon.build_launch_spec(
        executable=Path("/usr/bin/melonds"),
        rom=rom,
        cpu=RuntimeCpu.ARM9,
        debugger_host="127.0.0.1",
        debugger_port=39010,
        session_root=tmp_path,
        display=":101",
    )

    assert isinstance(spec.argv, tuple)
    assert spec.argv[0] == "/usr/bin/melonds"
    assert str(rom) in spec.argv
    assert ("DISPLAY", ":101") in spec.environment
