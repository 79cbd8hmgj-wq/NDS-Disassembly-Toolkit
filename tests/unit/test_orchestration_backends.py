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



def test_desmume_launch_spec_sets_managed_debugger_and_isolation(
    tmp_path: Path,
) -> None:
    rom = tmp_path / "game.nds"
    rom.write_bytes(b"fixture")
    backend = DeSmuMEBackend()

    spec = backend.build_launch_spec(
        executable=Path("/usr/bin/desmume-cli"),
        rom=rom,
        cpu=RuntimeCpu.ARM9,
        debugger_host="127.0.0.1",
        debugger_port=39011,
        session_root=tmp_path,
        display=":105",
    )

    assert spec.argv == (
        "/usr/bin/desmume-cli",
        "--arm9gdb",
        "39011",
        "--disable-sound",
        "--nojoy",
        str(rom),
    )
    assert spec.cwd == tmp_path
    environment = dict(spec.environment)
    assert environment["DISPLAY"] == ":105"
    assert environment["SDL_VIDEODRIVER"] == "x11"
    assert environment["XDG_CONFIG_HOME"] == str(tmp_path / "config")
    assert environment["XDG_DATA_HOME"] == str(tmp_path / "data")



def test_melonds_launch_spec_writes_isolated_gdb_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    rom = tmp_path / "game.nds"
    rom.write_bytes(b"fixture")
    backend = MelonDSBackend()
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.melonds_backend.allocate_loopback_port",
        lambda host="127.0.0.1": 39012,
        raising=False,
    )

    spec = backend.build_launch_spec(
        executable=Path("/usr/bin/melonDS"),
        rom=rom,
        cpu=RuntimeCpu.ARM9,
        debugger_host="127.0.0.1",
        debugger_port=39011,
        session_root=tmp_path,
        display=":105",
    )

    assert spec.argv == ("/usr/bin/melonDS", str(rom))
    assert spec.cwd == tmp_path
    environment = dict(spec.environment)
    assert environment["XDG_CONFIG_HOME"] == str(tmp_path / "config")
    assert environment["DISPLAY"] == ":105"
    assert environment["SDL_VIDEODRIVER"] == "x11"

    config = tmp_path / "config" / "melonDS" / "melonDS.toml"
    rendered = config.read_text(encoding="utf-8")
    assert "Enabled = true" in rendered
    assert "Port = 39011" in rendered
    assert "Port = 39012" in rendered
    assert "BreakOnStartup = true" in rendered
    assert str(tmp_path / "saves") in rendered
