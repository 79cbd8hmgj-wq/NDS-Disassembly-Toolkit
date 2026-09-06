from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration import (
    DebuggerHandshakeMode,
    DSButton,
    EmulatorKind,
)
from nds_disassembly_toolkit.analysis.orchestration.desmume_backend import DeSmuMEBackend
from nds_disassembly_toolkit.analysis.orchestration.input import WindowGeometry
from nds_disassembly_toolkit.analysis.orchestration.melonds_backend import MelonDSBackend
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeInputError


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



def test_desmume_managed_input_profile_matches_pinned_cli() -> None:
    backend = DeSmuMEBackend()

    assert backend.capabilities.window_input is True
    assert backend.capabilities.touchscreen_input is True
    assert {
        button: backend.host_key_for(button)
        for button in DSButton
    } == {
        DSButton.A: "x",
        DSButton.B: "z",
        DSButton.SELECT: "Shift_R",
        DSButton.START: "Return",
        DSButton.RIGHT: "Right",
        DSButton.LEFT: "Left",
        DSButton.UP: "Up",
        DSButton.DOWN: "Down",
        DSButton.R: "w",
        DSButton.L: "q",
        DSButton.X: "s",
        DSButton.Y: "a",
    }

    profile = backend.layout_profile(WindowGeometry(0, 0, 256, 384))
    assert profile.lower_screen.x == 0
    assert profile.lower_screen.y == 192
    assert profile.lower_screen.width == 256
    assert profile.lower_screen.height == 192


def test_desmume_managed_input_profile_rejects_unknown_geometry() -> None:
    backend = DeSmuMEBackend()

    with pytest.raises(RuntimeInputError, match="256x384"):
        backend.layout_profile(WindowGeometry(0, 0, 512, 768))



def test_desmume_bound_backend_saves_and_loads_isolated_slot(
    tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    backend = DeSmuMEBackend()
    session_root = tmp_path / "session"
    slot_dir = session_root / "config" / "desmume"
    slot_dir.mkdir(parents=True)
    slot = slot_dir / "game.ds1"
    record = SimpleNamespace(
        session_root=session_root,
        rom_path=tmp_path / "game.nds",
    )

    class Host:
        def __init__(self) -> None:
            self.keys: list[tuple[str, str]] = []

        def key_down(self, session: object, host_key: str) -> None:
            self.keys.append(("down", host_key))

        def key_up(self, session: object, host_key: str) -> None:
            self.keys.append(("up", host_key))
            if host_key == "F1" and ("down", "Shift_R") in self.keys:
                slot.write_bytes(b"saved-state")

        def send_key(self, session: object, host_key: str) -> None:
            self.keys.append(("key", host_key))

    class Debugger:
        def __init__(self) -> None:
            self.host_actions = 0

        def run_host_action(self, action: object) -> object:
            self.host_actions += 1
            return action()

    host = Host()
    debugger = Debugger()
    backend.bind_managed_session(record, host, debugger)

    destination = tmp_path / "checkpoint-state.bin"
    backend.save_state(destination)

    assert destination.read_bytes() == b"saved-state"
    assert host.keys == [
        ("down", "Shift_R"),
        ("down", "F1"),
        ("up", "F1"),
        ("up", "Shift_R"),
    ]
    assert debugger.host_actions == 1

    destination.write_bytes(b"restored-state")
    backend.load_state(destination)

    assert slot.read_bytes() == b"restored-state"
    assert host.keys == [
        ("down", "Shift_R"),
        ("down", "F1"),
        ("up", "F1"),
        ("up", "Shift_R"),
        ("down", "Shift_R"),
        ("down", "F1"),
        ("up", "F1"),
        ("up", "Shift_R"),
        ("key", "F1"),
    ]
    assert debugger.host_actions == 3


def test_desmume_state_requires_bound_managed_session(tmp_path: Path) -> None:
    backend = DeSmuMEBackend()

    with pytest.raises(RuntimeInputError, match="bound managed session"):
        backend.save_state(tmp_path / "state.bin")
