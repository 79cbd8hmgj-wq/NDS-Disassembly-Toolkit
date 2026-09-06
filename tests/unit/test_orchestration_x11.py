from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration.x11 import (
    allocate_display_number,
    find_x11_helpers,
    sanitize_x11_environment,
)


def test_sanitize_x11_environment_overrides_dummy_sdl() -> None:
    env = sanitize_x11_environment(
        {"SDL_VIDEODRIVER": "dummy", "KEEP_ME": "yes"},
        display=":104",
    )
    assert env["DISPLAY"] == ":104"
    assert env["SDL_VIDEODRIVER"] == "x11"
    assert env["KEEP_ME"] == "yes"


def test_allocate_display_number_skips_existing_x11_socket(tmp_path: Path) -> None:
    socket_dir = tmp_path / ".X11-unix"
    socket_dir.mkdir()
    (socket_dir / "X100").touch()
    assert allocate_display_number(socket_dir=socket_dir, start=100, stop=103) == 101


def test_find_x11_helpers_reports_missing_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.x11.shutil.which",
        lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None,
    )
    helpers = find_x11_helpers()
    assert helpers.xvfb == Path("/usr/bin/Xvfb")
    assert helpers.xdotool is None


def test_x11_driver_rejects_window_not_owned_by_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nds_disassembly_toolkit.analysis.orchestration import (
        EmulatorKind,
        RuntimeLifecycleState,
        RuntimeSessionRecord,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import X11HostDriver
    from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
    from nds_disassembly_toolkit.errors import RuntimeInputError

    session = RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.RUNNING,
        emulator=EmulatorKind.MELONDS,
        emulator_executable=Path("/usr/bin/melonDS"),
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        process_group=1234,
        process_start_identity="start",
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=":104",
        window_id="0xabc",
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )

    driver = X11HostDriver(xdotool=Path("/usr/bin/xdotool"))
    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 9999)

    with pytest.raises(RuntimeInputError, match="owned"):
        driver.send_key(session, "z")


def test_x11_driver_uses_argument_arrays_for_key_input(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nds_disassembly_toolkit.analysis.orchestration import (
        EmulatorKind,
        RuntimeLifecycleState,
        RuntimeSessionRecord,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import X11HostDriver
    from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu

    session = RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.RUNNING,
        emulator=EmulatorKind.MELONDS,
        emulator_executable=Path("/usr/bin/melonDS"),
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        process_group=1234,
        process_start_identity="start",
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=":104",
        window_id="0xabc",
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )

    calls: list[list[str]] = []
    driver = X11HostDriver(xdotool=Path("/usr/bin/xdotool"))
    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 1234)
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.x11.subprocess.run",
        lambda argv, **kwargs: calls.append(list(argv)),
    )

    driver.send_key(session, "z")

    assert calls == [
        ["/usr/bin/xdotool", "windowfocus", "--sync", "0xabc"],
        ["/usr/bin/xdotool", "key", "z"],
    ]



def test_x11_driver_reports_owned_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nds_disassembly_toolkit.analysis.orchestration import (
        EmulatorKind,
        RuntimeLifecycleState,
        RuntimeSessionRecord,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import X11HostDriver
    from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu

    session = RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.RUNNING,
        emulator=EmulatorKind.MELONDS,
        emulator_executable=Path("/usr/bin/melonDS"),
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        process_group=1234,
        process_start_identity="start",
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=":104",
        window_id="0xabc",
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )
    driver = X11HostDriver(xdotool=Path("/usr/bin/xdotool"))
    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 1234)

    assert driver.window_is_owned(session) is True

    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 9999)
    assert driver.window_is_owned(session) is False



def test_x11_driver_pointer_and_capture_use_owned_window_argument_arrays(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nds_disassembly_toolkit.analysis.orchestration import (
        EmulatorKind,
        RuntimeLifecycleState,
        RuntimeSessionRecord,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import X11HostDriver
    from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu

    session = RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.RUNNING,
        emulator=EmulatorKind.MELONDS,
        emulator_executable=Path("/usr/bin/melonDS"),
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        process_group=1234,
        process_start_identity="start",
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=":104",
        window_id="0xabc",
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )
    calls: list[list[str]] = []
    driver = X11HostDriver(
        xdotool=Path("/usr/bin/xdotool"),
        capture_tool=Path("/usr/bin/import"),
    )
    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 1234)
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.x11.subprocess.run",
        lambda argv, **kwargs: calls.append(list(argv)),
    )
    destination = tmp_path / "frame.png"

    driver.move_pointer(session, 10, 20)
    driver.pointer_down(session)
    driver.pointer_up(session)
    driver.capture_window(session, destination)

    assert calls == [
        ["/usr/bin/xdotool", "mousemove", "--window", "0xabc", "10", "20"],
        ["/usr/bin/xdotool", "mousedown", "1"],
        ["/usr/bin/xdotool", "mouseup", "1"],
        ["/usr/bin/import", "-window", "0xabc", str(destination)],
    ]


def test_x11_driver_capture_rejects_unowned_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nds_disassembly_toolkit.analysis.orchestration import (
        EmulatorKind,
        RuntimeLifecycleState,
        RuntimeSessionRecord,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import X11HostDriver
    from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
    from nds_disassembly_toolkit.errors import RuntimeInputError

    session = RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.RUNNING,
        emulator=EmulatorKind.MELONDS,
        emulator_executable=Path("/usr/bin/melonDS"),
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        process_group=1234,
        process_start_identity="start",
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=":104",
        window_id="0xabc",
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )
    driver = X11HostDriver(
        xdotool=Path("/usr/bin/xdotool"),
        capture_tool=Path("/usr/bin/import"),
    )
    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 9999)

    with pytest.raises(RuntimeInputError, match="owned"):
        driver.capture_window(session, tmp_path / "frame.png")



def test_x11_driver_reads_owned_window_geometry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    from nds_disassembly_toolkit.analysis.orchestration import (
        EmulatorKind,
        RuntimeLifecycleState,
        RuntimeSessionRecord,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import X11HostDriver
    from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu

    session = RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.RUNNING,
        emulator=EmulatorKind.DESMUME,
        emulator_executable=Path("/usr/bin/desmume-cli"),
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        process_group=1234,
        process_start_identity="start",
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=":104",
        window_id="0xabc",
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )
    calls: list[list[str]] = []
    driver = X11HostDriver(xdotool=Path("/usr/bin/xdotool"))
    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 1234)

    def fake_run(argv: list[str], **kwargs: object) -> object:
        calls.append(list(argv))
        return SimpleNamespace(
            returncode=0,
            stdout="WINDOW=0xabc\nX=10\nY=20\nWIDTH=256\nHEIGHT=384\nSCREEN=0\n",
        )

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.x11.subprocess.run",
        fake_run,
    )

    geometry = driver.window_geometry(session)

    assert (geometry.x, geometry.y, geometry.width, geometry.height) == (
        10,
        20,
        256,
        384,
    )
    assert calls == [[
        "/usr/bin/xdotool",
        "getwindowgeometry",
        "--shell",
        "0xabc",
    ]]


def test_x11_driver_discovers_window_by_owned_pid(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    from nds_disassembly_toolkit.analysis.orchestration import (
        EmulatorKind,
        RuntimeLifecycleState,
        RuntimeSessionRecord,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import X11HostDriver
    from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu

    session = RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.LAUNCHING,
        emulator=EmulatorKind.DESMUME,
        emulator_executable=Path("/usr/bin/desmume-cli"),
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        process_group=1234,
        process_start_identity="start",
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=":104",
        window_id=None,
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )
    driver = X11HostDriver(xdotool=Path("/usr/bin/xdotool"))

    def fake_run(argv: list[str], **kwargs: object) -> object:
        if "search" in argv:
            return SimpleNamespace(returncode=0, stdout="4194305\n")
        raise AssertionError(argv)

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.x11.subprocess.run",
        fake_run,
    )
    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 1234)

    assert driver.wait_for_window(session, timeout=0.01) == "4194305"



def test_x11_driver_sends_explicit_owned_key_down_and_up(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    from nds_disassembly_toolkit.analysis.orchestration import (
        EmulatorKind,
        RuntimeLifecycleState,
        RuntimeSessionRecord,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import X11HostDriver
    from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu

    session = RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.RUNNING,
        emulator=EmulatorKind.DESMUME,
        emulator_executable=Path("/usr/bin/desmume-cli"),
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        process_group=1234,
        process_start_identity="start",
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=":104",
        window_id="0xabc",
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )
    calls: list[list[str]] = []
    driver = X11HostDriver(xdotool=Path("/usr/bin/xdotool"))
    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 1234)

    def fake_run(argv: list[str], **kwargs: object) -> object:
        calls.append(list(argv))
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.x11.subprocess.run",
        fake_run,
    )

    driver.key_down(session, "Shift_R")
    driver.key_down(session, "F1")
    driver.key_up(session, "F1")
    driver.key_up(session, "Shift_R")

    assert calls == [
        ["/usr/bin/xdotool", "windowfocus", "--sync", "0xabc"],
        ["/usr/bin/xdotool", "keydown", "Shift_R"],
        ["/usr/bin/xdotool", "windowfocus", "--sync", "0xabc"],
        ["/usr/bin/xdotool", "keydown", "F1"],
        ["/usr/bin/xdotool", "windowfocus", "--sync", "0xabc"],
        ["/usr/bin/xdotool", "keyup", "F1"],
        ["/usr/bin/xdotool", "windowfocus", "--sync", "0xabc"],
        ["/usr/bin/xdotool", "keyup", "Shift_R"],
    ]



def test_x11_driver_keys_target_owned_window_explicitly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from nds_disassembly_toolkit.analysis.orchestration import (
        EmulatorKind,
        RuntimeLifecycleState,
        RuntimeSessionRecord,
    )
    from nds_disassembly_toolkit.analysis.orchestration.x11 import X11HostDriver
    from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu

    session = RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.RUNNING,
        emulator=EmulatorKind.DESMUME,
        emulator_executable=Path("/usr/bin/desmume-cli"),
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        process_group=1234,
        process_start_identity="start",
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=":104",
        window_id="0xabc",
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )
    calls: list[list[str]] = []
    driver = X11HostDriver(
        xdotool=Path("/usr/bin/xdotool"),
        display=":104",
    )
    monkeypatch.setattr(driver, "_window_pid", lambda window_id: 1234)
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.x11.subprocess.run",
        lambda argv, **kwargs: calls.append(list(argv)),
    )

    driver.key_down(session, "Shift_R")
    driver.send_key(session, "F1")
    driver.key_up(session, "Shift_R")

    assert [
        ["/usr/bin/xdotool", "keydown", "--window", "0xabc", "Shift_R"],
        ["/usr/bin/xdotool", "key", "--window", "0xabc", "F1"],
        ["/usr/bin/xdotool", "keyup", "--window", "0xabc", "Shift_R"],
    ] == [
        call for call in calls if call[1] in {"keydown", "key", "keyup"}
    ]
