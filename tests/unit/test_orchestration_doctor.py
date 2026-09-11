from __future__ import annotations

from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration import (
    DebuggerHandshakeMode,
    EmulatorCapabilities,
    EmulatorKind,
)
from nds_disassembly_toolkit.analysis.orchestration.doctor import run_doctor


class FakeBackend:
    kind = EmulatorKind.DESMUME
    capabilities = EmulatorCapabilities(
        debugger_arm9=True,
        debugger_arm7=False,
        managed_launch=True,
        save_state=False,
        battery_save_isolation=False,
        window_input=True,
        touchscreen_input=True,
        screenshot=False,
        debugger_handshake_mode=DebuggerHandshakeMode.DIRECT,
    )

    def save_state(self) -> None:
        raise AssertionError("basic doctor must not mutate emulator state")

    def write_memory(self) -> None:
        raise AssertionError("basic doctor must not write runtime memory")


def test_doctor_reports_missing_x11_helper_before_launch(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.doctor.shutil.which",
        lambda name: None,
    )
    report = run_doctor(
        FakeBackend(),
        rom=None,
        require=frozenset({"window_input"}),
    )
    checks = {check.name: check for check in report.checks}
    assert checks["xvfb"].passed is False
    assert checks["xdotool"].passed is False
    assert report.passed is False


def test_basic_doctor_is_non_destructive(monkeypatch) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.doctor.shutil.which",
        lambda name: "/usr/bin/" + name,
    )
    report = run_doctor(FakeBackend(), rom=None, require=frozenset())
    assert report.checks
    assert not any(check.name.startswith("live_") for check in report.checks)


def test_doctor_reports_missing_capture_tool_when_screenshot_required(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.doctor.shutil.which",
        lambda name: None,
    )
    report = run_doctor(FakeBackend(), rom=None, require=frozenset({"screenshot"}))
    checks = {check.name: check for check in report.checks}
    assert checks["capture_tool"].passed is False


def test_doctor_reports_capture_tool_when_available(monkeypatch) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.doctor.shutil.which",
        lambda name: "/usr/bin/import" if name == "import" else None,
    )
    report = run_doctor(FakeBackend(), rom=None, require=frozenset({"screenshot"}))
    checks = {check.name: check for check in report.checks}
    assert checks["capture_tool"].passed is True
    assert "import" in checks["capture_tool"].detail


def test_destructive_doctor_without_rom_reports_cannot_probe(monkeypatch) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.doctor.shutil.which",
        lambda name: "/usr/bin/" + name,
    )
    report = run_doctor(FakeBackend(), rom=None, require=frozenset(), destructive=True)
    checks = {check.name: check for check in report.checks}
    assert checks["live_launch"].passed is False
    assert "no ROM" in checks["live_launch"].detail


def test_destructive_doctor_without_executable_reports_cannot_probe(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.doctor.shutil.which",
        lambda name: None,
    )
    rom = tmp_path / "game.nds"
    rom.write_bytes(b"fixture")
    report = run_doctor(FakeBackend(), rom=rom, require=frozenset(), destructive=True)
    checks = {check.name: check for check in report.checks}
    assert checks["live_launch"].passed is False
    assert "executable not found" in checks["live_launch"].detail


def test_destructive_doctor_runs_live_probe_end_to_end(
    monkeypatch, tmp_path: Path
) -> None:
    import sys

    from nds_disassembly_toolkit.analysis.orchestration.model import LaunchSpec

    class LiveBackend:
        kind = EmulatorKind.DESMUME
        capabilities = EmulatorCapabilities(
            debugger_arm9=True,
            debugger_arm7=False,
            managed_launch=True,
            save_state=True,
            battery_save_isolation=True,
            window_input=False,
            touchscreen_input=False,
            screenshot=False,
            debugger_handshake_mode=DebuggerHandshakeMode.DIRECT,
        )

        def build_launch_spec(self, **kwargs: object) -> LaunchSpec:
            return LaunchSpec(argv=(sys.executable, "-c", "import time; time.sleep(60)"))

        def connect_debugger(self, **kwargs: object) -> object:
            class Debugger:
                def snapshot(self) -> object:
                    return object()

                def close(self) -> None:
                    pass

            return Debugger()

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.doctor.shutil.which",
        lambda name: sys.executable if name in {"desmume", "desmume-cli"} else None,
    )
    rom = tmp_path / "game.nds"
    rom.write_bytes(b"fixture")

    report = run_doctor(
        LiveBackend(),
        rom=rom,
        require=frozenset(),
        destructive=True,
        live_probe_timeout=5.0,
    )

    checks = {check.name: check for check in report.checks}
    assert checks["live_launch"].passed is True
    assert checks["live_debugger_handshake"].passed is True
    assert report.passed is True


def test_destructive_doctor_reports_failed_debugger_handshake(
    monkeypatch, tmp_path: Path
) -> None:
    import sys

    from nds_disassembly_toolkit.analysis.orchestration.model import LaunchSpec
    from nds_disassembly_toolkit.errors import RuntimeConnectionError

    class UnreachableBackend:
        kind = EmulatorKind.DESMUME
        capabilities = EmulatorCapabilities(
            debugger_arm9=True,
            debugger_arm7=False,
            managed_launch=True,
            save_state=True,
            battery_save_isolation=True,
            window_input=False,
            touchscreen_input=False,
            screenshot=False,
            debugger_handshake_mode=DebuggerHandshakeMode.DIRECT,
        )

        def build_launch_spec(self, **kwargs: object) -> LaunchSpec:
            return LaunchSpec(argv=(sys.executable, "-c", "import time; time.sleep(60)"))

        def connect_debugger(self, **kwargs: object) -> object:
            raise RuntimeConnectionError("debugger stub refused connection")

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.doctor.shutil.which",
        lambda name: sys.executable if name in {"desmume", "desmume-cli"} else None,
    )
    rom = tmp_path / "game.nds"
    rom.write_bytes(b"fixture")

    report = run_doctor(
        UnreachableBackend(),
        rom=rom,
        require=frozenset(),
        destructive=True,
        live_probe_timeout=2.0,
    )

    checks = {check.name: check for check in report.checks}
    assert checks["live_launch"].passed is True
    assert checks["live_debugger_handshake"].passed is False
    assert report.passed is False
