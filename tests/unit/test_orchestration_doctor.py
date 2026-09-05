from __future__ import annotations

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
