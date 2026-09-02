from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration import (
    CHECKPOINT_SCHEMA_VERSION,
    JOURNAL_SCHEMA_VERSION,
    MATRIX_SCHEMA_VERSION,
    SCENARIO_SCHEMA_VERSION,
    SESSION_SCHEMA_VERSION,
    DebuggerHandshakeMode,
    DoctorCheckResult,
    EmulatorCapabilities,
    EmulatorKind,
    LaunchSpec,
    ProcessIdentity,
    RuntimeLifecycleState,
    RuntimeSessionRecord,
)
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.errors import (
    NdsToolkitError,
    RuntimeAnalysisError,
    RuntimeCheckpointError,
    RuntimeDisplayError,
    RuntimeEnvironmentError,
    RuntimeInputError,
    RuntimeLaunchError,
    RuntimeOrchestrationError,
    RuntimeOwnershipError,
    RuntimeRecoveryError,
    RuntimeScenarioError,
)


def _session(tmp_path: Path, *, debugger_port: int = 39001) -> RuntimeSessionRecord:
    return RuntimeSessionRecord(
        schema_version=SESSION_SCHEMA_VERSION,
        session_id="0123456789abcdef0123456789abcdef",
        lifecycle=RuntimeLifecycleState.CREATED,
        emulator=EmulatorKind.DESMUME,
        emulator_executable=tmp_path / "desmume",
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=None,
        process_group=None,
        process_start_identity=None,
        debugger_host="127.0.0.1",
        debugger_port=debugger_port,
        display=None,
        window_id=None,
        session_root=tmp_path,
        last_completed_step=None,
        last_completed_case=None,
    )


def test_orchestration_schema_versions_start_at_one() -> None:
    assert SESSION_SCHEMA_VERSION == 1
    assert CHECKPOINT_SCHEMA_VERSION == 1
    assert SCENARIO_SCHEMA_VERSION == 1
    assert JOURNAL_SCHEMA_VERSION == 1
    assert MATRIX_SCHEMA_VERSION == 1


def test_runtime_enums_use_stable_values() -> None:
    assert EmulatorKind.MELONDS.value == "melonds"
    assert EmulatorKind.DESMUME.value == "desmume"
    assert DebuggerHandshakeMode.INITIAL_ACK.value == "initial_ack"
    assert DebuggerHandshakeMode.DIRECT.value == "direct"
    assert RuntimeLifecycleState.CREATED.value == "created"
    assert RuntimeLifecycleState.READY.value == "ready"
    assert RuntimeLifecycleState.FAILED.value == "failed"


def test_session_record_is_immutable_and_validates_debugger_port(tmp_path: Path) -> None:
    session = _session(tmp_path)
    with pytest.raises(AttributeError):
        session.debugger_port = 39002  # type: ignore[misc]

    with pytest.raises(ValueError, match="debugger port"):
        _session(tmp_path, debugger_port=0)
    with pytest.raises(ValueError, match="debugger port"):
        _session(tmp_path, debugger_port=65536)


def test_session_record_requires_non_empty_session_id(tmp_path: Path) -> None:
    session = _session(tmp_path)
    values = {
        field: getattr(session, field)
        for field in session.__dataclass_fields__
    }
    values["session_id"] = ""
    with pytest.raises(ValueError, match="session id"):
        RuntimeSessionRecord(**values)


def test_session_record_requires_lowercase_sha256(tmp_path: Path) -> None:
    session = _session(tmp_path)
    values = {
        field: getattr(session, field)
        for field in session.__dataclass_fields__
    }
    values["rom_sha256"] = "A" * 64
    with pytest.raises(ValueError, match="ROM SHA-256"):
        RuntimeSessionRecord(**values)


def test_capabilities_launch_process_and_doctor_records_are_immutable(tmp_path: Path) -> None:
    capabilities = EmulatorCapabilities(
        debugger_arm9=True,
        debugger_arm7=False,
        managed_launch=True,
        save_state=False,
        battery_save_isolation=True,
        window_input=True,
        touchscreen_input=True,
        screenshot=True,
        debugger_handshake_mode=DebuggerHandshakeMode.DIRECT,
    )
    launch = LaunchSpec(
        argv=(str(tmp_path / "desmume"), str(tmp_path / "game.nds")),
        environment=(("DISPLAY", ":101"),),
        cwd=tmp_path,
    )
    process = ProcessIdentity(
        pid=1234,
        process_group=1234,
        start_identity="424242",
        executable=tmp_path / "desmume",
        executable_sha256="1" * 64,
    )
    check = DoctorCheckResult(
        name="debugger",
        passed=True,
        detail="reachable",
    )

    assert capabilities.debugger_handshake_mode is DebuggerHandshakeMode.DIRECT
    assert launch.argv[0].endswith("desmume")
    assert process.pid == 1234
    assert check.passed is True
    with pytest.raises(AttributeError):
        check.passed = False  # type: ignore[misc]


def test_orchestration_errors_share_runtime_analysis_boundary() -> None:
    assert issubclass(RuntimeOrchestrationError, RuntimeAnalysisError)
    assert issubclass(RuntimeOrchestrationError, NdsToolkitError)
    for error_type in (
        RuntimeEnvironmentError,
        RuntimeLaunchError,
        RuntimeOwnershipError,
        RuntimeDisplayError,
        RuntimeInputError,
        RuntimeCheckpointError,
        RuntimeScenarioError,
        RuntimeRecoveryError,
    ):
        assert issubclass(error_type, RuntimeOrchestrationError)
