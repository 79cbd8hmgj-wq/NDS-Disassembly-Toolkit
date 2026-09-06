from __future__ import annotations

import nds_disassembly_toolkit.analysis.runtime as runtime
from nds_disassembly_toolkit.analysis.runtime import (
    BreakpointKind,
    RegisterSnapshot,
    RuntimeComponentLocation,
    RuntimeCpu,
    RuntimeLocation,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.errors import (
    NdsToolkitError,
    RuntimeAnalysisError,
    RuntimeConnectionError,
    RuntimeProtocolError,
    RuntimeTargetStateError,
    RuntimeTimeoutError,
)


def test_runtime_public_exports_are_available() -> None:
    assert RuntimeCpu.ARM9.value == "arm9"
    assert StopReasonKind.UNKNOWN.value == "unknown"
    assert BreakpointKind.CODE.value == "code"
    assert RegisterSnapshot is not None
    assert RuntimeStop is not None
    assert RuntimeSnapshot is not None
    assert RuntimeComponentLocation is not None
    assert RuntimeLocation is not None


def test_phase_7h2_trace_exports_are_available() -> None:
    for name in (
        "TRACE_SCHEMA_VERSION",
        "TraceCaptureMode",
        "TraceEventRole",
        "MemorySnapshotPhase",
        "TraceTermination",
        "TraceMemoryRegion",
        "TraceCaptureConfig",
        "TraceEvent",
        "MemorySnapshot",
        "TraceSummary",
    ):
        assert hasattr(runtime, name), name


def test_runtime_errors_share_toolkit_error_boundary() -> None:
    for error_type in (
        RuntimeAnalysisError,
        RuntimeConnectionError,
        RuntimeProtocolError,
        RuntimeTimeoutError,
        RuntimeTargetStateError,
    ):
        assert issubclass(error_type, NdsToolkitError)
    assert issubclass(RuntimeConnectionError, RuntimeAnalysisError)
    assert issubclass(RuntimeProtocolError, RuntimeAnalysisError)
    assert issubclass(RuntimeTimeoutError, RuntimeAnalysisError)
    assert issubclass(RuntimeTargetStateError, RuntimeAnalysisError)



def test_phase_7h3_orchestration_public_exports_are_available() -> None:
    import nds_disassembly_toolkit.analysis.orchestration as orchestration

    required = (
        "SESSION_SCHEMA_VERSION",
        "CHECKPOINT_SCHEMA_VERSION",
        "SCENARIO_SCHEMA_VERSION",
        "JOURNAL_SCHEMA_VERSION",
        "MATRIX_SCHEMA_VERSION",
        "EmulatorKind",
        "RuntimeSessionRecord",
        "DSButton",
        "DSPoint",
        "TouchTap",
        "TouchDrag",
        "TouchFlick",
        "CheckpointContext",
        "CheckpointMetadata",
        "create_checkpoint",
        "validate_checkpoint",
        "restore_checkpoint",
        "PredicateObservation",
        "PcEquals",
        "PcInRange",
        "RegisterEquals",
        "MemoryEquals",
        "MemoryMaskedEquals",
        "RuntimeMemoryWrite",
        "apply_guarded_write",
        "ParameterReference",
        "ScenarioDefinition",
        "ScenarioJournal",
        "JournalStepState",
        "load_scenario",
        "run_scenario",
        "resume_scenario",
        "AcceptanceCase",
        "AcceptanceMatrix",
        "AcceptanceCaseResult",
        "AcceptanceMatrixResult",
        "load_matrix",
        "run_acceptance_matrix",
        "RuntimeOrchestrationError",
        "RuntimeEnvironmentError",
        "RuntimeLaunchError",
        "RuntimeOwnershipError",
        "RuntimeDisplayError",
        "RuntimeInputError",
        "RuntimeCheckpointError",
        "RuntimeScenarioError",
        "RuntimeRecoveryError",
    )
    for name in required:
        assert hasattr(orchestration, name), name

    assert not hasattr(orchestration, "X11HostDriver")
