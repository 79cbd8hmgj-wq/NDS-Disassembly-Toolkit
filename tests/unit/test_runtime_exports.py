from __future__ import annotations

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
