from __future__ import annotations

import hashlib

import pytest

import nds_disassembly_toolkit.analysis.runtime as runtime
import nds_disassembly_toolkit.errors as errors


def test_trace_public_model_surface_exists() -> None:
    assert runtime.TRACE_SCHEMA_VERSION == 1
    assert runtime.TraceCaptureMode.STEP.value == "step"
    assert runtime.TraceEventRole.CONTROL_ADVANCE.value == "control_advance"
    assert runtime.MemorySnapshotPhase.BEFORE.value == "before"
    assert runtime.TraceTermination.LIMIT.value == "limit"


def test_step_trace_config_has_independent_large_bound() -> None:
    config = runtime.TraceCaptureConfig(
        cpu=runtime.RuntimeCpu.ARM9,
        mode=runtime.TraceCaptureMode.STEP,
        limit=100000,
        timeout=5.0,
    )
    assert config.limit == 100000


def test_trace_config_rejects_too_many_breakpoint_hits() -> None:
    with pytest.raises(ValueError, match="event limit"):
        runtime.TraceCaptureConfig(
            cpu=runtime.RuntimeCpu.ARM9,
            mode=runtime.TraceCaptureMode.BREAKPOINT,
            limit=10001,
            timeout=5.0,
            condition_kind=runtime.BreakpointKind.CODE,
            condition_address=0x02000000,
            condition_length=4,
        )


def test_memory_snapshot_computes_digest() -> None:
    region = runtime.TraceMemoryRegion(0, 0x02100000, 4)
    snapshot = runtime.MemorySnapshot.from_bytes(
        region,
        runtime.MemorySnapshotPhase.BEFORE,
        b"\x00\x01\x02\x03",
    )
    assert snapshot.sha256 == hashlib.sha256(snapshot.data).hexdigest()


def test_trace_errors_share_runtime_error_boundary() -> None:
    assert issubclass(errors.RuntimeTraceError, errors.RuntimeAnalysisError)
    assert issubclass(errors.RuntimeTraceFormatError, errors.RuntimeTraceError)
    assert issubclass(errors.RuntimeTraceMismatchError, errors.RuntimeTraceError)
