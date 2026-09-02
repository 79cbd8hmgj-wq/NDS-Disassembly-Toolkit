from __future__ import annotations

import json
from pathlib import Path
from types import TracebackType

import pytest

import nds_disassembly_toolkit.analysis.runtime_cli as runtime_cli
from nds_disassembly_toolkit.analysis.project import AnalysisProject
from nds_disassembly_toolkit.analysis.runtime import (
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.correlation import analysis_project_fingerprint
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore
from nds_disassembly_toolkit.cli import build_parser


class FakeCaptureSession:
    cpu = RuntimeCpu.ARM9

    def __init__(self) -> None:
        self.steps = 0
        self.closed = False

    def __enter__(self) -> FakeCaptureSession:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.closed = True

    def step(self) -> RuntimeSnapshot:
        self.steps += 1
        pc = 0x02000100 + (self.steps * 4)
        return RuntimeSnapshot(
            cpu=self.cpu,
            registers=RegisterSnapshot.from_mapping({"pc": pc, "cpsr": 0x13}),
            stop=RuntimeStop(StopReasonKind.STEP, address=pc),
        )

    def read_memory(self, address: int, length: int) -> bytes:
        return bytes((address + index) & 0xFF for index in range(length))

    def run_until_breakpoint(self, address: int, *, length: int = 4) -> RuntimeSnapshot:
        raise AssertionError("step capture should not use breakpoint execution")

    def run_until_watchpoint(
        self,
        kind: object,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        raise AssertionError("step capture should not use watchpoint execution")


def test_runtime_trace_capture_writes_trace_and_exact_summary_keys(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = FakeCaptureSession()
    monkeypatch.setattr(runtime_cli, "_connect", lambda arguments: session)
    destination = tmp_path / "attack.ndstrace"
    arguments = build_parser().parse_args(
        [
            "runtime",
            "trace",
            "capture",
            "--cpu",
            "arm9",
            "--steps",
            "2",
            "--memory",
            "0x02100000:4",
            "--output",
            str(destination),
        ]
    )

    assert runtime_cli.run_runtime_command(arguments) == 0

    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {
        "trace",
        "cpu",
        "capture_mode",
        "evidence_events",
        "control_events",
        "memory_regions",
        "terminated_by",
        "project_fingerprint",
    }
    assert payload["trace"] == str(destination)
    assert payload["cpu"] == "arm9"
    assert payload["capture_mode"] == "step"
    assert payload["evidence_events"] == 2
    assert payload["memory_regions"] == 1
    assert destination.read_bytes().startswith(b"SQLite format 3\x00")
    store = TraceStore.open(destination)
    try:
        assert len(store.events()) == 2
        assert len(store.config.memory_regions) == 1
    finally:
        store.close()
    assert session.closed is True


def test_runtime_trace_capture_fingerprints_project_before_connect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project_path = tmp_path / "game.ndsre"
    with AnalysisProject.create(project_path) as project:
        expected_fingerprint = analysis_project_fingerprint(project)

    session = FakeCaptureSession()
    observed: dict[str, object] = {}

    def _connect(arguments: object) -> FakeCaptureSession:
        observed["project_writable_marker_exists"] = (project_path / "analysis.sqlite-wal").exists()
        return session

    monkeypatch.setattr(runtime_cli, "_connect", _connect)
    destination = tmp_path / "project.ndstrace"
    arguments = build_parser().parse_args(
        [
            "runtime",
            "trace",
            "capture",
            "--cpu",
            "arm9",
            "--steps",
            "1",
            "--project",
            str(project_path),
            "--output",
            str(destination),
        ]
    )

    assert runtime_cli.run_runtime_command(arguments) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["project_fingerprint"] == expected_fingerprint
    store = TraceStore.open(destination)
    try:
        assert store.config.project_fingerprint == expected_fingerprint
    finally:
        store.close()
    assert observed["project_writable_marker_exists"] is False


def test_runtime_trace_capture_rejects_semantic_config_before_connect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def _fail_connect(arguments: object) -> object:
        raise AssertionError("invalid capture config reached debugger connection")

    monkeypatch.setattr(runtime_cli, "_connect", _fail_connect)
    arguments = build_parser().parse_args(
        [
            "runtime",
            "trace",
            "capture",
            "--cpu",
            "arm9",
            "--steps",
            "2",
            "--events",
            "2",
            "--output",
            str(tmp_path / "bad.ndstrace"),
        ]
    )

    with pytest.raises(ValueError, match="events"):
        runtime_cli.run_runtime_command(arguments)
