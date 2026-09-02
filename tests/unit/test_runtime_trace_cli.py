from __future__ import annotations

import json
from pathlib import Path

import pytest

import nds_disassembly_toolkit.analysis.runtime_cli as runtime_cli
from nds_disassembly_toolkit.analysis import InstructionSet
from nds_disassembly_toolkit.analysis.runtime import (
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceEvent,
    TraceEventRole,
    TraceSummary,
    TraceTermination,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore
from nds_disassembly_toolkit.cli import build_parser


def _write_trace(path: Path, pc: int) -> None:
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=1,
        timeout=5.0,
    )
    registers = RegisterSnapshot.from_mapping({"pc": pc, "cpsr": 0x13})
    event = TraceEvent(
        ordinal=0,
        role=TraceEventRole.EVIDENCE,
        cpu=RuntimeCpu.ARM9,
        pc=pc,
        cpsr=0x13,
        instruction_set=InstructionSet.ARM,
        stop=RuntimeStop(StopReasonKind.STEP, address=pc),
        registers=registers,
    )
    with TraceStore.create_atomic(path, config) as store:
        store.append_event(event)
        store.finalize(
            TraceSummary(
                trace=path,
                cpu=RuntimeCpu.ARM9,
                capture_mode=TraceCaptureMode.STEP,
                evidence_events=1,
                control_events=0,
                memory_regions=0,
                terminated_by=TraceTermination.LIMIT,
                project_fingerprint=None,
            )
        )


def test_runtime_trace_parser_accepts_nested_capture_inspect_and_diff() -> None:
    capture = build_parser().parse_args(
        [
            "runtime",
            "trace",
            "capture",
            "--cpu",
            "arm9",
            "--steps",
            "2000",
            "--memory",
            "0x02100000:0x1000",
            "--memory",
            "0x02200000:0x400",
            "--output",
            "attack.ndstrace",
        ]
    )
    assert capture.command == "runtime"
    assert capture.runtime_command == "trace"
    assert capture.runtime_trace_command == "capture"
    assert capture.cpu is RuntimeCpu.ARM9
    assert capture.steps == 2000
    assert capture.memory == ["0x02100000:0x1000", "0x02200000:0x400"]
    assert capture.output == Path("attack.ndstrace")

    inspect = build_parser().parse_args(
        [
            "runtime",
            "trace",
            "inspect",
            "attack.ndstrace",
            "--project",
            "game.ndsre",
            "--output",
            "inspect.json",
        ]
    )
    assert inspect.runtime_command == "trace"
    assert inspect.runtime_trace_command == "inspect"
    assert inspect.trace == Path("attack.ndstrace")
    assert inspect.project == Path("game.ndsre")

    diff = build_parser().parse_args(
        [
            "runtime",
            "diff",
            "idle.ndstrace",
            "attack.ndstrace",
            "--project",
            "game.ndsre",
        ]
    )
    assert diff.runtime_command == "diff"
    assert diff.baseline == Path("idle.ndstrace")
    assert diff.target == Path("attack.ndstrace")


@pytest.mark.parametrize(
    "selector",
    [
        ["--steps", "100001"],
        ["--break", "0x02000100", "--events", "10001"],
        ["--watch-write", "0x02100000", "--length", "0", "--events", "1"],
    ],
)
def test_runtime_trace_capture_rejects_unsafe_selector_bounds(selector: list[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(
            [
                "runtime",
                "trace",
                "capture",
                "--cpu",
                "arm9",
                *selector,
                "--output",
                "bad.ndstrace",
            ]
        )
    assert exc_info.value.code == 2


def test_runtime_trace_capture_requires_exactly_one_selector() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as missing:
        parser.parse_args(
            [
                "runtime",
                "trace",
                "capture",
                "--cpu",
                "arm9",
                "--output",
                "bad.ndstrace",
            ]
        )
    assert missing.value.code == 2

    with pytest.raises(SystemExit) as conflicting:
        parser.parse_args(
            [
                "runtime",
                "trace",
                "capture",
                "--cpu",
                "arm9",
                "--steps",
                "2",
                "--break",
                "0x02000000",
                "--events",
                "2",
                "--output",
                "bad.ndstrace",
            ]
        )
    assert conflicting.value.code == 2


def test_runtime_trace_capture_rejects_malformed_memory_region() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(
            [
                "runtime",
                "trace",
                "capture",
                "--cpu",
                "arm9",
                "--steps",
                "2",
                "--memory",
                "0x02100000",
                "--output",
                "bad.ndstrace",
            ]
        )
    assert exc_info.value.code == 2


def test_interactive_step_limit_remains_256() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(
            ["runtime", "step", "--cpu", "arm9", "--count", "257"]
        )
    assert exc_info.value.code == 2


def test_runtime_trace_inspect_is_offline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    trace = tmp_path / "trace.ndstrace"
    _write_trace(trace, 0x02000100)

    def _fail_connect(arguments: object) -> object:
        raise AssertionError("offline trace inspection attempted debugger connection")

    monkeypatch.setattr(runtime_cli, "_connect", _fail_connect)
    arguments = build_parser().parse_args(
        ["runtime", "trace", "inspect", str(trace)]
    )

    assert runtime_cli.run_runtime_command(arguments) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["evidence_events"] == 1
    assert payload["integrity_ok"] is True


def test_runtime_trace_diff_is_offline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    baseline = tmp_path / "baseline.ndstrace"
    target = tmp_path / "target.ndstrace"
    _write_trace(baseline, 0x02000100)
    _write_trace(target, 0x02000200)

    def _fail_connect(arguments: object) -> object:
        raise AssertionError("offline trace diff attempted debugger connection")

    monkeypatch.setattr(runtime_cli, "_connect", _fail_connect)
    arguments = build_parser().parse_args(
        ["runtime", "diff", str(baseline), str(target)]
    )

    assert runtime_cli.run_runtime_command(arguments) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["target_identity_verified"] is False
    assert [item["classification"] for item in payload["address_deltas"]] == [
        "baseline_only",
        "target_only",
    ]
