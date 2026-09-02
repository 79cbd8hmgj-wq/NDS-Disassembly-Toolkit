from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.cli import build_parser


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
