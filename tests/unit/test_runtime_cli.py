from __future__ import annotations

import pytest

from nds_disassembly_toolkit.cli import build_parser


@pytest.mark.parametrize(
    ("argv", "runtime_command"),
    [
        (["runtime", "probe", "--cpu", "arm9"], "probe"),
        (
            [
                "runtime",
                "snapshot",
                "--cpu",
                "arm7",
                "--host",
                "127.0.0.1",
                "--port",
                "3334",
                "--project",
                "game.ndsre",
            ],
            "snapshot",
        ),
        (
            [
                "runtime",
                "read-memory",
                "--cpu",
                "arm9",
                "0x02000000",
                "0x100",
            ],
            "read-memory",
        ),
        (
            [
                "runtime",
                "run-until",
                "--cpu",
                "arm9",
                "--break",
                "0x02012340",
            ],
            "run-until",
        ),
        (
            [
                "runtime",
                "run-until",
                "--cpu",
                "arm9",
                "--watch-write",
                "0x02100000",
                "--length",
                "4",
            ],
            "run-until",
        ),
        (["runtime", "step", "--cpu", "arm9", "--count", "4"], "step"),
    ],
)
def test_runtime_parser_accepts_phase_7h1_commands(
    argv: list[str],
    runtime_command: str,
) -> None:
    arguments = build_parser().parse_args(argv)
    assert arguments.command == "runtime"
    assert arguments.runtime_command == runtime_command


def test_runtime_parser_requires_cpu() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["runtime", "probe"])
    assert exc_info.value.code == 2


def test_runtime_run_until_rejects_conflicting_stop_conditions() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(
            [
                "runtime",
                "run-until",
                "--cpu",
                "arm9",
                "--break",
                "0x02000000",
                "--watch-write",
                "0x02100000",
            ]
        )
    assert exc_info.value.code == 2


@pytest.mark.parametrize(
    "argv",
    [
        ["runtime", "read-memory", "--cpu", "arm9", "0x02000000", "0"],
        ["runtime", "run-until", "--cpu", "arm9", "--break", "0x02000000", "--length", "0"],
        ["runtime", "step", "--cpu", "arm9", "--count", "0"],
        ["runtime", "step", "--cpu", "arm9", "--count", "257"],
    ],
)
def test_runtime_parser_rejects_unsafe_bounds(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(argv)
    assert exc_info.value.code == 2
