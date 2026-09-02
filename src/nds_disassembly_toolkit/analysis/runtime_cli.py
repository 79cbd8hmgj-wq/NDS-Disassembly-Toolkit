from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu

_MAX_STEP_COUNT = 256


def _auto_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer/address: {value}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError(f"value must be non-negative: {value}")
    return parsed


def _positive_int(value: str) -> int:
    parsed = _auto_int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"value must be positive: {value}")
    return parsed


def _step_count(value: str) -> int:
    parsed = _positive_int(value)
    if parsed > _MAX_STEP_COUNT:
        raise argparse.ArgumentTypeError(
            f"step count must be between 1 and {_MAX_STEP_COUNT}: {value}"
        )
    return parsed


def _port(value: str) -> int:
    parsed = _positive_int(value)
    if parsed > 65535:
        raise argparse.ArgumentTypeError(f"port must be between 1 and 65535: {value}")
    return parsed


def _timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid timeout: {value}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"timeout must be positive: {value}")
    return parsed


def _cpu(value: str) -> RuntimeCpu:
    try:
        return RuntimeCpu(value.lower())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("CPU must be 'arm9' or 'arm7'") from exc


def _add_connection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cpu", type=_cpu, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=_port)
    parser.add_argument("--timeout", type=_timeout, default=5.0)


def _add_project_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", type=Path)


def _add_output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path)


def add_runtime_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "runtime",
        help="inspect a running Nintendo DS target through a GDB RSP stub",
    )
    commands = parser.add_subparsers(dest="runtime_command")

    probe = commands.add_parser("probe", help="probe runtime debugger capabilities")
    _add_connection_arguments(probe)
    _add_output_argument(probe)

    snapshot = commands.add_parser("snapshot", help="capture a stopped runtime snapshot")
    _add_connection_arguments(snapshot)
    _add_project_argument(snapshot)
    _add_output_argument(snapshot)

    read_memory = commands.add_parser("read-memory", help="read runtime memory")
    _add_connection_arguments(read_memory)
    read_memory.add_argument("address", type=_auto_int)
    read_memory.add_argument("length", type=_positive_int)
    _add_output_argument(read_memory)

    run_until = commands.add_parser(
        "run-until",
        help="continue until one temporary breakpoint or watchpoint stops the target",
    )
    _add_connection_arguments(run_until)
    conditions = run_until.add_mutually_exclusive_group(required=True)
    conditions.add_argument("--break", dest="break_address", type=_auto_int)
    conditions.add_argument("--watch-read", type=_auto_int)
    conditions.add_argument("--watch-write", type=_auto_int)
    conditions.add_argument("--watch-access", type=_auto_int)
    run_until.add_argument("--length", type=_positive_int, default=4)
    _add_project_argument(run_until)
    _add_output_argument(run_until)

    step = commands.add_parser("step", help="single-step a bounded instruction count")
    _add_connection_arguments(step)
    step.add_argument("--count", type=_step_count, default=1)
    _add_project_argument(step)
    _add_output_argument(step)
