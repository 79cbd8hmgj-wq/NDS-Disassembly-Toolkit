from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from nds_disassembly_toolkit.analysis.model import FunctionCandidate, Symbol
from nds_disassembly_toolkit.analysis.project import AnalysisProject, LocationAnnotation
from nds_disassembly_toolkit.analysis.runtime import (
    BreakpointKind,
    MelonDSSession,
    RuntimeComponentLocation,
    RuntimeCpu,
    RuntimeLocation,
    RuntimeSnapshot,
    correlate_snapshot,
)
from nds_disassembly_toolkit.analysis.runtime.rsp import RSPCapabilities

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


def _hex(value: int) -> str:
    if value < 0:
        raise ValueError("unsigned hexadecimal value cannot be negative")
    return f"0x{value:08x}"


def _write_json(payload: object, output: Path | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(output)


def _capabilities_json(capabilities: RSPCapabilities) -> dict[str, object]:
    return {
        "features": [
            {"name": name, "value": value}
            for name, value in capabilities.features
        ],
        "packet_size": (
            None if capabilities.packet_size is None else _hex(capabilities.packet_size)
        ),
    }


def _function_json(function: FunctionCandidate | None) -> dict[str, object] | None:
    if function is None:
        return None
    return {
        "address": _hex(function.address),
        "component": function.component,
        "confidence": function.confidence,
        "evidence": list(function.evidence),
        "instruction_set": function.instruction_set.value,
        "offset": _hex(function.offset),
    }


def _symbol_json(symbol: Symbol) -> dict[str, object]:
    return {
        "address": _hex(symbol.address),
        "component": symbol.component,
        "confidence": symbol.confidence,
        "evidence": list(symbol.evidence),
        "instruction_set": (
            None if symbol.instruction_set is None else symbol.instruction_set.value
        ),
        "kind": symbol.kind.value,
        "name": symbol.name,
        "offset": _hex(symbol.offset),
    }


def _annotation_json(
    annotation: LocationAnnotation | None,
) -> dict[str, object] | None:
    if annotation is None:
        return None
    return {
        "address": _hex(annotation.address),
        "bookmarked": annotation.bookmarked,
        "comment": annotation.comment,
        "component": annotation.component,
        "name_override": annotation.name_override,
        "tags": list(annotation.tags),
    }


def _component_location_json(
    candidate: RuntimeComponentLocation,
) -> dict[str, object]:
    return {
        "annotation": _annotation_json(candidate.annotation),
        "component": candidate.component,
        "function": _function_json(candidate.function),
        "symbols": [_symbol_json(symbol) for symbol in candidate.symbols],
    }


def _runtime_location_json(location: RuntimeLocation) -> dict[str, object]:
    return {
        "candidates": [
            _component_location_json(candidate) for candidate in location.candidates
        ],
        "instruction_set": location.instruction_set.value,
        "pc": _hex(location.pc),
    }


def _snapshot_json(
    snapshot: RuntimeSnapshot,
    correlation: RuntimeLocation | None,
) -> dict[str, object]:
    return {
        "correlation": (
            None if correlation is None else _runtime_location_json(correlation)
        ),
        "cpu": snapshot.cpu.value,
        "cpsr": _hex(snapshot.cpsr),
        "instruction_set": snapshot.instruction_set.value,
        "pc": _hex(snapshot.pc),
        "registers": [
            {"name": name, "value": _hex(value)}
            for name, value in snapshot.registers.values
        ],
        "stop": {
            "address": (
                None if snapshot.stop.address is None else _hex(snapshot.stop.address)
            ),
            "kind": snapshot.stop.kind.value,
            "raw": snapshot.stop.raw,
            "signal": snapshot.stop.signal,
        },
    }


def _correlate_if_requested(
    project_path: Path | None,
    snapshot: RuntimeSnapshot,
) -> RuntimeLocation | None:
    if project_path is None:
        return None
    with AnalysisProject.open(project_path, read_only=True) as project:
        return correlate_snapshot(project, snapshot)


def _connect(arguments: argparse.Namespace) -> MelonDSSession:
    return MelonDSSession.connect(
        cpu=arguments.cpu,
        host=arguments.host,
        port=arguments.port,
        timeout=arguments.timeout,
    )


def _run_until(
    session: MelonDSSession,
    arguments: argparse.Namespace,
) -> tuple[RuntimeSnapshot, dict[str, object]]:
    length = arguments.length
    if arguments.break_address is not None:
        address = arguments.break_address
        snapshot = session.run_until_breakpoint(address, length=length)
        kind = "breakpoint"
    elif arguments.watch_read is not None:
        address = arguments.watch_read
        snapshot = session.run_until_watchpoint(
            BreakpointKind.READ,
            address,
            length=length,
        )
        kind = BreakpointKind.READ.value
    elif arguments.watch_write is not None:
        address = arguments.watch_write
        snapshot = session.run_until_watchpoint(
            BreakpointKind.WRITE,
            address,
            length=length,
        )
        kind = BreakpointKind.WRITE.value
    elif arguments.watch_access is not None:
        address = arguments.watch_access
        snapshot = session.run_until_watchpoint(
            BreakpointKind.ACCESS,
            address,
            length=length,
        )
        kind = BreakpointKind.ACCESS.value
    else:
        raise ValueError("runtime run-until requires one stop condition")
    return snapshot, {
        "address": _hex(address),
        "kind": kind,
        "length": _hex(length),
    }


def run_runtime_command(arguments: argparse.Namespace) -> int:
    command = arguments.runtime_command
    if command is None:
        raise ValueError("a runtime subcommand is required")

    with _connect(arguments) as session:
        if command == "probe":
            payload = {
                "capabilities": _capabilities_json(session.capabilities),
                "cpu": arguments.cpu.value,
                "host": arguments.host,
                "port": (
                    arguments.cpu.default_port
                    if arguments.port is None
                    else arguments.port
                ),
            }
            _write_json(payload, arguments.output)
            return 0

        if command == "snapshot":
            snapshot = session.snapshot()
            correlation = _correlate_if_requested(arguments.project, snapshot)
            _write_json(_snapshot_json(snapshot, correlation), arguments.output)
            return 0

        if command == "read-memory":
            data = session.read_memory(arguments.address, arguments.length)
            payload = {
                "address": _hex(arguments.address),
                "cpu": arguments.cpu.value,
                "data": data.hex(),
                "length": _hex(arguments.length),
            }
            _write_json(payload, arguments.output)
            return 0

        if command == "run-until":
            snapshot, condition = _run_until(session, arguments)
            correlation = _correlate_if_requested(arguments.project, snapshot)
            _write_json(
                {
                    "condition": condition,
                    "snapshot": _snapshot_json(snapshot, correlation),
                },
                arguments.output,
            )
            return 0

        if command == "step":
            snapshots = [session.step() for _ in range(arguments.count)]
            final = snapshots[-1]
            correlation = _correlate_if_requested(arguments.project, final)
            _write_json(
                {
                    "count": arguments.count,
                    "final_snapshot": _snapshot_json(final, correlation),
                    "stop_pcs": [_hex(snapshot.pc) for snapshot in snapshots],
                },
                arguments.output,
            )
            return 0

    raise ValueError(f"unknown runtime subcommand: {command}")
