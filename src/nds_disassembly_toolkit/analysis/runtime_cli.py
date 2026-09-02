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
from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces, inspect_trace
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    TraceDiffReport,
    TraceInspection,
)

_MAX_STEP_COUNT = 256
_MAX_TRACE_STEPS = 100000
_MAX_TRACE_EVENTS = 10000


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


def _bounded_positive_int(value: str, *, maximum: int, name: str) -> int:
    parsed = _positive_int(value)
    if parsed > maximum:
        raise argparse.ArgumentTypeError(
            f"{name} must be between 1 and {maximum}: {value}"
        )
    return parsed


def _step_count(value: str) -> int:
    return _bounded_positive_int(value, maximum=_MAX_STEP_COUNT, name="step count")


def _trace_steps(value: str) -> int:
    return _bounded_positive_int(value, maximum=_MAX_TRACE_STEPS, name="trace steps")


def _trace_events(value: str) -> int:
    return _bounded_positive_int(value, maximum=_MAX_TRACE_EVENTS, name="trace events")


def _memory_region_spec(value: str) -> str:
    address_text, separator, length_text = value.partition(":")
    if not separator or not address_text or not length_text:
        raise argparse.ArgumentTypeError(
            "memory region must use ADDRESS:LENGTH syntax"
        )
    address = _auto_int(address_text)
    length = _positive_int(length_text)
    if address > 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("memory region address exceeds 32-bit range")
    if address + length > 0x100000000:
        raise argparse.ArgumentTypeError("memory region exceeds 32-bit address space")
    return value


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


def _add_trace_capture_parser(commands: Any) -> None:
    capture = commands.add_parser("capture", help="capture a bounded runtime trace")
    _add_connection_arguments(capture)
    selectors = capture.add_mutually_exclusive_group(required=True)
    selectors.add_argument("--steps", type=_trace_steps)
    selectors.add_argument("--break", dest="break_address", type=_auto_int)
    selectors.add_argument("--watch-read", type=_auto_int)
    selectors.add_argument("--watch-write", type=_auto_int)
    selectors.add_argument("--watch-access", type=_auto_int)
    capture.add_argument("--events", type=_trace_events)
    capture.add_argument("--length", type=_positive_int, default=4)
    capture.add_argument("--memory", action="append", type=_memory_region_spec, default=[])
    _add_project_argument(capture)
    capture.add_argument("--label")
    capture.add_argument("--output", type=Path, required=True)


def _add_trace_parsers(commands: Any) -> None:
    trace = commands.add_parser("trace", help="capture or inspect portable runtime traces")
    trace_commands = trace.add_subparsers(dest="runtime_trace_command")
    _add_trace_capture_parser(trace_commands)

    inspect = trace_commands.add_parser("inspect", help="inspect a completed runtime trace")
    inspect.add_argument("trace", type=Path)
    _add_project_argument(inspect)
    _add_output_argument(inspect)


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

    _add_trace_parsers(commands)

    diff = commands.add_parser("diff", help="compare two completed runtime traces")
    diff.add_argument("baseline", type=Path)
    diff.add_argument("target", type=Path)
    _add_project_argument(diff)
    _add_output_argument(diff)


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


def _trace_inspection_json(inspection: TraceInspection) -> dict[str, object]:
    return {
        "addresses": [
            {
                "count": item.hit.count,
                "cpu": item.hit.cpu.value,
                "frequency": item.hit.frequency,
                "instruction_set": item.hit.instruction_set.value,
                "pc": _hex(item.hit.pc),
            }
            for item in inspection.addresses
        ],
        "capture_status": inspection.capture_status,
        "control_events": inspection.control_events,
        "evidence_events": inspection.evidence_events,
        "events": inspection.events,
        "integrity_ok": inspection.integrity_ok,
        "memory_regions": [
            {
                "address": _hex(item.region.address),
                "after_sha256": item.after_sha256,
                "before_sha256": item.before_sha256,
                "changed_bytes": item.changed_bytes,
                "changed_ranges": item.changed_ranges,
                "length": _hex(item.region.length),
                "ordinal": item.region.ordinal,
            }
            for item in inspection.memory_regions
        ],
        "trace_schema_version": inspection.trace_schema_version,
    }


def _trace_diff_json(report: TraceDiffReport) -> dict[str, object]:
    return {
        "address_deltas": [
            {
                "baseline_frequency": item.baseline_frequency,
                "baseline_hits": item.baseline_hits,
                "classification": item.classification,
                "cpu": item.cpu.value,
                "frequency_delta": item.frequency_delta,
                "instruction_set": item.instruction_set.value,
                "pc": _hex(item.pc),
                "target_frequency": item.target_frequency,
                "target_hits": item.target_hits,
            }
            for item in report.address_deltas
        ],
        "target_identity_verified": report.target_identity_verified,
    }


def _correlate_if_requested(
    project_path: Path | None,
    snapshot: RuntimeSnapshot,
) -> RuntimeLocation | None:
    if project_path is None:
        return None
    with AnalysisProject.open(project_path, read_only=True) as project:
        return correlate_snapshot(project, snapshot)


def _inspect_trace_command(arguments: argparse.Namespace) -> int:
    if arguments.runtime_trace_command != "inspect":
        raise ValueError("runtime trace requires capture or inspect")
    if arguments.project is None:
        inspection = inspect_trace(arguments.trace)
    else:
        with AnalysisProject.open(arguments.project, read_only=True) as project:
            inspection = inspect_trace(arguments.trace, project=project)
    _write_json(_trace_inspection_json(inspection), arguments.output)
    return 0


def _diff_trace_command(arguments: argparse.Namespace) -> int:
    if arguments.project is None:
        report = compare_traces(arguments.baseline, arguments.target)
    else:
        with AnalysisProject.open(arguments.project, read_only=True) as project:
            report = compare_traces(
                arguments.baseline,
                arguments.target,
                project=project,
            )
    _write_json(_trace_diff_json(report), arguments.output)
    return 0


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

    if command == "trace" and arguments.runtime_trace_command == "inspect":
        return _inspect_trace_command(arguments)
    if command == "diff":
        return _diff_trace_command(arguments)

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

        if command == "trace" and arguments.runtime_trace_command == "capture":
            raise ValueError("runtime trace capture is not implemented yet")

    raise ValueError(f"unknown runtime subcommand: {command}")
