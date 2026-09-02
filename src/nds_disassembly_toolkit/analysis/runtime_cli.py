from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from nds_disassembly_toolkit.analysis.model import CrossReference, FunctionCandidate, Symbol
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
from nds_disassembly_toolkit.analysis.runtime.capture import capture_trace
from nds_disassembly_toolkit.analysis.runtime.correlation import analysis_project_fingerprint
from nds_disassembly_toolkit.analysis.runtime.memory_diff import diff_trace_memory
from nds_disassembly_toolkit.analysis.runtime.rsp import RSPCapabilities
from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces, inspect_trace
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    MemoryChange,
    RankedFunctionCandidate,
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceDiffReport,
    TraceEventCorrelation,
    TraceFunctionDelta,
    TraceInspection,
    TraceMemoryRegion,
    TraceSummary,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore

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
    capture.add_argument("--length", type=_positive_int)
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


def _width_hex(value: int, width: int) -> str:
    if value < 0:
        raise ValueError("unsigned hexadecimal value cannot be negative")
    return f"0x{value:0{width * 2}x}"


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


def _trace_config_json(config: TraceCaptureConfig) -> dict[str, object]:
    condition: dict[str, object] | None = None
    if config.condition_kind is not None:
        condition = {
            "address": (
                None if config.condition_address is None else _hex(config.condition_address)
            ),
            "kind": config.condition_kind.value,
            "length": (
                None if config.condition_length is None else _hex(config.condition_length)
            ),
        }
    return {
        "capture_mode": config.mode.value,
        "condition": condition,
        "cpu": config.cpu.value,
        "label": config.label,
        "limit": config.limit,
        "memory_regions": [
            {
                "address": _hex(region.address),
                "label": region.label,
                "length": _hex(region.length),
                "ordinal": region.ordinal,
            }
            for region in config.memory_regions
        ],
        "project_fingerprint": config.project_fingerprint,
        "timeout": config.timeout,
        "toolkit_version": config.toolkit_version,
        "trace_schema_version": config.trace_schema_version,
    }


def _trace_event_correlation_json(
    correlation: TraceEventCorrelation | None,
) -> dict[str, object] | None:
    if correlation is None:
        return None
    return {
        "ambiguous": correlation.ambiguous,
        "candidates": [
            {
                "annotation": _annotation_json(candidate.annotation),
                "component": candidate.component,
                "functions": [
                    _function_json(function) for function in candidate.functions
                ],
                "symbols": [_symbol_json(symbol) for symbol in candidate.symbols],
            }
            for candidate in correlation.candidates
        ],
        "instruction_set": correlation.instruction_set.value,
        "pc": _hex(correlation.pc),
        "resolved_function": _function_json(correlation.resolved_function),
    }


def _memory_change_json(change: MemoryChange) -> dict[str, object]:
    def aligned(values: tuple[Any, ...]) -> list[dict[str, object]]:
        return [
            {
                "address": _hex(value.address),
                "after": _width_hex(value.after, value.width),
                "before": _width_hex(value.before, value.width),
                "width": value.width,
            }
            for value in values
        ]

    return {
        "address": _hex(change.address),
        "after": change.after.hex(),
        "before": change.before.hex(),
        "region_ordinal": change.region_ordinal,
        "values16": aligned(change.values16),
        "values32": aligned(change.values32),
    }


def _xref_json(reference: CrossReference) -> dict[str, object]:
    return {
        "kind": reference.kind.value,
        "source_address": _hex(reference.source_address),
        "source_component": reference.source_component,
        "source_function_address": (
            None
            if reference.source_function_address is None
            else _hex(reference.source_function_address)
        ),
        "source_instruction_set": (
            None
            if reference.source_instruction_set is None
            else reference.source_instruction_set.value
        ),
        "target_address": _hex(reference.target_address),
        "target_instruction_set": (
            None
            if reference.target_instruction_set is None
            else reference.target_instruction_set.value
        ),
    }


def _trace_function_delta_json(delta: TraceFunctionDelta) -> dict[str, object]:
    return {
        "address": _hex(delta.address),
        "annotation": _annotation_json(delta.annotation),
        "baseline_frequency": delta.baseline_frequency,
        "baseline_hits": delta.baseline_hits,
        "changed_memory_references": [
            _xref_json(reference) for reference in delta.changed_memory_references
        ],
        "classification": delta.classification,
        "component": delta.component,
        "condition_hit": delta.condition_hit,
        "condition_stop_pcs": [_hex(pc) for pc in delta.condition_stop_pcs],
        "dynamic_pcs": [_hex(pc) for pc in delta.dynamic_pcs],
        "instruction_set": delta.instruction_set.value,
        "symbols": [_symbol_json(symbol) for symbol in delta.symbols],
        "target_frequency": delta.target_frequency,
        "target_hits": delta.target_hits,
    }


def _ranked_function_json(candidate: RankedFunctionCandidate) -> dict[str, object]:
    return {
        "address": _hex(candidate.address),
        "component": candidate.component,
        "evidence": [
            {
                "contribution": evidence.contribution,
                "name": evidence.name,
                "reasons": list(evidence.reasons),
                "value": evidence.value,
                "weight": evidence.weight,
            }
            for evidence in candidate.evidence
        ],
        "instruction_set": candidate.instruction_set.value,
        "score": candidate.score,
    }


def _trace_inspection_json(inspection: TraceInspection) -> dict[str, object]:
    return {
        "addresses": [
            {
                "correlation": _trace_event_correlation_json(item.correlation),
                "count": item.hit.count,
                "cpu": item.hit.cpu.value,
                "frequency": item.hit.frequency,
                "instruction_set": item.hit.instruction_set.value,
                "pc": _hex(item.hit.pc),
            }
            for item in inspection.addresses
        ],
        "capture_status": inspection.capture_status,
        "config": _trace_config_json(inspection.config),
        "control_events": inspection.control_events,
        "evidence_events": inspection.evidence_events,
        "events": inspection.events,
        "integrity_ok": inspection.integrity_ok,
        "memory_changes": [
            _memory_change_json(change) for change in inspection.memory_changes
        ],
        "memory_regions": [
            {
                "address": _hex(item.region.address),
                "after_sha256": item.after_sha256,
                "before_sha256": item.before_sha256,
                "changed_bytes": item.changed_bytes,
                "changed_ranges": item.changed_ranges,
                "label": item.region.label,
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
        "ambiguous_correlations": [
            _trace_event_correlation_json(correlation)
            for correlation in report.ambiguous_correlations
        ],
        "baseline_config": _trace_config_json(report.baseline_config),
        "baseline_memory_changes": [
            _memory_change_json(change) for change in report.baseline_memory_changes
        ],
        "function_deltas": [
            _trace_function_delta_json(delta) for delta in report.function_deltas
        ],
        "rankings": [_ranked_function_json(candidate) for candidate in report.rankings],
        "target_config": _trace_config_json(report.target_config),
        "target_identity_verified": report.target_identity_verified,
        "target_memory_changes": [
            _memory_change_json(change) for change in report.target_memory_changes
        ],
    }


def _trace_summary_json(summary: TraceSummary) -> dict[str, object]:
    return {
        "trace": str(summary.trace),
        "cpu": summary.cpu.value,
        "capture_mode": summary.capture_mode.value,
        "evidence_events": summary.evidence_events,
        "control_events": summary.control_events,
        "memory_regions": summary.memory_regions,
        "terminated_by": summary.terminated_by.value,
        "project_fingerprint": summary.project_fingerprint,
    }


def _correlate_if_requested(
    project_path: Path | None,
    snapshot: RuntimeSnapshot,
) -> RuntimeLocation | None:
    if project_path is None:
        return None
    with AnalysisProject.open(project_path, read_only=True) as project:
        return correlate_snapshot(project, snapshot)


def _inspection_with_memory_changes(
    trace: Path,
    inspection: TraceInspection,
) -> TraceInspection:
    store = TraceStore.open(trace)
    try:
        memory_changes = diff_trace_memory(store)
    finally:
        store.close()
    return replace(inspection, memory_changes=memory_changes)


def _inspect_trace_command(arguments: argparse.Namespace) -> int:
    if arguments.runtime_trace_command != "inspect":
        raise ValueError("runtime trace requires capture or inspect")
    if arguments.project is None:
        inspection = inspect_trace(arguments.trace)
    else:
        with AnalysisProject.open(arguments.project, read_only=True) as project:
            inspection = inspect_trace(arguments.trace, project=project)
    inspection = _inspection_with_memory_changes(arguments.trace, inspection)
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


def _toolkit_version() -> str | None:
    try:
        return version("nds-disassembly-toolkit")
    except PackageNotFoundError:
        return None


def _trace_memory_regions(specs: list[str]) -> tuple[TraceMemoryRegion, ...]:
    regions: list[TraceMemoryRegion] = []
    for ordinal, spec in enumerate(specs):
        address_text, _, length_text = spec.partition(":")
        regions.append(
            TraceMemoryRegion(
                ordinal=ordinal,
                address=int(address_text, 0),
                length=int(length_text, 0),
            )
        )
    return tuple(regions)


def _capture_project_fingerprint(project_path: Path | None) -> str | None:
    if project_path is None:
        return None
    with AnalysisProject.open(project_path, read_only=True) as project:
        return analysis_project_fingerprint(project)


def _trace_capture_config(arguments: argparse.Namespace) -> TraceCaptureConfig:
    project_fingerprint = _capture_project_fingerprint(arguments.project)
    memory_regions = _trace_memory_regions(arguments.memory)

    if arguments.steps is not None:
        if arguments.events is not None:
            raise ValueError("step trace cannot define --events")
        if arguments.length is not None:
            raise ValueError("step trace cannot define --length")
        return TraceCaptureConfig(
            cpu=arguments.cpu,
            mode=TraceCaptureMode.STEP,
            limit=arguments.steps,
            timeout=arguments.timeout,
            memory_regions=memory_regions,
            label=arguments.label,
            project_fingerprint=project_fingerprint,
            toolkit_version=_toolkit_version(),
        )

    if arguments.events is None:
        raise ValueError("breakpoint/watchpoint trace requires --events")
    condition_length = 4 if arguments.length is None else arguments.length

    if arguments.break_address is not None:
        mode = TraceCaptureMode.BREAKPOINT
        condition_kind = BreakpointKind.CODE
        condition_address = arguments.break_address
    elif arguments.watch_read is not None:
        mode = TraceCaptureMode.WATCHPOINT
        condition_kind = BreakpointKind.READ
        condition_address = arguments.watch_read
    elif arguments.watch_write is not None:
        mode = TraceCaptureMode.WATCHPOINT
        condition_kind = BreakpointKind.WRITE
        condition_address = arguments.watch_write
    elif arguments.watch_access is not None:
        mode = TraceCaptureMode.WATCHPOINT
        condition_kind = BreakpointKind.ACCESS
        condition_address = arguments.watch_access
    else:
        raise ValueError("runtime trace capture requires one selector")

    return TraceCaptureConfig(
        cpu=arguments.cpu,
        mode=mode,
        limit=arguments.events,
        timeout=arguments.timeout,
        condition_kind=condition_kind,
        condition_address=condition_address,
        condition_length=condition_length,
        memory_regions=memory_regions,
        label=arguments.label,
        project_fingerprint=project_fingerprint,
        toolkit_version=_toolkit_version(),
    )


def _capture_trace_command(arguments: argparse.Namespace) -> int:
    config = _trace_capture_config(arguments)
    with _connect(arguments) as session:
        summary = capture_trace(session, config, arguments.output)
    _write_json(_trace_summary_json(summary), None)
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

    if command == "trace":
        trace_command = arguments.runtime_trace_command
        if trace_command == "inspect":
            return _inspect_trace_command(arguments)
        if trace_command == "capture":
            return _capture_trace_command(arguments)
        raise ValueError("runtime trace requires capture or inspect")
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

    raise ValueError(f"unknown runtime subcommand: {command}")
