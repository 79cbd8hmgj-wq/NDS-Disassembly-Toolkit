from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from nds_disassembly_toolkit.analysis.model import (
    CrossReference,
    CrossReferenceKind,
    FunctionCandidate,
    InstructionSet,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject
from nds_disassembly_toolkit.analysis.runtime.correlation import correlate_trace_event
from nds_disassembly_toolkit.analysis.runtime.memory_diff import (
    diff_memory_snapshots,
    diff_trace_memory,
)
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu, StopReasonKind
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    FunctionRankEvidence,
    MemoryChange,
    MemorySnapshotPhase,
    RankedFunctionCandidate,
    TraceAddressDelta,
    TraceAddressHit,
    TraceAddressInspection,
    TraceDiffReport,
    TraceEvent,
    TraceEventCorrelation,
    TraceEventRole,
    TraceFunctionDelta,
    TraceInspection,
    TraceMemoryRegionInspection,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore
from nds_disassembly_toolkit.errors import (
    RuntimeTraceFormatError,
    RuntimeTraceMismatchError,
)

_AddressKey = tuple[RuntimeCpu, int, InstructionSet]
_CorrelationKey = tuple[int, InstructionSet]
_FunctionKey = tuple[str, int, InstructionSet]
_XrefKey = tuple[str, int, int | None, str | None, int, str | None, str]
_CONDITION_STOP_KINDS = frozenset(
    {StopReasonKind.BREAKPOINT, StopReasonKind.WATCHPOINT}
)
_RANK_FEATURES = (
    ("target_exclusive", 0.30),
    ("positive_frequency_delta", 0.25),
    ("condition_hit", 0.20),
    ("changed_memory_reference", 0.15),
    ("dynamic_neighbor", 0.10),
)


def _inspect_open_store(
    store: TraceStore,
    *,
    project: AnalysisProject | None,
) -> TraceInspection:
    store.validate_complete()
    config = store.config
    events = store.events()
    evidence = tuple(event for event in events if event.role is TraceEventRole.EVIDENCE)
    control_count = sum(
        event.role is TraceEventRole.CONTROL_ADVANCE for event in events
    )

    counts: Counter[_AddressKey] = Counter(
        (event.cpu, event.pc, event.instruction_set) for event in evidence
    )
    representative: dict[_AddressKey, TraceEvent] = {}
    for event in evidence:
        representative.setdefault((event.cpu, event.pc, event.instruction_set), event)

    correlation_cache: dict[_CorrelationKey, TraceEventCorrelation] = {}
    addresses: list[TraceAddressInspection] = []
    evidence_count = len(evidence)
    for key in sorted(counts, key=lambda item: (item[0].value, item[1], item[2].value)):
        cpu, pc, instruction_set = key
        correlation = None
        if project is not None:
            correlation_key = (pc, instruction_set)
            correlation = correlation_cache.get(correlation_key)
            if correlation is None:
                correlation = correlate_trace_event(project, representative[key])
                correlation_cache[correlation_key] = correlation
        addresses.append(
            TraceAddressInspection(
                hit=TraceAddressHit(
                    cpu=cpu,
                    pc=pc,
                    instruction_set=instruction_set,
                    count=counts[key],
                    frequency=counts[key] / evidence_count,
                ),
                correlation=correlation,
            )
        )

    memory_regions: list[TraceMemoryRegionInspection] = []
    for region in config.memory_regions:
        before = store.memory_snapshot(region.ordinal, MemorySnapshotPhase.BEFORE)
        after = store.memory_snapshot(region.ordinal, MemorySnapshotPhase.AFTER)
        if before is None or after is None:
            raise RuntimeTraceFormatError("runtime trace memory snapshots are incomplete")
        changes = diff_memory_snapshots(before, after)
        memory_regions.append(
            TraceMemoryRegionInspection(
                region=region,
                before_sha256=before.sha256,
                after_sha256=after.sha256,
                changed_ranges=len(changes),
                changed_bytes=sum(len(change.before) for change in changes),
            )
        )

    return TraceInspection(
        config=config,
        trace_schema_version=config.trace_schema_version,
        capture_status="complete",
        events=len(events),
        evidence_events=evidence_count,
        control_events=control_count,
        addresses=tuple(addresses),
        memory_regions=tuple(memory_regions),
        integrity_ok=True,
    )


def inspect_trace(
    trace: Path | TraceStore,
    *,
    project: AnalysisProject | None = None,
) -> TraceInspection:
    if isinstance(trace, TraceStore):
        return _inspect_open_store(trace, project=project)

    store = TraceStore.open(Path(trace))
    try:
        return _inspect_open_store(store, project=project)
    finally:
        store.close()


def _evidence_events(store: TraceStore) -> tuple[TraceEvent, ...]:
    return tuple(
        event for event in store.events() if event.role is TraceEventRole.EVIDENCE
    )


def _evidence_counts(store: TraceStore) -> tuple[Counter[_AddressKey], int]:
    evidence = _evidence_events(store)
    return (
        Counter((event.cpu, event.pc, event.instruction_set) for event in evidence),
        len(evidence),
    )


def _classification(baseline_hits: int, target_hits: int) -> str:
    if baseline_hits and target_hits:
        return "shared"
    if baseline_hits:
        return "baseline_only"
    return "target_only"


def _function_key(function: FunctionCandidate) -> _FunctionKey:
    return (
        function.component,
        function.address,
        function.instruction_set,
    )


def _xref_key(reference: CrossReference) -> _XrefKey:
    return (
        reference.source_component,
        reference.source_address,
        reference.source_function_address,
        (
            reference.source_instruction_set.value
            if reference.source_instruction_set is not None
            else None
        ),
        reference.target_address,
        (
            reference.target_instruction_set.value
            if reference.target_instruction_set is not None
            else None
        ),
        reference.kind.value,
    )


def _correlate_function_events(
    project: AnalysisProject,
    events: tuple[TraceEvent, ...],
    cache: dict[_CorrelationKey, TraceEventCorrelation],
) -> tuple[
    dict[_FunctionKey, FunctionCandidate],
    dict[_FunctionKey, list[TraceEvent]],
    dict[_CorrelationKey, TraceEventCorrelation],
]:
    functions: dict[_FunctionKey, FunctionCandidate] = {}
    grouped: dict[_FunctionKey, list[TraceEvent]] = defaultdict(list)
    ambiguous: dict[_CorrelationKey, TraceEventCorrelation] = {}
    for event in events:
        correlation_key = (event.pc, event.instruction_set)
        correlation = cache.get(correlation_key)
        if correlation is None:
            correlation = correlate_trace_event(project, event)
            cache[correlation_key] = correlation
        if correlation.ambiguous:
            ambiguous[correlation_key] = correlation
            continue
        function = correlation.resolved_function
        if function is None:
            continue
        key = _function_key(function)
        functions[key] = function
        grouped[key].append(event)
    return functions, grouped, ambiguous


def _changed_references(
    project: AnalysisProject,
    changes: tuple[MemoryChange, ...],
) -> dict[_FunctionKey, tuple[CrossReference, ...]]:
    collected: dict[_FunctionKey, dict[_XrefKey, CrossReference]] = defaultdict(dict)
    for change in changes:
        end_address = change.address + len(change.before)
        for reference in project.xrefs_to_range(change.address, end_address):
            if (
                reference.source_function_address is None
                or reference.source_instruction_set is None
            ):
                continue
            function_key = (
                reference.source_component,
                reference.source_function_address,
                reference.source_instruction_set,
            )
            collected[function_key][_xref_key(reference)] = reference
    return {
        key: tuple(reference for _, reference in sorted(items.items()))
        for key, items in collected.items()
    }


def _build_function_deltas(
    project: AnalysisProject,
    baseline_events: tuple[TraceEvent, ...],
    target_events: tuple[TraceEvent, ...],
    target_memory_changes: tuple[MemoryChange, ...],
) -> tuple[tuple[TraceFunctionDelta, ...], tuple[TraceEventCorrelation, ...]]:
    cache: dict[_CorrelationKey, TraceEventCorrelation] = {}
    baseline_functions, baseline_grouped, baseline_ambiguous = (
        _correlate_function_events(project, baseline_events, cache)
    )
    target_functions, target_grouped, target_ambiguous = _correlate_function_events(
        project,
        target_events,
        cache,
    )
    functions = {**baseline_functions, **target_functions}
    references = _changed_references(project, target_memory_changes)
    baseline_total = len(baseline_events)
    target_total = len(target_events)

    deltas: list[TraceFunctionDelta] = []
    for key in sorted(functions, key=lambda item: (item[0], item[1], item[2].value)):
        function = functions[key]
        baseline_items = baseline_grouped.get(key, [])
        target_items = target_grouped.get(key, [])
        baseline_hits = len(baseline_items)
        target_hits = len(target_items)
        baseline_frequency = (
            baseline_hits / baseline_total if baseline_total else 0.0
        )
        target_frequency = target_hits / target_total if target_total else 0.0
        condition_stop_pcs = tuple(
            sorted(
                {
                    event.pc
                    for event in target_items
                    if event.stop.kind in _CONDITION_STOP_KINDS
                }
            )
        )
        deltas.append(
            TraceFunctionDelta(
                component=function.component,
                address=function.address,
                instruction_set=function.instruction_set,
                baseline_hits=baseline_hits,
                target_hits=target_hits,
                baseline_frequency=baseline_frequency,
                target_frequency=target_frequency,
                classification=_classification(baseline_hits, target_hits),
                dynamic_pcs=tuple(
                    sorted({event.pc for event in baseline_items + target_items})
                ),
                symbols=project.symbols_at(function.component, function.address),
                annotation=project.annotation(function.component, function.address),
                condition_hit=bool(condition_stop_pcs),
                condition_stop_pcs=condition_stop_pcs,
                changed_memory_references=references.get(key, ()),
            )
        )

    ambiguous = {**baseline_ambiguous, **target_ambiguous}
    return (
        tuple(deltas),
        tuple(
            ambiguous[key]
            for key in sorted(ambiguous, key=lambda item: (item[0], item[1].value))
        ),
    )


def _call_target_matches(
    reference: CrossReference,
    target_exclusive: set[_FunctionKey],
) -> tuple[_FunctionKey, ...]:
    if reference.target_instruction_set is None:
        return ()
    return tuple(
        key
        for key in target_exclusive
        if key[1] == reference.target_address
        and key[2] is reference.target_instruction_set
    )


def _has_dynamic_neighbor(
    project: AnalysisProject,
    delta: TraceFunctionDelta,
    target_exclusive: set[_FunctionKey],
) -> bool:
    current = (delta.component, delta.address, delta.instruction_set)
    for reference in project.xrefs_from_function(
        delta.component,
        delta.address,
        delta.instruction_set,
    ):
        if reference.kind is not CrossReferenceKind.CALL:
            continue
        matches = _call_target_matches(reference, target_exclusive)
        if len(matches) == 1 and matches[0] != current:
            return True

    for reference in project.xrefs_to(delta.address):
        if reference.kind is not CrossReferenceKind.CALL:
            continue
        if (
            reference.target_instruction_set is not None
            and reference.target_instruction_set is not delta.instruction_set
        ):
            continue
        if (
            reference.source_function_address is None
            or reference.source_instruction_set is None
        ):
            continue
        source = (
            reference.source_component,
            reference.source_function_address,
            reference.source_instruction_set,
        )
        if source in target_exclusive and source != current:
            return True
    return False


def _rank_evidence(
    name: str,
    value: float,
    weight: float,
    delta: TraceFunctionDelta,
    dynamic_neighbor: bool,
) -> FunctionRankEvidence:
    reasons: tuple[str, ...]
    if name == "target_exclusive":
        reasons = (
            "target trace only" if value else "not target-exclusive",
        )
    elif name == "positive_frequency_delta":
        reasons = (
            (
                f"target evidence frequency exceeds baseline by {value:.6f}"
                if value
                else "no positive target frequency delta"
            ),
        )
    elif name == "condition_hit":
        reasons = (
            (
                "target breakpoint/watchpoint evidence hit this function"
                if value
                else "no target breakpoint/watchpoint evidence hit"
            ),
        )
    elif name == "changed_memory_reference":
        if delta.changed_memory_references:
            reasons = tuple(
                "static reference to changed memory at "
                f"0x{reference.target_address:08x}"
                for reference in delta.changed_memory_references
            )
        else:
            reasons = ("no static reference to changed memory",)
    else:
        reasons = (
            (
                "static call relation to target-exclusive dynamic candidate"
                if dynamic_neighbor
                else "no qualifying dynamic neighbor"
            ),
        )
    return FunctionRankEvidence(
        name=name,
        value=value,
        weight=weight,
        contribution=value * weight,
        reasons=reasons,
    )


def _build_rankings(
    project: AnalysisProject,
    deltas: tuple[TraceFunctionDelta, ...],
) -> tuple[RankedFunctionCandidate, ...]:
    target_exclusive = {
        (delta.component, delta.address, delta.instruction_set)
        for delta in deltas
        if delta.target_hits > 0 and delta.baseline_hits == 0
    }
    rankings: list[RankedFunctionCandidate] = []
    for delta in deltas:
        dynamic_neighbor = _has_dynamic_neighbor(project, delta, target_exclusive)
        values = {
            "target_exclusive": (
                1.0 if delta.target_hits > 0 and delta.baseline_hits == 0 else 0.0
            ),
            "positive_frequency_delta": max(
                0.0,
                delta.target_frequency - delta.baseline_frequency,
            ),
            "condition_hit": 1.0 if delta.condition_hit else 0.0,
            "changed_memory_reference": (
                1.0 if delta.changed_memory_references else 0.0
            ),
            "dynamic_neighbor": 1.0 if dynamic_neighbor else 0.0,
        }
        evidence = tuple(
            _rank_evidence(name, values[name], weight, delta, dynamic_neighbor)
            for name, weight in _RANK_FEATURES
        )
        rankings.append(
            RankedFunctionCandidate(
                component=delta.component,
                address=delta.address,
                instruction_set=delta.instruction_set,
                score=sum(item.contribution for item in evidence),
                evidence=evidence,
            )
        )
    return tuple(
        sorted(
            rankings,
            key=lambda item: (
                -item.score,
                item.component,
                item.address,
                item.instruction_set.value,
            ),
        )
    )


def _compare_open_stores(
    baseline: TraceStore,
    target: TraceStore,
    *,
    project: AnalysisProject | None,
) -> TraceDiffReport:
    baseline.validate_complete()
    target.validate_complete()

    baseline_fingerprint = baseline.config.project_fingerprint
    target_fingerprint = target.config.project_fingerprint
    if (
        baseline_fingerprint is not None
        and target_fingerprint is not None
        and baseline_fingerprint != target_fingerprint
    ):
        raise RuntimeTraceMismatchError(
            "runtime trace project fingerprints do not match"
        )
    target_identity_verified = (
        baseline_fingerprint is not None
        and target_fingerprint is not None
        and baseline_fingerprint == target_fingerprint
    )

    baseline_counts, baseline_total = _evidence_counts(baseline)
    target_counts, target_total = _evidence_counts(target)
    keys = sorted(
        set(baseline_counts) | set(target_counts),
        key=lambda item: (item[0].value, item[1], item[2].value),
    )
    deltas: list[TraceAddressDelta] = []
    for cpu, pc, instruction_set in keys:
        key = (cpu, pc, instruction_set)
        baseline_hits = baseline_counts[key]
        target_hits = target_counts[key]
        baseline_frequency = (
            baseline_hits / baseline_total if baseline_total else 0.0
        )
        target_frequency = target_hits / target_total if target_total else 0.0
        deltas.append(
            TraceAddressDelta(
                cpu=cpu,
                pc=pc,
                instruction_set=instruction_set,
                baseline_hits=baseline_hits,
                target_hits=target_hits,
                baseline_frequency=baseline_frequency,
                target_frequency=target_frequency,
                frequency_delta=target_frequency - baseline_frequency,
                classification=_classification(baseline_hits, target_hits),
            )
        )

    baseline_memory_changes = diff_trace_memory(baseline)
    target_memory_changes = diff_trace_memory(target)
    function_deltas: tuple[TraceFunctionDelta, ...] = ()
    ambiguous_correlations: tuple[TraceEventCorrelation, ...] = ()
    rankings: tuple[RankedFunctionCandidate, ...] = ()
    if project is not None:
        function_deltas, ambiguous_correlations = _build_function_deltas(
            project,
            _evidence_events(baseline),
            _evidence_events(target),
            target_memory_changes,
        )
        rankings = _build_rankings(project, function_deltas)

    return TraceDiffReport(
        baseline_config=baseline.config,
        target_config=target.config,
        target_identity_verified=target_identity_verified,
        address_deltas=tuple(deltas),
        function_deltas=function_deltas,
        ambiguous_correlations=ambiguous_correlations,
        baseline_memory_changes=baseline_memory_changes,
        target_memory_changes=target_memory_changes,
        rankings=rankings,
    )


def compare_traces(
    baseline: Path | TraceStore,
    target: Path | TraceStore,
    *,
    project: AnalysisProject | None = None,
) -> TraceDiffReport:
    baseline_store = (
        baseline
        if isinstance(baseline, TraceStore)
        else TraceStore.open(Path(baseline))
    )
    target_store = (
        target if isinstance(target, TraceStore) else TraceStore.open(Path(target))
    )
    close_baseline = not isinstance(baseline, TraceStore)
    close_target = not isinstance(target, TraceStore)
    try:
        return _compare_open_stores(
            baseline_store,
            target_store,
            project=project,
        )
    finally:
        if close_target:
            target_store.close()
        if close_baseline:
            baseline_store.close()
