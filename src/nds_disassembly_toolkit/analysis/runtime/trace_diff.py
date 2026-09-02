from __future__ import annotations

from collections import Counter
from pathlib import Path

from nds_disassembly_toolkit.analysis.model import InstructionSet
from nds_disassembly_toolkit.analysis.project import AnalysisProject
from nds_disassembly_toolkit.analysis.runtime.correlation import correlate_trace_event
from nds_disassembly_toolkit.analysis.runtime.memory_diff import diff_memory_snapshots
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    MemorySnapshotPhase,
    TraceAddressDelta,
    TraceAddressHit,
    TraceAddressInspection,
    TraceDiffReport,
    TraceEvent,
    TraceEventCorrelation,
    TraceEventRole,
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


def _evidence_counts(store: TraceStore) -> tuple[Counter[_AddressKey], int]:
    evidence = tuple(
        event for event in store.events() if event.role is TraceEventRole.EVIDENCE
    )
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


def _compare_open_stores(
    baseline: TraceStore,
    target: TraceStore,
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

    return TraceDiffReport(
        baseline_config=baseline.config,
        target_config=target.config,
        target_identity_verified=target_identity_verified,
        address_deltas=tuple(deltas),
    )


def compare_traces(
    baseline: Path | TraceStore,
    target: Path | TraceStore,
    *,
    project: AnalysisProject | None = None,
) -> TraceDiffReport:
    del project
    baseline_store = baseline if isinstance(baseline, TraceStore) else TraceStore.open(Path(baseline))
    target_store = target if isinstance(target, TraceStore) else TraceStore.open(Path(target))
    close_baseline = not isinstance(baseline, TraceStore)
    close_target = not isinstance(target, TraceStore)
    try:
        return _compare_open_stores(baseline_store, target_store)
    finally:
        if close_target:
            target_store.close()
        if close_baseline:
            baseline_store.close()
