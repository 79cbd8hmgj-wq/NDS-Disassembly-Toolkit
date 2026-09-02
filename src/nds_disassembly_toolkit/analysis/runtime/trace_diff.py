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
    TraceAddressHit,
    TraceAddressInspection,
    TraceEvent,
    TraceEventCorrelation,
    TraceEventRole,
    TraceInspection,
    TraceMemoryRegionInspection,
)
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore
from nds_disassembly_toolkit.errors import RuntimeTraceFormatError

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
