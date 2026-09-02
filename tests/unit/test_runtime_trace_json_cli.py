from __future__ import annotations

import json

import nds_disassembly_toolkit.analysis.runtime_cli as runtime_cli
from nds_disassembly_toolkit.analysis.model import (
    CrossReference,
    CrossReferenceKind,
    FunctionCandidate,
    InstructionSet,
    Symbol,
    SymbolKind,
)
from nds_disassembly_toolkit.analysis.project import LocationAnnotation
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    AlignedMemoryValueChange,
    FunctionRankEvidence,
    MemoryChange,
    RankedFunctionCandidate,
    TraceAddressDelta,
    TraceAddressHit,
    TraceAddressInspection,
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceDiffReport,
    TraceEventComponentCorrelation,
    TraceEventCorrelation,
    TraceFunctionDelta,
    TraceInspection,
    TraceMemoryRegion,
    TraceMemoryRegionInspection,
)


def _function(component: str = "arm9", address: int = 0x02000100) -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=address,
        offset=address - 0x02000000,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("cfg",),
    )


def _symbol(component: str = "arm9", address: int = 0x02000100) -> Symbol:
    return Symbol(
        component=component,
        address=address,
        offset=address - 0x02000000,
        name="target_func",
        kind=SymbolKind.FUNCTION,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("function",),
    )


def _annotation(component: str = "arm9", address: int = 0x02000100) -> LocationAnnotation:
    return LocationAnnotation(
        component=component,
        address=address,
        name_override="interesting",
        comment="runtime candidate",
        tags=("runtime", "target"),
        bookmarked=True,
    )


def _config(*, fingerprint: str = "a" * 64) -> TraceCaptureConfig:
    return TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=2,
        timeout=5.0,
        memory_regions=(TraceMemoryRegion(0, 0x02100000, 8, "state"),),
        label="attack",
        project_fingerprint=fingerprint,
        toolkit_version="0.1.0",
    )


def _memory_change() -> MemoryChange:
    return MemoryChange(
        region_ordinal=0,
        address=0x02100002,
        before=b"\x02\x03",
        after=b"\xaa\xbb",
        values16=(
            AlignedMemoryValueChange(
                address=0x02100002,
                width=2,
                before=0x0302,
                after=0xBBAA,
            ),
        ),
        values32=(
            AlignedMemoryValueChange(
                address=0x02100000,
                width=4,
                before=0x03020100,
                after=0xBBAA0100,
            ),
        ),
    )


def _correlation() -> TraceEventCorrelation:
    function = _function()
    symbol = _symbol()
    annotation = _annotation()
    return TraceEventCorrelation(
        pc=0x02000104,
        instruction_set=InstructionSet.ARM,
        candidates=(
            TraceEventComponentCorrelation(
                component="arm9",
                functions=(function,),
                symbols=(symbol,),
                annotation=annotation,
            ),
        ),
        ambiguous=False,
        resolved_function=function,
    )


def test_trace_inspection_json_preserves_correlation_and_raw_memory_changes() -> None:
    config = _config()
    correlation = _correlation()
    inspection = TraceInspection(
        config=config,
        trace_schema_version=1,
        capture_status="complete",
        events=2,
        evidence_events=2,
        control_events=0,
        addresses=(
            TraceAddressInspection(
                hit=TraceAddressHit(
                    cpu=RuntimeCpu.ARM9,
                    pc=0x02000104,
                    instruction_set=InstructionSet.ARM,
                    count=2,
                    frequency=1.0,
                ),
                correlation=correlation,
            ),
        ),
        memory_regions=(
            TraceMemoryRegionInspection(
                region=config.memory_regions[0],
                before_sha256="1" * 64,
                after_sha256="2" * 64,
                changed_ranges=1,
                changed_bytes=2,
            ),
        ),
        memory_changes=(_memory_change(),),
        integrity_ok=True,
    )

    payload = runtime_cli._trace_inspection_json(inspection)

    assert payload["config"]["memory_regions"][0]["address"] == "0x02100000"
    address = payload["addresses"][0]
    assert address["pc"] == "0x02000104"
    assert address["correlation"]["resolved_function"]["address"] == "0x02000100"
    assert address["correlation"]["candidates"][0]["symbols"][0]["name"] == "target_func"
    assert address["correlation"]["candidates"][0]["annotation"]["bookmarked"] is True

    change = payload["memory_changes"][0]
    assert change["address"] == "0x02100002"
    assert change["before"] == "0203"
    assert change["after"] == "aabb"
    assert change["values16"] == [
        {
            "address": "0x02100002",
            "after": "0xbbaa",
            "before": "0x0302",
            "width": 2,
        }
    ]
    assert change["values32"] == [
        {
            "address": "0x02100000",
            "after": "0xbbaa0100",
            "before": "0x03020100",
            "width": 4,
        }
    ]


def test_trace_diff_json_exposes_function_memory_ambiguity_and_ranking_evidence() -> None:
    function = _function()
    symbol = _symbol()
    annotation = _annotation()
    reference = CrossReference(
        kind=CrossReferenceKind.DATA_POINTER,
        source_component="arm9",
        source_address=0x02000108,
        source_function_address=function.address,
        source_instruction_set=InstructionSet.ARM,
        target_address=0x02100002,
        target_instruction_set=None,
    )
    function_delta = TraceFunctionDelta(
        component="arm9",
        address=function.address,
        instruction_set=InstructionSet.ARM,
        baseline_hits=0,
        target_hits=1,
        baseline_frequency=0.0,
        target_frequency=0.5,
        classification="target_only",
        dynamic_pcs=(0x02000104,),
        symbols=(symbol,),
        annotation=annotation,
        condition_hit=True,
        condition_stop_pcs=(0x02000104,),
        changed_memory_references=(reference,),
    )
    evidence = (
        FunctionRankEvidence("target_exclusive", 1.0, 0.30, 0.30, ("target trace only",)),
        FunctionRankEvidence(
            "positive_frequency_delta",
            0.5,
            0.25,
            0.125,
            ("target evidence frequency exceeds baseline by 0.500000",),
        ),
        FunctionRankEvidence(
            "condition_hit",
            1.0,
            0.20,
            0.20,
            ("target breakpoint/watchpoint evidence hit this function",),
        ),
        FunctionRankEvidence(
            "changed_memory_reference",
            1.0,
            0.15,
            0.15,
            ("static reference to changed memory at 0x02100002",),
        ),
        FunctionRankEvidence(
            "dynamic_neighbor",
            1.0,
            0.10,
            0.10,
            ("static call relation to target-exclusive dynamic candidate",),
        ),
    )
    ambiguous = TraceEventCorrelation(
        pc=0x02200000,
        instruction_set=InstructionSet.ARM,
        candidates=(
            TraceEventComponentCorrelation("overlay_3", (), (), None),
            TraceEventComponentCorrelation("overlay_7", (), (), None),
        ),
        ambiguous=True,
        resolved_function=None,
    )
    report = TraceDiffReport(
        baseline_config=_config(),
        target_config=_config(),
        target_identity_verified=True,
        address_deltas=(
            TraceAddressDelta(
                cpu=RuntimeCpu.ARM9,
                pc=0x02000104,
                instruction_set=InstructionSet.ARM,
                baseline_hits=0,
                target_hits=1,
                baseline_frequency=0.0,
                target_frequency=0.5,
                frequency_delta=0.5,
                classification="target_only",
            ),
        ),
        function_deltas=(function_delta,),
        ambiguous_correlations=(ambiguous,),
        baseline_memory_changes=(),
        target_memory_changes=(_memory_change(),),
        rankings=(
            RankedFunctionCandidate(
                component="arm9",
                address=function.address,
                instruction_set=InstructionSet.ARM,
                score=0.875,
                evidence=evidence,
            ),
        ),
    )

    payload = runtime_cli._trace_diff_json(report)

    assert set(payload) == {
        "baseline_config",
        "target_config",
        "target_identity_verified",
        "address_deltas",
        "function_deltas",
        "ambiguous_correlations",
        "baseline_memory_changes",
        "target_memory_changes",
        "rankings",
    }
    assert payload["target_identity_verified"] is True
    delta = payload["function_deltas"][0]
    assert delta["address"] == "0x02000100"
    assert delta["dynamic_pcs"] == ["0x02000104"]
    assert delta["condition_stop_pcs"] == ["0x02000104"]
    assert delta["symbols"][0]["name"] == "target_func"
    assert delta["annotation"]["name_override"] == "interesting"
    assert delta["changed_memory_references"][0]["target_address"] == "0x02100002"
    assert payload["ambiguous_correlations"][0]["candidates"][0]["component"] == "overlay_3"
    assert payload["target_memory_changes"][0]["before"] == "0203"

    ranked = payload["rankings"][0]
    assert ranked["address"] == "0x02000100"
    assert ranked["score"] == 0.875
    assert [item["name"] for item in ranked["evidence"]] == [
        "target_exclusive",
        "positive_frequency_delta",
        "condition_hit",
        "changed_memory_reference",
        "dynamic_neighbor",
    ]
    assert ranked["evidence"][3]["weight"] == 0.15
    assert ranked["evidence"][3]["contribution"] == 0.15
    assert ranked["evidence"][3]["reasons"] == [
        "static reference to changed memory at 0x02100002"
    ]
    assert "probability" not in json.dumps(payload, sort_keys=True).lower()
