from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace

from nds_disassembly_toolkit.analysis.decompiler import decompile_function
from nds_disassembly_toolkit.analysis.investigation.model import (
    InvestigationCandidate,
    InvestigationEvidence,
    InvestigationEvidenceKind,
    InvestigationReport,
    InvestigationRequest,
)
from nds_disassembly_toolkit.analysis.model import (
    CrossReference,
    CrossReferenceKind,
    FunctionCandidate,
    InstructionSet,
    OperandKind,
    Symbol,
    SymbolKind,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject, LocationAnnotation
from nds_disassembly_toolkit.analysis.runtime.trace_diff import compare_traces
from nds_disassembly_toolkit.errors import DecompilerError, InvestigationError

_FunctionKey = tuple[str, int, InstructionSet]
_AddressModeKey = tuple[int, InstructionSet]

_WEIGHTS: dict[InvestigationEvidenceKind, float] = {
    InvestigationEvidenceKind.RUNTIME_DIFFERENTIAL: 0.35,
    InvestigationEvidenceKind.TEXT: 0.25,
    InvestigationEvidenceKind.CONSTANT: 0.20,
    InvestigationEvidenceKind.ADDRESS_XREF: 0.15,
    InvestigationEvidenceKind.CALL_NEIGHBOR: 0.05,
}
_EVIDENCE_ORDER = tuple(_WEIGHTS)


@dataclass
class _EvidenceData:
    value: float = 1.0
    reasons: set[str] = field(default_factory=set)
    addresses: set[int] = field(default_factory=set)


def _function_key(function: FunctionCandidate) -> _FunctionKey:
    return function.component, function.address, function.instruction_set


def _source_function_key(reference: CrossReference) -> _FunctionKey | None:
    source_function_address = reference.source_function_address
    source_instruction_set = reference.source_instruction_set
    if source_function_address is None or source_instruction_set is None:
        return None
    return (
        reference.source_component,
        source_function_address,
        source_instruction_set,
    )


def _add_evidence(
    evidence: dict[_FunctionKey, dict[InvestigationEvidenceKind, _EvidenceData]],
    key: _FunctionKey,
    kind: InvestigationEvidenceKind,
    *,
    reason: str,
    address: int | None = None,
    value: float = 1.0,
) -> None:
    by_kind = evidence.setdefault(key, {})
    item = by_kind.get(kind)
    if item is None:
        item = _EvidenceData(value=value)
        by_kind[kind] = item
    else:
        item.value = max(item.value, value)
    item.reasons.add(reason)
    if address is not None:
        item.addresses.add(address)


def _annotation_matches(annotation: LocationAnnotation, needle: str) -> bool:
    fields = (
        annotation.name_override,
        annotation.comment,
        *annotation.tags,
    )
    return any(value is not None and needle in value.casefold() for value in fields)


def _annotation_function_keys(
    project: AnalysisProject,
    annotation: LocationAnnotation,
    functions: dict[_FunctionKey, FunctionCandidate],
) -> tuple[_FunctionKey, ...]:
    exact = tuple(
        key
        for key in functions
        if key[0] == annotation.component and key[1] == annotation.address
    )
    if exact:
        return tuple(sorted(exact, key=lambda item: (item[0], item[1], item[2].value)))

    matches: set[_FunctionKey] = set()
    for mode in InstructionSet:
        for function in project.functions_containing(
            annotation.component,
            annotation.address,
            mode,
        ):
            key = _function_key(function)
            if key in functions:
                matches.add(key)
    return tuple(sorted(matches, key=lambda item: (item[0], item[1], item[2].value)))


def _collect_text_evidence(
    project: AnalysisProject,
    request: InvestigationRequest,
    functions: dict[_FunctionKey, FunctionCandidate],
    evidence: dict[_FunctionKey, dict[InvestigationEvidenceKind, _EvidenceData]],
) -> None:
    if request.text is None or not request.text.strip():
        return
    needle = request.text.casefold()
    for record in project.strings(component=request.component):
        if needle not in record.text.casefold():
            continue
        for reference in project.xrefs_to(
            record.address,
            source_component=request.component,
        ):
            key = _source_function_key(reference)
            if key is None or key not in functions:
                continue
            _add_evidence(
                evidence,
                key,
                InvestigationEvidenceKind.TEXT,
                reason=f"references matching string {record.text!r} at 0x{record.address:08x}",
                address=record.address,
            )

    for annotation in project.annotations(component=request.component):
        if not _annotation_matches(annotation, needle):
            continue
        for key in _annotation_function_keys(project, annotation, functions):
            _add_evidence(
                evidence,
                key,
                InvestigationEvidenceKind.TEXT,
                reason=(
                    "matching user annotation at "
                    f"{annotation.component}:0x{annotation.address:08x}"
                ),
                address=annotation.address,
            )


def _collect_constant_evidence(
    project: AnalysisProject,
    request: InvestigationRequest,
    functions: dict[_FunctionKey, FunctionCandidate],
    evidence: dict[_FunctionKey, dict[InvestigationEvidenceKind, _EvidenceData]],
) -> None:
    if not request.constants:
        return
    requested = tuple(sorted(set(request.constants)))
    for key, function in functions.items():
        cfg = project.cfg(function.component, function.address, function.instruction_set)
        if cfg is None:
            continue
        matches: dict[int, set[int]] = defaultdict(set)
        for block in cfg.blocks:
            for instruction in block.instructions:
                for operand in instruction.semantics.operands:
                    if (
                        operand.kind is OperandKind.IMMEDIATE
                        and operand.immediate is not None
                        and operand.immediate in requested
                    ):
                        matches[operand.immediate].add(instruction.address)
        if not matches:
            continue
        for value in sorted(matches):
            addresses = tuple(sorted(matches[value]))
            _add_evidence(
                evidence,
                key,
                InvestigationEvidenceKind.CONSTANT,
                reason=(
                    f"typed immediate constant {value} at "
                    + ", ".join(f"0x{address:08x}" for address in addresses)
                ),
            )
            evidence[key][InvestigationEvidenceKind.CONSTANT].addresses.update(addresses)


def _collect_address_evidence(
    project: AnalysisProject,
    request: InvestigationRequest,
    functions: dict[_FunctionKey, FunctionCandidate],
    evidence: dict[_FunctionKey, dict[InvestigationEvidenceKind, _EvidenceData]],
) -> None:
    for address in sorted(set(request.addresses)):
        for reference in project.xrefs_to(
            address,
            source_component=request.component,
        ):
            key = _source_function_key(reference)
            if key is None or key not in functions:
                continue
            _add_evidence(
                evidence,
                key,
                InvestigationEvidenceKind.ADDRESS_XREF,
                reason=(
                    f"static {reference.kind.value} reference to requested address "
                    f"0x{address:08x}"
                ),
                address=address,
            )


def _collect_runtime_evidence(
    project: AnalysisProject,
    request: InvestigationRequest,
    functions: dict[_FunctionKey, FunctionCandidate],
    evidence: dict[_FunctionKey, dict[InvestigationEvidenceKind, _EvidenceData]],
) -> None:
    if request.baseline_trace is None or request.target_trace is None:
        return
    report = compare_traces(
        request.baseline_trace,
        request.target_trace,
        project=project,
    )
    for ranked in report.rankings:
        key = (ranked.component, ranked.address, ranked.instruction_set)
        if key not in functions:
            continue
        value = min(1.0, max(0.0, ranked.score))
        if value <= 0.0:
            continue
        reasons = tuple(
            sorted(
                {
                    f"runtime {runtime_evidence.name}: {reason}"
                    for runtime_evidence in ranked.evidence
                    if runtime_evidence.contribution > 0.0
                    for reason in runtime_evidence.reasons
                }
            )
        ) or ("runtime differential ranked this function",)
        for reason in reasons:
            _add_evidence(
                evidence,
                key,
                InvestigationEvidenceKind.RUNTIME_DIFFERENTIAL,
                reason=reason,
                address=ranked.address,
                value=value,
            )


def _resolve_call_target(
    address_index: dict[_AddressModeKey, tuple[_FunctionKey, ...]],
    target_address: int,
    target_mode: InstructionSet | None,
) -> _FunctionKey | None:
    if target_mode is None:
        return None
    matches = address_index.get((target_address, target_mode), ())
    return matches[0] if len(matches) == 1 else None


def _collect_call_neighbors(
    project: AnalysisProject,
    functions: dict[_FunctionKey, FunctionCandidate],
    evidence: dict[_FunctionKey, dict[InvestigationEvidenceKind, _EvidenceData]],
) -> None:
    direct_keys = tuple(
        sorted(
            (
                key
                for key, items in evidence.items()
                if any(
                    kind is not InvestigationEvidenceKind.CALL_NEIGHBOR
                    and data.value > 0.0
                    for kind, data in items.items()
                )
            ),
            key=lambda item: (item[0], item[1], item[2].value),
        )
    )
    address_index_lists: dict[_AddressModeKey, list[_FunctionKey]] = defaultdict(list)
    for key in functions:
        address_index_lists[(key[1], key[2])].append(key)
    address_index = {
        key: tuple(sorted(values, key=lambda item: (item[0], item[1], item[2].value)))
        for key, values in address_index_lists.items()
    }

    for direct_key in direct_keys:
        direct = functions[direct_key]
        for reference in project.xrefs_from_function(
            direct.component,
            direct.address,
            direct.instruction_set,
        ):
            if reference.kind is not CrossReferenceKind.CALL:
                continue
            target = _resolve_call_target(
                address_index,
                reference.target_address,
                reference.target_instruction_set,
            )
            if target is None or target == direct_key:
                continue
            _add_evidence(
                evidence,
                target,
                InvestigationEvidenceKind.CALL_NEIGHBOR,
                reason=(
                    f"called by evidence-bearing {direct.component}:"
                    f"0x{direct.address:08x} ({direct.instruction_set.value})"
                ),
                address=reference.source_address,
            )

        for reference in project.xrefs_to(direct.address):
            if reference.kind is not CrossReferenceKind.CALL:
                continue
            resolved_target = _resolve_call_target(
                address_index,
                reference.target_address,
                reference.target_instruction_set,
            )
            if resolved_target != direct_key:
                continue
            source = _source_function_key(reference)
            if source is None or source not in functions or source == direct_key:
                continue
            _add_evidence(
                evidence,
                source,
                InvestigationEvidenceKind.CALL_NEIGHBOR,
                reason=(
                    f"calls evidence-bearing {direct.component}:"
                    f"0x{direct.address:08x} ({direct.instruction_set.value})"
                ),
                address=reference.source_address,
            )


def _display_context(
    project: AnalysisProject,
    function: FunctionCandidate,
) -> tuple[str, tuple[Symbol, ...], LocationAnnotation | None]:
    symbols = project.symbols_at(function.component, function.address)
    annotation = project.annotation(function.component, function.address)
    if annotation is not None and annotation.name_override is not None:
        name = annotation.name_override
    else:
        preferred = next(
            (
                symbol
                for symbol in symbols
                if symbol.kind in {SymbolKind.FUNCTION, SymbolKind.NAMED}
            ),
            None,
        )
        name = preferred.name if preferred is not None else f"sub_{function.address:08X}"
    return name, symbols, annotation


def _build_candidates(
    project: AnalysisProject,
    request: InvestigationRequest,
    functions: dict[_FunctionKey, FunctionCandidate],
    evidence: dict[_FunctionKey, dict[InvestigationEvidenceKind, _EvidenceData]],
) -> tuple[InvestigationCandidate, ...]:
    candidates: list[InvestigationCandidate] = []
    for key, by_kind in evidence.items():
        rendered_evidence: list[InvestigationEvidence] = []
        for kind in _EVIDENCE_ORDER:
            data = by_kind.get(kind)
            if data is None or data.value <= 0.0:
                continue
            weight = _WEIGHTS[kind]
            rendered_evidence.append(
                InvestigationEvidence(
                    kind=kind,
                    value=data.value,
                    weight=weight,
                    contribution=data.value * weight,
                    reasons=tuple(sorted(data.reasons)),
                    addresses=tuple(sorted(data.addresses)),
                )
            )
        score = sum(item.contribution for item in rendered_evidence)
        if score <= 0.0:
            continue
        function = functions[key]
        name, symbols, annotation = _display_context(project, function)
        candidates.append(
            InvestigationCandidate(
                function=function,
                name=name,
                score=score,
                evidence=tuple(rendered_evidence),
                symbols=symbols,
                annotation=annotation,
            )
        )

    ranked = sorted(
        candidates,
        key=lambda item: (
            -item.score,
            item.function.component,
            item.function.address,
            item.function.instruction_set.value,
        ),
    )[: request.top]

    if not request.include_pseudo_c:
        return tuple(ranked)

    enriched: list[InvestigationCandidate] = []
    for candidate in ranked:
        function = candidate.function
        try:
            result = decompile_function(
                project,
                function.component,
                function.address,
                function.instruction_set,
            )
        except DecompilerError as exc:
            enriched.append(replace(candidate, pseudo_c_error=str(exc)))
        else:
            enriched.append(replace(candidate, pseudo_c=result.pseudo_c))
    return tuple(enriched)


def investigate_project(
    project: AnalysisProject,
    request: InvestigationRequest,
) -> InvestigationReport:
    request.validate()
    identities = project.component_identities()
    if request.component is not None and request.component not in {
        identity.name for identity in identities
    }:
        raise InvestigationError(
            f"analysis component {request.component!r} is missing from the project"
        )

    function_items = project.functions(component=request.component)
    functions = {_function_key(function): function for function in function_items}
    evidence: dict[
        _FunctionKey,
        dict[InvestigationEvidenceKind, _EvidenceData],
    ] = {}

    _collect_text_evidence(project, request, functions, evidence)
    _collect_constant_evidence(project, request, functions, evidence)
    _collect_address_evidence(project, request, functions, evidence)
    _collect_runtime_evidence(project, request, functions, evidence)
    _collect_call_neighbors(project, functions, evidence)

    return InvestigationReport(
        request=request,
        candidates=_build_candidates(project, request, functions, evidence),
    )
