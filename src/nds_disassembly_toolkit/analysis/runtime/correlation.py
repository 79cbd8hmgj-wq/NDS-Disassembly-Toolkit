from __future__ import annotations

import hashlib
import json

from nds_disassembly_toolkit.analysis.model import FunctionCandidate
from nds_disassembly_toolkit.analysis.project import AnalysisProject
from nds_disassembly_toolkit.analysis.runtime.model import (
    RuntimeComponentLocation,
    RuntimeLocation,
    RuntimeSnapshot,
)
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    TraceEvent,
    TraceEventComponentCorrelation,
    TraceEventCorrelation,
)


def analysis_project_fingerprint(project: AnalysisProject) -> str:
    metadata = project.metadata
    payload = {
        "analysis_model_version": metadata.analysis_model_version,
        "components": [
            {
                "base_address": item.base_address,
                "name": item.name,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in project.component_identities()
        ],
        "project_format_version": metadata.project_format_version,
        "schema_version": metadata.schema_version,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def correlate_snapshot(
    project: AnalysisProject,
    snapshot: RuntimeSnapshot,
) -> RuntimeLocation:
    candidates: list[RuntimeComponentLocation] = []
    for identity in sorted(
        project.component_identities(),
        key=lambda candidate: candidate.name,
    ):
        if not (
            identity.base_address
            <= snapshot.pc
            < identity.base_address + identity.size
        ):
            continue
        candidates.append(
            RuntimeComponentLocation(
                component=identity.name,
                function=project.function(
                    identity.name,
                    snapshot.pc,
                    snapshot.instruction_set,
                ),
                symbols=project.symbols_at(identity.name, snapshot.pc),
                annotation=project.annotation(identity.name, snapshot.pc),
            )
        )
    return RuntimeLocation(
        pc=snapshot.pc,
        instruction_set=snapshot.instruction_set,
        candidates=tuple(candidates),
    )


def correlate_trace_event(
    project: AnalysisProject,
    event: TraceEvent,
) -> TraceEventCorrelation:
    candidates: list[TraceEventComponentCorrelation] = []
    functions: list[FunctionCandidate] = []
    for identity in sorted(
        project.component_identities(),
        key=lambda candidate: candidate.name,
    ):
        if not (
            identity.base_address <= event.pc < identity.base_address + identity.size
        ):
            continue
        component_functions = project.functions_containing(
            identity.name,
            event.pc,
            event.instruction_set,
        )
        candidates.append(
            TraceEventComponentCorrelation(
                component=identity.name,
                functions=component_functions,
                symbols=project.symbols_at(identity.name, event.pc),
                annotation=project.annotation(identity.name, event.pc),
            )
        )
        functions.extend(component_functions)

    resolved_function = functions[0] if len(functions) == 1 else None
    return TraceEventCorrelation(
        pc=event.pc,
        instruction_set=event.instruction_set,
        candidates=tuple(candidates),
        ambiguous=len(candidates) > 1 or len(functions) > 1,
        resolved_function=resolved_function,
    )
