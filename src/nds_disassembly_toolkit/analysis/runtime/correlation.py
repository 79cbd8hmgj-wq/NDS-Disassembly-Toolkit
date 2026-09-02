from __future__ import annotations

from nds_disassembly_toolkit.analysis.project import AnalysisProject
from nds_disassembly_toolkit.analysis.runtime.model import (
    RuntimeComponentLocation,
    RuntimeLocation,
    RuntimeSnapshot,
)


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
