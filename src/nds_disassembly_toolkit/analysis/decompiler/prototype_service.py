from __future__ import annotations

from dataclasses import dataclass

from nds_disassembly_toolkit.analysis.decompiler.lift import lift_function
from nds_disassembly_toolkit.analysis.decompiler.names import build_name_context
from nds_disassembly_toolkit.analysis.decompiler.prototype import (
    PrototypePropagationResult,
    propagate_prototypes,
)
from nds_disassembly_toolkit.analysis.decompiler.simplify import (
    simplify_ssa_function,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAFunction,
    build_ssa_function,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    FunctionTypeIdentity,
    LocalTypeEnvironment,
    infer_local_types,
)
from nds_disassembly_toolkit.analysis.model import FunctionCandidate
from nds_disassembly_toolkit.analysis.project import AnalysisProject


def _identity(function: FunctionCandidate) -> FunctionTypeIdentity:
    return FunctionTypeIdentity(
        function.component,
        function.address,
        function.instruction_set,
    )


def _function_sort_key(
    function: FunctionCandidate,
) -> tuple[str, int, str]:
    return (
        function.component,
        function.address,
        function.instruction_set.value,
    )


@dataclass(frozen=True, slots=True, order=True)
class PrototypeServiceDiagnostic:
    identity: FunctionTypeIdentity
    message: str

    def __post_init__(self) -> None:
        if not self.message:
            raise ValueError("prototype service diagnostic cannot be empty")


@dataclass(frozen=True, slots=True)
class ProjectPrototypeAnalysis:
    propagation: PrototypePropagationResult
    functions: tuple[SSAFunction, ...]
    environments: tuple[LocalTypeEnvironment, ...]
    diagnostics: tuple[PrototypeServiceDiagnostic, ...] = ()

    def __post_init__(self) -> None:
        if len(self.functions) != len(self.environments):
            raise ValueError(
                "project prototype functions and environments must align"
            )
        object.__setattr__(
            self,
            "diagnostics",
            tuple(sorted(set(self.diagnostics))),
        )

    def ssa_for(
        self,
        identity: FunctionTypeIdentity,
    ) -> SSAFunction | None:
        for function in self.functions:
            if (
                function.component == identity.component
                and function.address == identity.address
                and function.instruction_set
                is identity.instruction_set
            ):
                return function
        return None

    def environment_for(
        self,
        identity: FunctionTypeIdentity,
    ) -> LocalTypeEnvironment | None:
        for function, environment in zip(
            self.functions,
            self.environments,
            strict=True,
        ):
            if (
                function.component == identity.component
                and function.address == identity.address
                and function.instruction_set
                is identity.instruction_set
            ):
                return environment
        return None


def recover_project_prototypes(
    project: AnalysisProject,
    *,
    iteration_cap: int = 32,
) -> ProjectPrototypeAnalysis:
    analyzed_functions: list[SSAFunction] = []
    environments: list[LocalTypeEnvironment] = []
    diagnostics: list[PrototypeServiceDiagnostic] = []

    for function in sorted(
        project.functions(),
        key=_function_sort_key,
    ):
        identity = _identity(function)
        cfg = project.cfg(
            function.component,
            function.address,
            function.instruction_set,
        )
        if cfg is None:
            diagnostics.append(
                PrototypeServiceDiagnostic(
                    identity,
                    "missing persisted CFG",
                )
            )
            continue

        flow = project.data_flow(
            function.component,
            function.address,
            function.instruction_set,
        )
        if flow is None:
            diagnostics.append(
                PrototypeServiceDiagnostic(
                    identity,
                    "missing persisted data flow",
                )
            )
            continue

        names = build_name_context(project, function, flow)
        lifted = lift_function(
            project,
            function,
            cfg,
            flow,
            names,
        )
        ssa = build_ssa_function(lifted)
        simplified = simplify_ssa_function(ssa).function
        environment = infer_local_types(simplified)

        analyzed_functions.append(simplified)
        environments.append(environment)

    propagation = propagate_prototypes(
        tuple(analyzed_functions),
        tuple(environments),
        iteration_cap=iteration_cap,
    )
    return ProjectPrototypeAnalysis(
        propagation=propagation,
        functions=tuple(analyzed_functions),
        environments=tuple(environments),
        diagnostics=tuple(diagnostics),
    )
