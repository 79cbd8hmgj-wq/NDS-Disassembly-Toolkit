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
    used_resolved_call_results,
)
from nds_disassembly_toolkit.analysis.decompiler.type_model import (
    IntegerType,
    PointerType,
    RecoveredSignedness,
    RecoveredStructType,
    RecoveredType,
    UnknownType,
    VoidType,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    FunctionTypeIdentity,
    LocalTypeEnvironment,
    RenderTypeContext,
    build_render_type_context,
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



def _recovered_c_type(
    recovered: RecoveredType,
    *,
    allow_void: bool = False,
) -> str | None:
    if isinstance(recovered, UnknownType):
        return None
    if isinstance(recovered, VoidType):
        return "void" if allow_void else None
    if isinstance(recovered, IntegerType):
        prefix = (
            "int"
            if recovered.signedness is RecoveredSignedness.SIGNED
            else "uint"
        )
        return f"{prefix}{recovered.width_bytes * 8}_t"
    if isinstance(recovered, PointerType):
        if recovered.pointee_name is not None:
            return f"struct {recovered.pointee_name} *"
        return "void *"
    if isinstance(recovered, RecoveredStructType):
        return f"struct {recovered.name}"
    return None


def _pointer_struct_name(
    recovered: RecoveredType,
) -> str | None:
    if isinstance(recovered, PointerType):
        return recovered.pointee_name
    return None


def build_project_render_type_context(
    analysis: ProjectPrototypeAnalysis,
    identity: FunctionTypeIdentity,
) -> RenderTypeContext:
    function = analysis.ssa_for(identity)
    environment = analysis.environment_for(identity)
    prototype = analysis.propagation.prototype_for(identity)
    if function is None or environment is None or prototype is None:
        return RenderTypeContext()

    local_context = build_render_type_context(
        function,
        environment,
    )
    parameter_types = dict(local_context.parameter_types)
    forward_structs: set[str] = set(local_context.forward_structs)

    for parameter in prototype.parameters:
        type_name = _recovered_c_type(parameter.recovered_type)
        if type_name is not None:
            parameter_types[parameter.name] = type_name
        struct_name = _pointer_struct_name(
            parameter.recovered_type
        )
        if struct_name is not None:
            forward_structs.add(struct_name)

    local_types = dict(local_context.local_types)
    for index, result in enumerate(
        used_resolved_call_results(function)
    ):
        recovered = analysis.propagation.type_for_value(
            identity,
            result,
        )
        if recovered is None:
            continue
        type_name = _recovered_c_type(recovered)
        if type_name is not None:
            local_types[f"call_result_{index}"] = type_name
        struct_name = _pointer_struct_name(recovered)
        if struct_name is not None:
            forward_structs.add(struct_name)

    return_type = _recovered_c_type(
        prototype.return_type,
        allow_void=True,
    )
    return_struct = _pointer_struct_name(prototype.return_type)
    if return_struct is not None:
        forward_structs.add(return_struct)

    defined_structures = {
        structure.name
        for structure in local_context.structures
    }
    return RenderTypeContext(
        parameter_types=tuple(
            (parameter.name, parameter_types[parameter.name])
            for parameter in function.parameters
            if parameter.name in parameter_types
        ),
        local_types=tuple(sorted(local_types.items())),
        structures=local_context.structures,
        forward_structs=tuple(
            sorted(forward_structs - defined_structures)
        ),
        return_type=return_type,
    )
