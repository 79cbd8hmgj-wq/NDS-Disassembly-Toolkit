from __future__ import annotations

from dataclasses import replace

from nds_disassembly_toolkit.analysis.decompiler.lift import lift_function
from nds_disassembly_toolkit.analysis.decompiler.lower import lower_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.model import DecompilationResult
from nds_disassembly_toolkit.analysis.decompiler.names import build_name_context
from nds_disassembly_toolkit.analysis.decompiler.render import render_pseudo_c
from nds_disassembly_toolkit.analysis.decompiler.simplify import simplify_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.ssa import build_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.structure import structure_function
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    build_render_type_context,
    infer_local_types,
)
from nds_disassembly_toolkit.analysis.decompiler.value_facts import analyze_value_facts
from nds_disassembly_toolkit.analysis.model import InstructionSet
from nds_disassembly_toolkit.analysis.project import AnalysisProject
from nds_disassembly_toolkit.errors import DecompilerError


def _identity(component: str, address: int, instruction_set: InstructionSet) -> str:
    return f"{component} 0x{address:08x} ({instruction_set.value})"


def decompile_function(
    project: AnalysisProject,
    component: str,
    address: int,
    instruction_set: InstructionSet,
) -> DecompilationResult:
    identity = _identity(component, address, instruction_set)
    function = project.function(component, address, instruction_set)
    if function is None:
        raise DecompilerError(f"no persisted function for {identity}")

    cfg = project.cfg(component, address, instruction_set)
    if cfg is None:
        raise DecompilerError(f"no persisted CFG for {identity}")

    flow = project.data_flow(component, address, instruction_set)
    if flow is None:
        raise DecompilerError(f"no persisted data flow for {identity}")

    names = build_name_context(project, function, flow)
    lifted = lift_function(project, function, cfg, flow, names)

    ssa = build_ssa_function(lifted)
    facts = analyze_value_facts(ssa)
    if not facts.converged:
        warning = (
            "SSA value-facts analysis reached its iteration cap before convergence"
        )
        if warning not in ssa.warnings:
            ssa = replace(ssa, warnings=(*ssa.warnings, warning))

    simplified = simplify_ssa_function(ssa)
    type_environment = infer_local_types(simplified.function)
    ir = lower_ssa_function(
        simplified.function,
        type_environment=type_environment,
    )
    type_context = build_render_type_context(
        simplified.function,
        type_environment,
    )
    structured = structure_function(ir)
    pseudo_c = render_pseudo_c(
        structured,
        type_context=type_context,
    )
    return DecompilationResult(ir, structured, pseudo_c)
