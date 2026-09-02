from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.lift import lift_function
from nds_disassembly_toolkit.analysis.decompiler.model import DecompilationResult
from nds_disassembly_toolkit.analysis.decompiler.names import build_name_context
from nds_disassembly_toolkit.analysis.decompiler.render import render_pseudo_c
from nds_disassembly_toolkit.analysis.decompiler.structure import structure_function
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
    ir = lift_function(project, function, cfg, flow, names)
    structured = structure_function(ir)
    pseudo_c = render_pseudo_c(structured)
    return DecompilationResult(ir, structured, pseudo_c)
