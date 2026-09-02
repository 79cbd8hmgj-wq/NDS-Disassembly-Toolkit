from __future__ import annotations

import re
from dataclasses import dataclass

from nds_disassembly_toolkit.analysis.decompiler.model import (
    DecompilerVariable,
    DecompilerVariableKind,
)
from nds_disassembly_toolkit.analysis.model import (
    ArgumentLocationKind,
    FunctionCandidate,
    FunctionDataFlow,
    InstructionSet,
    Register,
    StackSlotKind,
    SymbolKind,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject

_IDENTIFIER = re.compile(r"[^0-9A-Za-z_]")
_C_KEYWORDS = frozenset(
    {
        "else",
        "goto",
        "if",
        "int32_t",
        "return",
        "uint16_t",
        "uint32_t",
        "uint8_t",
        "void",
        "while",
    }
)


@dataclass(frozen=True, slots=True)
class NameContext:
    function_name: str
    parameters: tuple[DecompilerVariable, ...]
    locals: tuple[DecompilerVariable, ...]
    register_arguments: tuple[tuple[Register, DecompilerVariable], ...]
    stack_arguments: tuple[tuple[int, DecompilerVariable], ...]
    stack_locals: tuple[tuple[int, DecompilerVariable], ...]


class TemporaryAllocator:
    def __init__(self) -> None:
        self._by_definition: dict[tuple[int, Register], DecompilerVariable] = {}
        self._variables: list[DecompilerVariable] = []

    def for_definition(self, address: int, register: Register) -> DecompilerVariable:
        if not 0 <= address <= 0xFFFFFFFF:
            raise ValueError("temporary definition address must be an unsigned 32-bit value")
        key = (address, register)
        existing = self._by_definition.get(key)
        if existing is not None:
            return existing
        variable = DecompilerVariable(
            name=f"tmp_{len(self._variables)}",
            kind=DecompilerVariableKind.TEMPORARY,
        )
        self._by_definition[key] = variable
        self._variables.append(variable)
        return variable

    def variables(self) -> tuple[DecompilerVariable, ...]:
        return tuple(self._variables)


def sanitize_identifier(value: str) -> str:
    normalized = _IDENTIFIER.sub("_", value.strip())
    if not normalized:
        normalized = "unnamed"
    if normalized[0].isdigit():
        normalized = "_" + normalized
    if normalized in _C_KEYWORDS:
        normalized += "_"
    return normalized


def _claim_name(base: str, used: set[str]) -> str:
    name = sanitize_identifier(base)
    if name not in used:
        used.add(name)
        return name
    suffix = 2
    while f"{name}_{suffix}" in used:
        suffix += 1
    unique = f"{name}_{suffix}"
    used.add(unique)
    return unique


def _function_name(
    project: AnalysisProject,
    function: FunctionCandidate,
) -> str:
    annotation = project.annotation(function.component, function.address)
    if annotation is not None and annotation.name_override is not None:
        return sanitize_identifier(annotation.name_override)

    matches = tuple(
        symbol
        for symbol in project.symbols_at(function.component, function.address)
        if symbol.kind is SymbolKind.FUNCTION
        and (
            symbol.instruction_set is None
            or symbol.instruction_set is function.instruction_set
        )
    )
    if len(matches) == 1:
        return sanitize_identifier(matches[0].name)
    return f"sub_{function.address:08X}"


def _stack_name(prefix: str, offset: int) -> str:
    if offset < 0:
        return f"{prefix}_{abs(offset):02X}"
    return f"{prefix}_{offset:02X}"


def build_name_context(
    project: AnalysisProject,
    function: FunctionCandidate,
    flow: FunctionDataFlow,
) -> NameContext:
    if flow.function != function:
        raise ValueError("data flow does not belong to requested function")

    parameters: list[DecompilerVariable] = []
    locals_: list[DecompilerVariable] = []
    register_arguments: list[tuple[Register, DecompilerVariable]] = []
    stack_arguments: list[tuple[int, DecompilerVariable]] = []
    stack_locals: list[tuple[int, DecompilerVariable]] = []
    used: set[str] = set()

    summary = flow.summary
    if summary is not None:
        register_evidence = sorted(
            (
                argument
                for argument in summary.arguments
                if argument.kind is ArgumentLocationKind.REGISTER
                and argument.index is not None
                and argument.register is not None
            ),
            key=lambda argument: argument.index if argument.index is not None else -1,
        )
        for argument in register_evidence:
            assert argument.index is not None
            assert argument.register is not None
            variable = DecompilerVariable(
                _claim_name(f"arg{argument.index}", used),
                DecompilerVariableKind.ARGUMENT,
                register=argument.register,
            )
            parameters.append(variable)
            register_arguments.append((argument.register, variable))

        stack_evidence = sorted(
            (
                argument
                for argument in summary.arguments
                if argument.kind is ArgumentLocationKind.STACK
                and argument.stack_offset is not None
            ),
            key=lambda argument: (
                argument.stack_offset if argument.stack_offset is not None else 0
            ),
        )
        for argument in stack_evidence:
            assert argument.stack_offset is not None
            variable = DecompilerVariable(
                _claim_name(_stack_name("arg_stack", argument.stack_offset), used),
                DecompilerVariableKind.ARGUMENT,
                stack_offset=argument.stack_offset,
            )
            parameters.append(variable)
            stack_arguments.append((argument.stack_offset, variable))

        local_slots = sorted(
            (slot for slot in summary.stack_slots if slot.kind is StackSlotKind.LOCAL),
            key=lambda slot: (abs(slot.offset), slot.offset),
        )
        for slot in local_slots:
            variable = DecompilerVariable(
                _claim_name(_stack_name("local", slot.offset), used),
                DecompilerVariableKind.LOCAL,
                stack_offset=slot.offset,
            )
            locals_.append(variable)
            stack_locals.append((slot.offset, variable))

    return NameContext(
        function_name=_function_name(project, function),
        parameters=tuple(parameters),
        locals=tuple(locals_),
        register_arguments=tuple(register_arguments),
        stack_arguments=tuple(stack_arguments),
        stack_locals=tuple(stack_locals),
    )


@dataclass(frozen=True, slots=True)
class ResolvedCallTarget:
    name: str
    address: int
    instruction_set: InstructionSet
    component: str | None
    parameter_registers: tuple[Register, ...]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("resolved call name cannot be empty")
        if not 0 <= self.address <= 0xFFFFFFFF:
            raise ValueError("resolved call address must be an unsigned 32-bit value")
        if self.component == "":
            raise ValueError("resolved call component cannot be empty")


def resolve_call_target(
    project: AnalysisProject,
    *,
    current_component: str,
    address: int,
    instruction_set: InstructionSet,
) -> ResolvedCallTarget:
    del current_component
    matches = tuple(
        function
        for identity in project.component_identities()
        if (
            function := project.function(
                identity.name,
                address,
                instruction_set,
            )
        )
        is not None
    )
    if len(matches) != 1:
        return ResolvedCallTarget(
            name=f"sub_{address:08X}",
            address=address,
            instruction_set=instruction_set,
            component=None,
            parameter_registers=(),
        )

    function = matches[0]
    name = _function_name(project, function)
    flow = project.data_flow(function.component, address, instruction_set)
    parameter_registers: tuple[Register, ...] = ()
    if flow is not None and flow.summary is not None:
        register_arguments = sorted(
            (
                argument
                for argument in flow.summary.arguments
                if argument.kind is ArgumentLocationKind.REGISTER
                and argument.index is not None
                and argument.register is not None
            ),
            key=lambda argument: argument.index if argument.index is not None else -1,
        )
        parameter_registers = tuple(
            argument.register
            for argument in register_arguments
            if argument.register is not None
        )

    return ResolvedCallTarget(
        name=name,
        address=address,
        instruction_set=instruction_set,
        component=function.component,
        parameter_registers=parameter_registers,
    )
