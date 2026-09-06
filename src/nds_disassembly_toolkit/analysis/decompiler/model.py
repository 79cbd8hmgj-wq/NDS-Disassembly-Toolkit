from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from nds_disassembly_toolkit.analysis.model import (
    CFGEdge,
    ConditionCode,
    InstructionSet,
    Register,
)

_U32_MAX = 0xFFFFFFFF
_MEMORY_WIDTHS = frozenset({1, 2, 4})


def _validate_u32(value: int, *, name: str) -> None:
    if not 0 <= value <= _U32_MAX:
        raise ValueError(f"{name} must be an unsigned 32-bit value")


def _validate_name(value: str, *, name: str) -> None:
    if not value:
        raise ValueError(f"{name} cannot be empty")


def _validate_width(width: int) -> None:
    if width not in _MEMORY_WIDTHS:
        raise ValueError("memory width must be 1, 2, or 4 bytes")


@dataclass(frozen=True, slots=True)
class SourceRef:
    address: int
    instruction_set: InstructionSet

    def __post_init__(self) -> None:
        _validate_u32(self.address, name="source address")


class DecompilerVariableKind(StrEnum):
    ARGUMENT = "argument"
    LOCAL = "local"
    TEMPORARY = "temporary"


@dataclass(frozen=True, slots=True)
class DecompilerVariable:
    name: str
    kind: DecompilerVariableKind
    register: Register | None = None
    stack_offset: int | None = None

    def __post_init__(self) -> None:
        _validate_name(self.name, name="variable name")
        if self.kind is DecompilerVariableKind.ARGUMENT:
            if (self.register is None) == (self.stack_offset is None):
                raise ValueError(
                    "argument variable must have exactly one register or stack location"
                )
            return
        if self.kind is DecompilerVariableKind.LOCAL:
            if self.stack_offset is None or self.register is not None:
                raise ValueError("local variable must have a stack offset only")
            return
        if self.register is not None or self.stack_offset is not None:
            raise ValueError("temporary variable cannot carry register or stack metadata")


@dataclass(frozen=True, slots=True)
class ConstantExpression:
    value: int
    source: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        _validate_u32(self.value, name="constant value")


@dataclass(frozen=True, slots=True)
class AddressExpression:
    address: int
    component: str | None
    source: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        _validate_u32(self.address, name="address expression")
        if self.component == "":
            raise ValueError("address component cannot be empty")


@dataclass(frozen=True, slots=True)
class VariableExpression:
    variable: DecompilerVariable
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class RegisterExpression:
    register: Register
    source: tuple[SourceRef, ...] = ()


class UnaryOperator(StrEnum):
    NEGATE = "negate"
    BITWISE_NOT = "bitwise_not"


class BinaryOperator(StrEnum):
    ADD = "add"
    SUBTRACT = "subtract"
    MULTIPLY = "multiply"
    BITWISE_AND = "bitwise_and"
    BITWISE_OR = "bitwise_or"
    BITWISE_XOR = "bitwise_xor"
    SHIFT_LEFT = "shift_left"
    SHIFT_RIGHT_LOGICAL = "shift_right_logical"
    SHIFT_RIGHT_ARITHMETIC = "shift_right_arithmetic"


@dataclass(frozen=True, slots=True)
class UnaryExpression:
    operator: UnaryOperator
    operand: DecompilerExpression
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class BinaryExpression:
    operator: BinaryOperator
    left: DecompilerExpression
    right: DecompilerExpression
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class CompareExpression:
    condition: ConditionCode
    left: DecompilerExpression
    right: DecompilerExpression
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class MemoryReadExpression:
    address: DecompilerExpression
    width: int
    source: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        _validate_width(self.width)


@dataclass(frozen=True, slots=True)
class FieldAddressExpression:
    base: DecompilerExpression
    structure_name: str
    field_name: str
    offset: int
    width: int
    source: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        _validate_name(self.structure_name, name="field structure name")
        _validate_name(self.field_name, name="field name")
        if self.offset < 0:
            raise ValueError("field offset must be non-negative")
        _validate_width(self.width)


@dataclass(frozen=True, slots=True)
class CallExpression:
    name: str
    target_address: int
    target_instruction_set: InstructionSet
    target_component: str | None
    arguments: tuple[DecompilerExpression, ...] = ()
    source: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        _validate_name(self.name, name="call name")
        _validate_u32(self.target_address, name="call target address")
        if self.target_component == "":
            raise ValueError("call target component cannot be empty")


@dataclass(frozen=True, slots=True)
class UnknownExpression:
    description: str
    source: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        _validate_name(self.description, name="unknown expression description")


DecompilerExpression: TypeAlias = (
    ConstantExpression
    | AddressExpression
    | VariableExpression
    | RegisterExpression
    | UnaryExpression
    | BinaryExpression
    | CompareExpression
    | MemoryReadExpression
    | FieldAddressExpression
    | CallExpression
    | UnknownExpression
)


@dataclass(frozen=True, slots=True)
class AssignmentStatement:
    target: VariableExpression | RegisterExpression
    value: DecompilerExpression
    source: tuple[SourceRef, ...]


@dataclass(frozen=True, slots=True)
class MemoryWriteStatement:
    address: DecompilerExpression
    value: DecompilerExpression
    width: int
    source: tuple[SourceRef, ...]

    def __post_init__(self) -> None:
        _validate_width(self.width)


@dataclass(frozen=True, slots=True)
class CallStatement:
    call: CallExpression
    source: tuple[SourceRef, ...]


@dataclass(frozen=True, slots=True)
class ReturnStatement:
    value: DecompilerExpression | None
    source: tuple[SourceRef, ...]


@dataclass(frozen=True, slots=True)
class BranchStatement:
    condition: DecompilerExpression | None
    target_address: int
    target_instruction_set: InstructionSet
    source: tuple[SourceRef, ...]

    def __post_init__(self) -> None:
        _validate_u32(self.target_address, name="branch target address")


@dataclass(frozen=True, slots=True)
class UnknownStatement:
    description: str
    source: tuple[SourceRef, ...]

    def __post_init__(self) -> None:
        _validate_name(self.description, name="unknown statement description")


DecompilerStatement: TypeAlias = (
    AssignmentStatement
    | MemoryWriteStatement
    | CallStatement
    | ReturnStatement
    | BranchStatement
    | UnknownStatement
)


@dataclass(frozen=True, slots=True)
class DecompiledBlock:
    address: int
    instruction_set: InstructionSet
    statements: tuple[DecompilerStatement, ...]
    edges: tuple[CFGEdge, ...]

    def __post_init__(self) -> None:
        _validate_u32(self.address, name="decompiled block address")


@dataclass(frozen=True, slots=True)
class DecompiledFunction:
    component: str
    address: int
    instruction_set: InstructionSet
    name: str
    parameters: tuple[DecompilerVariable, ...]
    locals: tuple[DecompilerVariable, ...]
    blocks: tuple[DecompiledBlock, ...]
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_name(self.component, name="function component")
        _validate_u32(self.address, name="decompiled function address")
        _validate_name(self.name, name="function name")


@dataclass(frozen=True, slots=True)
class StatementNode:
    statement: DecompilerStatement


@dataclass(frozen=True, slots=True)
class LabelNode:
    address: int

    def __post_init__(self) -> None:
        _validate_u32(self.address, name="label address")


@dataclass(frozen=True, slots=True)
class GotoNode:
    target_address: int

    def __post_init__(self) -> None:
        _validate_u32(self.target_address, name="goto target address")


@dataclass(frozen=True, slots=True)
class IfNode:
    condition: DecompilerExpression
    then_body: tuple[StructuredNode, ...]
    else_body: tuple[StructuredNode, ...] = ()


@dataclass(frozen=True, slots=True)
class LoopNode:
    condition: DecompilerExpression
    body: tuple[StructuredNode, ...]
    post_test: bool = False


StructuredNode: TypeAlias = StatementNode | LabelNode | GotoNode | IfNode | LoopNode


@dataclass(frozen=True, slots=True)
class StructuredFunction:
    function: DecompiledFunction
    body: tuple[StructuredNode, ...]
    fallback_used: bool


@dataclass(frozen=True, slots=True)
class DecompilationResult:
    ir: DecompiledFunction
    structured: StructuredFunction
    pseudo_c: str
