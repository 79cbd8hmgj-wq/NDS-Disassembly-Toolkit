from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


@dataclass(frozen=True)
class Component:
    name: str
    path: Path
    base_address: int
    data: bytes

    @property
    def end_address(self) -> int:
        return self.base_address + len(self.data)

    def address_for_offset(self, offset: int) -> int:
        if not 0 <= offset < len(self.data):
            raise ValueError(f"offset 0x{offset:X} is outside {self.name}")
        return self.base_address + offset

    def offset_for_address(self, address: int) -> int:
        if not self.base_address <= address < self.end_address:
            raise ValueError(f"address 0x{address:X} is outside {self.name}")
        return address - self.base_address


@dataclass(frozen=True)
class StringRecord:
    component: str
    offset: int
    address: int
    text: str


@dataclass(frozen=True)
class PointerReference:
    component: str
    offset: int
    address: int
    target_address: int


@dataclass(frozen=True)
class NumericMatch:
    component: str
    offset: int
    address: int
    record_index: int
    record_name: str
    values: tuple[int, ...]
    encoding: str


@dataclass(frozen=True)
class SymbolCandidate:
    component: str
    address: int
    offset: int
    name: str
    confidence: str
    evidence: str


class InstructionSet(StrEnum):
    ARM = "arm"
    THUMB = "thumb"

    @property
    def alignment(self) -> int:
        return 4 if self is InstructionSet.ARM else 2


class ControlFlowKind(StrEnum):
    ORDINARY = "ordinary"
    CALL = "call"
    BRANCH = "branch"
    RETURN = "return"


class Register(StrEnum):
    R0 = "r0"
    R1 = "r1"
    R2 = "r2"
    R3 = "r3"
    R4 = "r4"
    R5 = "r5"
    R6 = "r6"
    R7 = "r7"
    R8 = "r8"
    R9 = "r9"
    R10 = "r10"
    R11 = "r11"
    R12 = "r12"
    R13 = "r13"
    SP = "r13"
    R14 = "r14"
    LR = "r14"
    R15 = "r15"
    PC = "r15"


@dataclass(frozen=True)
class InstructionSemantics:
    pass


@dataclass(frozen=True)
class DecodedInstruction:
    address: int
    size: int
    data: bytes
    mnemonic: str
    operands: str
    instruction_set: InstructionSet
    control_flow: ControlFlowKind
    direct_target: int | None = None
    target_instruction_set: InstructionSet | None = None
    conditional: bool = False
    semantics: InstructionSemantics = field(default_factory=InstructionSemantics)


@dataclass(frozen=True)
class FunctionSeed:
    address: int
    instruction_set: InstructionSet
    source: str = "explicit"


@dataclass(frozen=True)
class FunctionCandidate:
    component: str
    address: int
    offset: int
    instruction_set: InstructionSet
    confidence: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class FunctionDiscoveryResult:
    functions: tuple[FunctionCandidate, ...]
    unresolved_calls: tuple[int, ...]
    decode_failures: tuple[int, ...]


class CFGEdgeKind(StrEnum):
    FALLTHROUGH = "fallthrough"
    BRANCH = "branch"
    CALL = "call"


@dataclass(frozen=True)
class BasicBlock:
    component: str
    address: int
    offset: int
    instruction_set: InstructionSet
    instructions: tuple[DecodedInstruction, ...]

    @property
    def size(self) -> int:
        return sum(instruction.size for instruction in self.instructions)

    @property
    def end_address(self) -> int:
        return self.address + self.size


@dataclass(frozen=True)
class CFGEdge:
    source_address: int
    source_instruction_address: int
    target_address: int
    target_instruction_set: InstructionSet
    kind: CFGEdgeKind


@dataclass(frozen=True)
class UnresolvedTransfer:
    source_address: int
    instruction_set: InstructionSet
    control_flow: ControlFlowKind
    mnemonic: str
    operands: str


@dataclass(frozen=True)
class FunctionControlFlowGraph:
    function: FunctionCandidate
    blocks: tuple[BasicBlock, ...]
    edges: tuple[CFGEdge, ...]
    unresolved_transfers: tuple[UnresolvedTransfer, ...]
    decode_failures: tuple[int, ...]


class CrossReferenceKind(StrEnum):
    CALL = "call"
    BRANCH = "branch"
    DATA_POINTER = "data_pointer"


@dataclass(frozen=True)
class CrossReference:
    kind: CrossReferenceKind
    source_component: str
    source_address: int
    source_function_address: int | None
    source_instruction_set: InstructionSet | None
    target_address: int
    target_instruction_set: InstructionSet | None


@dataclass(frozen=True)
class CrossReferenceIndex:
    references: tuple[CrossReference, ...]

    def to_address(
        self,
        address: int,
        *,
        kind: CrossReferenceKind | None = None,
    ) -> tuple[CrossReference, ...]:
        return tuple(
            reference
            for reference in self.references
            if reference.target_address == address and (kind is None or reference.kind is kind)
        )

    def from_address(
        self,
        address: int,
        *,
        kind: CrossReferenceKind | None = None,
    ) -> tuple[CrossReference, ...]:
        return tuple(
            reference
            for reference in self.references
            if reference.source_address == address and (kind is None or reference.kind is kind)
        )


@dataclass(frozen=True)
class CallGraphEdge:
    caller_component: str
    caller_function_address: int
    callsite_address: int
    target_address: int
    target_instruction_set: InstructionSet | None


class SymbolKind(StrEnum):
    FUNCTION = "function"
    LABEL = "label"
    STRING = "string"
    DATA = "data"
    NAMED = "named"


@dataclass(frozen=True)
class Symbol:
    component: str
    address: int
    offset: int
    name: str
    kind: SymbolKind
    instruction_set: InstructionSet | None
    confidence: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class SymbolTable:
    symbols: tuple[Symbol, ...]

    def at_address(
        self,
        address: int,
        *,
        component: str | None = None,
    ) -> tuple[Symbol, ...]:
        return tuple(
            symbol
            for symbol in self.symbols
            if symbol.address == address and (component is None or symbol.component == component)
        )

    def by_name(
        self,
        name: str,
        *,
        component: str | None = None,
    ) -> tuple[Symbol, ...]:
        return tuple(
            symbol
            for symbol in self.symbols
            if symbol.name == name and (component is None or symbol.component == component)
        )

    def for_component(self, component: str) -> tuple[Symbol, ...]:
        return tuple(symbol for symbol in self.symbols if symbol.component == component)
