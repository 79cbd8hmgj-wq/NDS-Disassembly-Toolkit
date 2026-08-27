from __future__ import annotations

from dataclasses import dataclass
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
