from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag, StrEnum
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

    @classmethod
    def from_name(cls, name: str) -> Register | None:
        normalized = name.strip().lower()
        normalized = {"sp": "r13", "lr": "r14", "pc": "r15"}.get(
            normalized,
            normalized,
        )
        try:
            return cls(normalized)
        except ValueError:
            return None


class ConditionCode(StrEnum):
    INVALID = "invalid"
    EQ = "eq"
    NE = "ne"
    HS = "hs"
    CS = "hs"
    LO = "lo"
    CC = "lo"
    MI = "mi"
    PL = "pl"
    VS = "vs"
    VC = "vc"
    HI = "hi"
    LS = "ls"
    GE = "ge"
    LT = "lt"
    GT = "gt"
    LE = "le"
    AL = "al"


class OperandKind(StrEnum):
    REGISTER = "register"
    IMMEDIATE = "immediate"
    MEMORY = "memory"
    REGISTER_LIST = "register_list"


class OperandAccess(IntFlag):
    NONE = 0
    READ = 1
    WRITE = 2


class ShiftKind(StrEnum):
    NONE = "none"
    LSL = "lsl"
    LSR = "lsr"
    ASR = "asr"
    ROR = "ror"
    RRX = "rrx"


@dataclass(frozen=True)
class OperandShift:
    kind: ShiftKind = ShiftKind.NONE
    value: int = 0


@dataclass(frozen=True)
class MemoryOperand:
    base: Register | None
    index: Register | None
    scale: int
    displacement: int
    subtract_index: bool = False


@dataclass(frozen=True)
class InstructionOperand:
    kind: OperandKind
    access: OperandAccess
    register: Register | None = None
    registers: tuple[Register, ...] = ()
    immediate: int | None = None
    memory: MemoryOperand | None = None
    shift: OperandShift = field(default_factory=OperandShift)
    access_width: int | None = None

    def __post_init__(self) -> None:
        register_payload = self.register is not None
        register_list_payload = bool(self.registers)
        immediate_payload = self.immediate is not None
        memory_payload = self.memory is not None

        valid_payload = {
            OperandKind.REGISTER: (
                register_payload
                and not register_list_payload
                and not immediate_payload
                and not memory_payload
            ),
            OperandKind.IMMEDIATE: (
                immediate_payload
                and not register_payload
                and not register_list_payload
                and not memory_payload
            ),
            OperandKind.MEMORY: (
                memory_payload
                and not register_payload
                and not register_list_payload
                and not immediate_payload
            ),
            OperandKind.REGISTER_LIST: (
                register_list_payload
                and not register_payload
                and not immediate_payload
                and not memory_payload
            ),
        }[self.kind]
        if not valid_payload:
            raise ValueError(f"operand payload does not match {self.kind.value} kind")
        if self.access_width is not None and self.access_width <= 0:
            raise ValueError("operand payload access width must be positive")


@dataclass(frozen=True)
class InstructionSemantics:
    operands: tuple[InstructionOperand, ...] = ()
    registers_read: tuple[Register, ...] = ()
    registers_written: tuple[Register, ...] = ()
    condition: ConditionCode = ConditionCode.AL
    writeback: bool = False


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


class AbstractValueKind(StrEnum):
    UNKNOWN = "unknown"
    CONSTANT = "constant"
    ADDRESS = "address"


@dataclass(frozen=True)
class AbstractValue:
    kind: AbstractValueKind
    value: int | None = None
    component: str | None = None
    provenance: tuple[int, ...] = field(default=(), compare=False)

    def __post_init__(self) -> None:
        if any(address < 0 for address in self.provenance):
            raise ValueError("abstract-value provenance addresses must be non-negative")
        object.__setattr__(self, "provenance", tuple(sorted(set(self.provenance))))
        if self.kind is AbstractValueKind.UNKNOWN:
            if self.value is not None or self.component is not None:
                raise ValueError("unknown abstract value cannot carry value or component")
            return
        if self.value is None or not 0 <= self.value <= 0xFFFFFFFF:
            raise ValueError("known abstract value must carry an unsigned 32-bit value")
        if self.kind is AbstractValueKind.CONSTANT and self.component is not None:
            raise ValueError("constant abstract value cannot carry a component")
        if self.component == "":
            raise ValueError("abstract-value component cannot be empty")


@dataclass(frozen=True)
class RegisterState:
    values: tuple[tuple[Register, AbstractValue], ...] = ()

    def __post_init__(self) -> None:
        normalized: dict[Register, AbstractValue] = {}
        for register, value in self.values:
            if register in normalized:
                raise ValueError(f"duplicate register state for {register.value}")
            if value.kind is not AbstractValueKind.UNKNOWN:
                normalized[register] = value
        object.__setattr__(
            self,
            "values",
            tuple(
                sorted(
                    normalized.items(),
                    key=lambda item: int(item[0].value[1:]),
                )
            ),
        )

    def value(self, register: Register) -> AbstractValue:
        for candidate, value in self.values:
            if candidate is register:
                return value
        return AbstractValue(AbstractValueKind.UNKNOWN)

    def with_value(self, register: Register, value: AbstractValue) -> RegisterState:
        updated = dict(self.values)
        if value.kind is AbstractValueKind.UNKNOWN:
            updated.pop(register, None)
        else:
            updated[register] = value
        return RegisterState(tuple(updated.items()))


@dataclass(frozen=True)
class InstructionFlowState:
    instruction: DecodedInstruction
    before: RegisterState
    after: RegisterState

    @property
    def address(self) -> int:
        return self.instruction.address


@dataclass(frozen=True)
class BlockFlowState:
    address: int
    instruction_set: InstructionSet
    entry: RegisterState
    exit: RegisterState


@dataclass(frozen=True)
class FunctionDataFlow:
    function: FunctionCandidate
    blocks: tuple[BlockFlowState, ...]
    instructions: tuple[InstructionFlowState, ...]
    warnings: tuple[str, ...] = ()

    def at_instruction(self, address: int) -> InstructionFlowState | None:
        return next(
            (state for state in self.instructions if state.address == address),
            None,
        )

    def for_block(self, address: int) -> BlockFlowState | None:
        return next(
            (state for state in self.blocks if state.address == address),
            None,
        )
