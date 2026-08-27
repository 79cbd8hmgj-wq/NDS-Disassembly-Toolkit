from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ExecutionMode(StrEnum):
    ARM = "arm"
    THUMB = "thumb"


class ControlFlowKind(StrEnum):
    FALLTHROUGH = "fallthrough"
    CALL = "call"
    BRANCH = "branch"
    RETURN = "return"
    INDIRECT_BRANCH = "indirect-branch"


@dataclass(frozen=True)
class DecodedInstruction:
    address: int
    size: int
    mode: ExecutionMode
    mnemonic: str
    operands: str
    flow: ControlFlowKind
    target: int | None = None
    target_mode: ExecutionMode | None = None
    conditional: bool = False

    @property
    def end_address(self) -> int:
        return self.address + self.size


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
