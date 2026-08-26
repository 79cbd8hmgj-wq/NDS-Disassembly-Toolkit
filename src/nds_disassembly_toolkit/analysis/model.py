from __future__ import annotations

from dataclasses import dataclass
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
