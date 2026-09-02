from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from nds_disassembly_toolkit.analysis.model import (
    FunctionCandidate,
    InstructionSet,
    Symbol,
)
from nds_disassembly_toolkit.analysis.project.model import LocationAnnotation

_CANONICAL_REGISTERS = tuple(f"r{index}" for index in range(13)) + (
    "sp",
    "lr",
    "pc",
    "cpsr",
)
_REGISTER_ORDER = {name: index for index, name in enumerate(_CANONICAL_REGISTERS)}


class RuntimeCpu(StrEnum):
    ARM9 = "arm9"
    ARM7 = "arm7"

    @property
    def default_port(self) -> int:
        return 3333 if self is RuntimeCpu.ARM9 else 3334


class StopReasonKind(StrEnum):
    BREAKPOINT = "breakpoint"
    WATCHPOINT = "watchpoint"
    STEP = "step"
    INTERRUPT = "interrupt"
    SIGNAL = "signal"
    EXITED = "exited"
    UNKNOWN = "unknown"


class BreakpointKind(StrEnum):
    CODE = "code"
    READ = "read"
    WRITE = "write"
    ACCESS = "access"


@dataclass(frozen=True, slots=True)
class RegisterSnapshot:
    values: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        names: set[str] = set()
        for name, value in self.values:
            if not name:
                raise ValueError("register names must not be empty")
            if name in names:
                raise ValueError(f"duplicate register name: {name}")
            if value < 0:
                raise ValueError("register values must be non-negative")
            names.add(name)

    @classmethod
    def from_mapping(cls, values: Mapping[str, int]) -> RegisterSnapshot:
        ordered = tuple(
            sorted(
                values.items(),
                key=lambda item: (
                    0 if item[0] in _REGISTER_ORDER else 1,
                    _REGISTER_ORDER.get(item[0], 0),
                    item[0],
                ),
            )
        )
        return cls(ordered)

    def value(self, name: str) -> int | None:
        for register, value in self.values:
            if register == name:
                return value
        return None


@dataclass(frozen=True, slots=True)
class RuntimeStop:
    kind: StopReasonKind
    signal: int | None = None
    address: int | None = None
    raw: str | None = None

    def __post_init__(self) -> None:
        if self.signal is not None and self.signal < 0:
            raise ValueError("stop signal must be non-negative")
        if self.address is not None and self.address < 0:
            raise ValueError("stop address must be non-negative")


@dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    cpu: RuntimeCpu
    registers: RegisterSnapshot
    stop: RuntimeStop

    def __post_init__(self) -> None:
        if self.registers.value("pc") is None or self.registers.value("cpsr") is None:
            raise ValueError("runtime snapshot requires pc and cpsr")

    @property
    def pc(self) -> int:
        value = self.registers.value("pc")
        if value is None:
            raise ValueError("runtime snapshot requires pc and cpsr")
        return value

    @property
    def cpsr(self) -> int:
        value = self.registers.value("cpsr")
        if value is None:
            raise ValueError("runtime snapshot requires pc and cpsr")
        return value

    @property
    def instruction_set(self) -> InstructionSet:
        if self.cpsr & (1 << 5):
            return InstructionSet.THUMB
        return InstructionSet.ARM


@dataclass(frozen=True, slots=True)
class RuntimeComponentLocation:
    component: str
    function: FunctionCandidate | None = None
    symbols: tuple[Symbol, ...] = ()
    annotation: LocationAnnotation | None = None


@dataclass(frozen=True, slots=True)
class RuntimeLocation:
    pc: int
    instruction_set: InstructionSet
    candidates: tuple[RuntimeComponentLocation, ...] = ()
