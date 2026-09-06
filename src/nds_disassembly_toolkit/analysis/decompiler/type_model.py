from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from nds_disassembly_toolkit.analysis.decompiler.model import SourceRef

_MEMORY_WIDTHS = frozenset({1, 2, 4})


def _validate_name(value: str, *, label: str) -> None:
    if not value:
        raise ValueError(f"{label} cannot be empty")


def _validate_width(width: int) -> None:
    if width not in _MEMORY_WIDTHS:
        raise ValueError("integer/field width must be 1, 2, or 4 bytes")


class RecoveredTypeKind(StrEnum):
    UNKNOWN = "unknown"
    INTEGER = "integer"
    POINTER = "pointer"
    STRUCT = "struct"


class RecoveredSignedness(StrEnum):
    UNKNOWN = "unknown"
    UNSIGNED = "unsigned"
    SIGNED = "signed"


@dataclass(frozen=True, slots=True)
class UnknownType:
    @property
    def kind(self) -> RecoveredTypeKind:
        return RecoveredTypeKind.UNKNOWN


@dataclass(frozen=True, slots=True)
class IntegerType:
    width_bytes: int
    signedness: RecoveredSignedness = RecoveredSignedness.UNKNOWN

    def __post_init__(self) -> None:
        _validate_width(self.width_bytes)

    @property
    def kind(self) -> RecoveredTypeKind:
        return RecoveredTypeKind.INTEGER


@dataclass(frozen=True, slots=True)
class PointerType:
    pointee_name: str | None = None
    component: str | None = None

    def __post_init__(self) -> None:
        if self.pointee_name == "":
            raise ValueError("pointer pointee name cannot be empty")
        if self.component == "":
            raise ValueError("pointer component cannot be empty")

    @property
    def kind(self) -> RecoveredTypeKind:
        return RecoveredTypeKind.POINTER


RecoveredFieldType: TypeAlias = UnknownType | IntegerType | PointerType


@dataclass(frozen=True, slots=True)
class RecoveredStructField:
    offset: int
    width_bytes: int
    name: str
    field_type: RecoveredFieldType
    source: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("structure field offset must be non-negative")
        _validate_width(self.width_bytes)
        _validate_name(self.name, label="field name")


@dataclass(frozen=True, slots=True)
class RecoveredStructType:
    name: str
    fields: tuple[RecoveredStructField, ...]

    def __post_init__(self) -> None:
        _validate_name(self.name, label="structure name")
        ordered = tuple(sorted(self.fields, key=lambda field: field.offset))
        seen: set[int] = set()
        previous_end = 0
        for field in ordered:
            if field.offset in seen:
                raise ValueError("duplicate structure field offset")
            seen.add(field.offset)
            if field.offset < previous_end:
                raise ValueError("structure fields overlap")
            previous_end = field.offset + field.width_bytes
        object.__setattr__(self, "fields", ordered)

    @property
    def kind(self) -> RecoveredTypeKind:
        return RecoveredTypeKind.STRUCT

    @property
    def minimum_size(self) -> int:
        if not self.fields:
            return 0
        last = self.fields[-1]
        return last.offset + last.width_bytes


RecoveredType: TypeAlias = (
    UnknownType
    | IntegerType
    | PointerType
    | RecoveredStructType
)


class TypeEvidenceKind(StrEnum):
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    POINTER_DEREFERENCE = "pointer_dereference"
    POINTER_ARITHMETIC = "pointer_arithmetic"
    INTEGER_ARITHMETIC = "integer_arithmetic"
    SIGNED_COMPARE = "signed_compare"
    UNSIGNED_COMPARE = "unsigned_compare"
    CALL_ARGUMENT = "call_argument"
    CALL_RETURN = "call_return"
    PHI_JOIN = "phi_join"
    EXACT_ADDRESS = "exact_address"


@dataclass(frozen=True, slots=True)
class TypeEvidence:
    kind: TypeEvidenceKind
    source: tuple[SourceRef, ...] = ()
    description: str = ""
