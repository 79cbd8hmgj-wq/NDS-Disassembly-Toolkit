from __future__ import annotations

import pytest

from nds_disassembly_toolkit.analysis.decompiler.model import SourceRef
from nds_disassembly_toolkit.analysis.decompiler.type_model import (
    IntegerType,
    PointerType,
    RecoveredSignedness,
    RecoveredStructField,
    RecoveredStructType,
    RecoveredTypeKind,
    TypeEvidence,
    TypeEvidenceKind,
    UnknownType,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet


def _source(address: int = 0x02000000) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def test_unknown_type_has_explicit_kind() -> None:
    assert UnknownType().kind is RecoveredTypeKind.UNKNOWN


@pytest.mark.parametrize("width", [1, 2, 4])
def test_integer_widths_are_limited_to_machine_access_sizes(width: int) -> None:
    value = IntegerType(width, RecoveredSignedness.UNKNOWN)

    assert value.kind is RecoveredTypeKind.INTEGER
    assert value.width_bytes == width


@pytest.mark.parametrize("width", [0, 3, 8])
def test_invalid_integer_width_is_rejected(width: int) -> None:
    with pytest.raises(ValueError, match="1, 2, or 4"):
        IntegerType(width, RecoveredSignedness.UNKNOWN)


def test_integer_signedness_is_explicit() -> None:
    assert IntegerType(4, RecoveredSignedness.SIGNED).signedness is RecoveredSignedness.SIGNED
    assert (
        IntegerType(4, RecoveredSignedness.UNSIGNED).signedness
        is RecoveredSignedness.UNSIGNED
    )


def test_pointer_component_cannot_be_empty() -> None:
    with pytest.raises(ValueError, match="component"):
        PointerType(component="")


def test_pointer_type_can_reference_a_recovered_struct_name() -> None:
    value = PointerType(pointee_name="struct_actor", component="arm9")

    assert value.kind is RecoveredTypeKind.POINTER
    assert value.pointee_name == "struct_actor"
    assert value.component == "arm9"


def test_struct_fields_are_canonical_by_offset() -> None:
    fields = (
        RecoveredStructField(
            0x18,
            4,
            "field_18",
            IntegerType(4, RecoveredSignedness.UNKNOWN),
            _source(0x02000018),
        ),
        RecoveredStructField(
            0x04,
            2,
            "field_04",
            IntegerType(2, RecoveredSignedness.UNKNOWN),
            _source(0x02000004),
        ),
    )

    struct = RecoveredStructType("struct_actor", fields)

    assert tuple(field.offset for field in struct.fields) == (0x04, 0x18)
    assert struct.minimum_size == 0x1C
    assert struct.kind is RecoveredTypeKind.STRUCT


def test_duplicate_struct_field_offset_is_rejected() -> None:
    first = RecoveredStructField(
        4,
        4,
        "field_04",
        IntegerType(4, RecoveredSignedness.UNKNOWN),
    )
    second = RecoveredStructField(
        4,
        2,
        "field_04_short",
        IntegerType(2, RecoveredSignedness.UNKNOWN),
    )

    with pytest.raises(ValueError, match="duplicate"):
        RecoveredStructType("struct_actor", (first, second))


def test_overlapping_struct_fields_are_rejected() -> None:
    first = RecoveredStructField(
        4,
        4,
        "field_04",
        IntegerType(4, RecoveredSignedness.UNKNOWN),
    )
    second = RecoveredStructField(
        6,
        2,
        "field_06",
        IntegerType(2, RecoveredSignedness.UNKNOWN),
    )

    with pytest.raises(ValueError, match="overlap"):
        RecoveredStructType("struct_actor", (first, second))


def test_empty_struct_and_field_names_are_rejected() -> None:
    with pytest.raises(ValueError, match="structure name"):
        RecoveredStructType("", ())

    with pytest.raises(ValueError, match="field name"):
        RecoveredStructField(
            0,
            4,
            "",
            IntegerType(4, RecoveredSignedness.UNKNOWN),
        )


def test_type_evidence_preserves_provenance() -> None:
    source = _source()
    evidence = TypeEvidence(
        TypeEvidenceKind.POINTER_DEREFERENCE,
        source,
        "read 4 bytes at +0x18",
    )

    assert evidence.source == source
    assert evidence.kind is TypeEvidenceKind.POINTER_DEREFERENCE
