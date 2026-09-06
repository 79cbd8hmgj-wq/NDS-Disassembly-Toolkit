from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.access_paths import (
    AccessPath,
    normalize_access_path,
)
from nds_disassembly_toolkit.analysis.decompiler.model import (
    BinaryOperator,
    ConstantExpression,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSABinaryExpression,
    SSAReferenceExpression,
    SSAStorage,
    SSAStorageKind,
    SSAValue,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x02001000


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _value(register: Register, version: int = 0) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=register),
        version,
        _source(),
    )


def _ref(value: SSAValue, address: int = BASE) -> SSAReferenceExpression:
    return SSAReferenceExpression(value.storage, value, _source(address))


def _constant(value: int, address: int = BASE) -> ConstantExpression:
    return ConstantExpression(value, _source(address))


def _binary(
    operator: BinaryOperator,
    left: object,
    right: object,
    address: int = BASE,
) -> SSABinaryExpression:
    return SSABinaryExpression(
        operator,
        left,  # type: ignore[arg-type]
        right,  # type: ignore[arg-type]
        _source(address),
    )


def test_base_plus_constant_normalizes_to_field_offset() -> None:
    base = _value(Register.R0)
    expression = _binary(
        BinaryOperator.ADD,
        _ref(base),
        _constant(0x18),
    )

    path = normalize_access_path(expression)

    assert path == AccessPath(base, 0x18, None, None, expression.source)


def test_nested_constant_adds_are_flattened() -> None:
    base = _value(Register.R0)
    expression = _binary(
        BinaryOperator.ADD,
        _binary(
            BinaryOperator.ADD,
            _ref(base),
            _constant(4),
        ),
        _constant(8),
    )

    path = normalize_access_path(expression)

    assert path is not None
    assert path.root == base
    assert path.byte_offset == 12
    assert path.index is None


def test_base_minus_constant_produces_negative_offset() -> None:
    base = _value(Register.R0)
    expression = _binary(
        BinaryOperator.SUBTRACT,
        _ref(base),
        _constant(4),
    )

    path = normalize_access_path(expression)

    assert path is not None
    assert path.root == base
    assert path.byte_offset == -4


def test_scaled_index_and_constant_offset_are_preserved() -> None:
    base = _value(Register.R0)
    index = _value(Register.R1)
    scaled = _binary(
        BinaryOperator.MULTIPLY,
        _ref(index),
        _constant(4),
    )
    expression = _binary(
        BinaryOperator.ADD,
        _binary(
            BinaryOperator.ADD,
            _ref(base),
            scaled,
        ),
        _constant(0x10),
    )

    path = normalize_access_path(expression)

    assert path is not None
    assert path.root == base
    assert path.index == index
    assert path.scale == 4
    assert path.byte_offset == 0x10


def test_subtracted_scaled_index_uses_negative_scale() -> None:
    base = _value(Register.R0)
    index = _value(Register.R1)
    scaled = _binary(
        BinaryOperator.MULTIPLY,
        _ref(index),
        _constant(2),
    )
    expression = _binary(
        BinaryOperator.SUBTRACT,
        _ref(base),
        scaled,
    )

    path = normalize_access_path(expression)

    assert path is not None
    assert path.root == base
    assert path.index == index
    assert path.scale == -2


def test_two_unscaled_ssa_terms_are_ambiguous() -> None:
    left = _value(Register.R0)
    right = _value(Register.R1)
    expression = _binary(
        BinaryOperator.ADD,
        _ref(left),
        _ref(right),
    )

    assert normalize_access_path(expression) is None


def test_two_scaled_index_terms_are_ambiguous() -> None:
    base = _value(Register.R0)
    first = _value(Register.R1)
    second = _value(Register.R2)
    expression = _binary(
        BinaryOperator.ADD,
        _ref(base),
        _binary(
            BinaryOperator.ADD,
            _binary(
                BinaryOperator.MULTIPLY,
                _ref(first),
                _constant(2),
            ),
            _binary(
                BinaryOperator.MULTIPLY,
                _ref(second),
                _constant(4),
            ),
        ),
    )

    assert normalize_access_path(expression) is None


def test_constant_address_has_no_ssa_root() -> None:
    assert normalize_access_path(_constant(0x02004000)) is None


def test_exact_ssa_reference_retains_value_identity() -> None:
    base = _value(Register.R3, version=7)

    path = normalize_access_path(_ref(base))

    assert path is not None
    assert path.root == base
    assert path.byte_offset == 0


def test_undefined_ssa_reference_is_unresolved() -> None:
    storage = SSAStorage(SSAStorageKind.REGISTER, register=Register.R0)
    expression = SSAReferenceExpression(storage, None, _source())

    assert normalize_access_path(expression) is None
