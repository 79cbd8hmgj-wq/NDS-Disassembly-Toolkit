from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.access_paths import (
    AccessPath,
    FieldAccessKind,
    collect_field_accesses,
    normalize_access_path,
)
from nds_disassembly_toolkit.analysis.decompiler.model import (
    BinaryOperator,
    ConstantExpression,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAAssignmentStatement,
    SSABinaryExpression,
    SSABlock,
    SSAFunction,
    SSAMemoryReadExpression,
    SSAMemoryWriteStatement,
    SSAReferenceExpression,
    SSAReturnStatement,
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



def _temporary(name: str, version: int = 0) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.TEMPORARY, temporary_name=name),
        version,
        _source(),
    )


def _function_with_statements(
    statements: tuple[object, ...],
) -> SSAFunction:
    return SSAFunction(
        component="arm9",
        address=BASE,
        instruction_set=InstructionSet.ARM,
        name="field_accesses",
        parameters=(),
        locals=(),
        blocks=(
            SSABlock(
                BASE,
                InstructionSet.ARM,
                (),
                statements,  # type: ignore[arg-type]
                (),
            ),
        ),
    )


def test_collects_memory_read_field_evidence() -> None:
    base = _value(Register.R0)
    address = _binary(
        BinaryOperator.ADD,
        _ref(base),
        _constant(0x18),
    )
    source = _source(BASE + 4)
    read = SSAMemoryReadExpression(address, 4, source)
    function = _function_with_statements(
        (
            SSAAssignmentStatement(
                _temporary("tmp_read"),
                read,
                source,
            ),
        )
    )

    evidence = collect_field_accesses(function)

    assert len(evidence) == 1
    item = evidence[0]
    assert item.kind is FieldAccessKind.READ
    assert item.root == base
    assert item.byte_offset == 0x18
    assert item.width_bytes == 4
    assert item.index is None
    assert item.scale is None
    assert item.source == source
    assert item.is_direct_field is True


def test_collects_memory_write_field_evidence() -> None:
    base = _value(Register.R0)
    address = _binary(
        BinaryOperator.ADD,
        _ref(base),
        _constant(0x0C),
    )
    source = _source(BASE + 8)
    function = _function_with_statements(
        (
            SSAMemoryWriteStatement(
                address,
                _constant(7),
                2,
                source,
            ),
        )
    )

    evidence = collect_field_accesses(function)

    assert len(evidence) == 1
    item = evidence[0]
    assert item.kind is FieldAccessKind.WRITE
    assert item.root == base
    assert item.byte_offset == 0x0C
    assert item.width_bytes == 2
    assert item.source == source


def test_collects_memory_access_widths_exactly() -> None:
    base = _value(Register.R0)
    statements: list[object] = []
    for index, width in enumerate((1, 2, 4)):
        source = _source(BASE + index * 4)
        address = _binary(
            BinaryOperator.ADD,
            _ref(base),
            _constant(index * 4),
            BASE + index * 4,
        )
        statements.append(
            SSAAssignmentStatement(
                _temporary(f"tmp_{index}"),
                SSAMemoryReadExpression(address, width, source),
                source,
            )
        )

    evidence = collect_field_accesses(
        _function_with_statements(tuple(statements))
    )

    assert tuple(item.width_bytes for item in evidence) == (1, 2, 4)


def test_negative_offset_is_not_field_evidence() -> None:
    base = _value(Register.R0)
    address = _binary(
        BinaryOperator.SUBTRACT,
        _ref(base),
        _constant(4),
    )
    source = _source()
    function = _function_with_statements(
        (
            SSAAssignmentStatement(
                _temporary("tmp_negative"),
                SSAMemoryReadExpression(address, 4, source),
                source,
            ),
        )
    )

    assert collect_field_accesses(function) == ()


def test_scaled_index_access_is_recorded_but_not_direct_field() -> None:
    base = _value(Register.R0)
    index = _value(Register.R1)
    address = _binary(
        BinaryOperator.ADD,
        _binary(
            BinaryOperator.ADD,
            _ref(base),
            _binary(
                BinaryOperator.MULTIPLY,
                _ref(index),
                _constant(4),
            ),
        ),
        _constant(0x10),
    )
    source = _source(BASE + 12)
    function = _function_with_statements(
        (
            SSAReturnStatement(
                SSAMemoryReadExpression(address, 4, source),
                source,
            ),
        )
    )

    evidence = collect_field_accesses(function)

    assert len(evidence) == 1
    item = evidence[0]
    assert item.root == base
    assert item.index == index
    assert item.scale == 4
    assert item.byte_offset == 0x10
    assert item.is_direct_field is False


def test_unresolved_memory_address_is_not_guessed() -> None:
    left = _value(Register.R0)
    right = _value(Register.R1)
    address = _binary(
        BinaryOperator.ADD,
        _ref(left),
        _ref(right),
    )
    source = _source()
    function = _function_with_statements(
        (
            SSAReturnStatement(
                SSAMemoryReadExpression(address, 4, source),
                source,
            ),
        )
    )

    assert collect_field_accesses(function) == ()


def test_field_evidence_order_is_deterministic_by_source() -> None:
    base = _value(Register.R0)
    late_source = _source(BASE + 0x20)
    early_source = _source(BASE + 0x04)
    late_address = _binary(
        BinaryOperator.ADD,
        _ref(base),
        _constant(8),
        BASE + 0x20,
    )
    early_address = _binary(
        BinaryOperator.ADD,
        _ref(base),
        _constant(4),
        BASE + 0x04,
    )
    function = _function_with_statements(
        (
            SSAMemoryWriteStatement(
                late_address,
                _constant(1),
                4,
                late_source,
            ),
            SSAMemoryWriteStatement(
                early_address,
                _constant(2),
                4,
                early_source,
            ),
        )
    )

    evidence = collect_field_accesses(function)

    assert tuple(item.source[0].address for item in evidence) == (
        BASE + 0x04,
        BASE + 0x20,
    )
