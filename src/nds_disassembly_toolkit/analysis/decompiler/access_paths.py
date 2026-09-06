from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from nds_disassembly_toolkit.analysis.decompiler.model import (
    BinaryOperator,
    ConstantExpression,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAAssignmentStatement,
    SSABinaryExpression,
    SSABranchStatement,
    SSACallExpression,
    SSACallStatement,
    SSACompareExpression,
    SSAExpression,
    SSAFunction,
    SSAMemoryReadExpression,
    SSAMemoryWriteStatement,
    SSAReferenceExpression,
    SSAReturnStatement,
    SSAUnaryExpression,
    SSAValue,
)


@dataclass(frozen=True, slots=True)
class AccessPath:
    root: SSAValue
    byte_offset: int
    index: SSAValue | None = None
    scale: int | None = None
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class _LinearForm:
    constant: int
    terms: tuple[tuple[SSAValue, int], ...]


def _merge_terms(
    left: tuple[tuple[SSAValue, int], ...],
    right: tuple[tuple[SSAValue, int], ...],
    *,
    right_sign: int,
) -> tuple[tuple[SSAValue, int], ...]:
    coefficients: dict[SSAValue, int] = {}
    for value, coefficient in left:
        coefficients[value] = coefficients.get(value, 0) + coefficient
    for value, coefficient in right:
        coefficients[value] = coefficients.get(value, 0) + right_sign * coefficient
    return tuple(
        sorted(
            (
                (value, coefficient)
                for value, coefficient in coefficients.items()
                if coefficient != 0
            ),
            key=lambda item: (
                item[0].storage.kind.value,
                item[0].storage.register.value
                if item[0].storage.register is not None
                else "",
                item[0].storage.stack_offset
                if item[0].storage.stack_offset is not None
                else 0,
                item[0].storage.temporary_name or "",
                item[0].version,
            ),
        )
    )


def _scaled_reference(
    expression: SSAExpression,
) -> tuple[SSAValue, int] | None:
    if not isinstance(expression, SSABinaryExpression):
        return None
    if expression.operator is not BinaryOperator.MULTIPLY:
        return None

    if isinstance(expression.left, SSAReferenceExpression) and isinstance(
        expression.right,
        ConstantExpression,
    ):
        if expression.left.value is None:
            return None
        return expression.left.value, expression.right.value

    if isinstance(expression.right, SSAReferenceExpression) and isinstance(
        expression.left,
        ConstantExpression,
    ):
        if expression.right.value is None:
            return None
        return expression.right.value, expression.left.value

    return None


def _linearize(expression: SSAExpression) -> _LinearForm | None:
    if isinstance(expression, ConstantExpression):
        return _LinearForm(expression.value, ())

    if isinstance(expression, SSAReferenceExpression):
        if expression.value is None:
            return None
        return _LinearForm(0, ((expression.value, 1),))

    scaled = _scaled_reference(expression)
    if scaled is not None:
        value, coefficient = scaled
        return _LinearForm(0, ((value, coefficient),))

    if not isinstance(expression, SSABinaryExpression):
        return None
    if expression.operator not in {
        BinaryOperator.ADD,
        BinaryOperator.SUBTRACT,
    }:
        return None

    left = _linearize(expression.left)
    right = _linearize(expression.right)
    if left is None or right is None:
        return None

    sign = 1 if expression.operator is BinaryOperator.ADD else -1
    return _LinearForm(
        left.constant + sign * right.constant,
        _merge_terms(left.terms, right.terms, right_sign=sign),
    )


def normalize_access_path(expression: SSAExpression) -> AccessPath | None:
    linear = _linearize(expression)
    if linear is None:
        return None

    roots = [
        (value, coefficient)
        for value, coefficient in linear.terms
        if coefficient == 1
    ]
    scaled = [
        (value, coefficient)
        for value, coefficient in linear.terms
        if coefficient != 1
    ]

    # Without independent pointer evidence there is no sound way to decide
    # which of two equally unscaled SSA values is the object base.
    if len(roots) != 1 or len(scaled) > 1:
        return None

    root, _ = roots[0]
    index: SSAValue | None = None
    scale: int | None = None
    if scaled:
        index, scale = scaled[0]
        if scale == 0:
            return None

    return AccessPath(
        root=root,
        byte_offset=linear.constant,
        index=index,
        scale=scale,
        source=expression.source,
    )



class FieldAccessKind(StrEnum):
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True, slots=True)
class FieldAccessEvidence:
    kind: FieldAccessKind
    root: SSAValue
    byte_offset: int
    width_bytes: int
    index: SSAValue | None = None
    scale: int | None = None
    source: tuple[SourceRef, ...] = ()

    @property
    def is_direct_field(self) -> bool:
        return self.index is None


def _value_sort_key(value: SSAValue | None) -> tuple[object, ...]:
    if value is None:
        return ("", "", 0, "", -1)
    storage = value.storage
    return (
        storage.kind.value,
        storage.register.value if storage.register is not None else "",
        storage.stack_offset if storage.stack_offset is not None else 0,
        storage.temporary_name or "",
        value.version,
    )


def _evidence_sort_key(
    evidence: FieldAccessEvidence,
) -> tuple[object, ...]:
    source_key = tuple(
        (item.address, item.instruction_set.value)
        for item in evidence.source
    )
    return (
        source_key,
        evidence.kind.value,
        _value_sort_key(evidence.root),
        evidence.byte_offset,
        evidence.width_bytes,
        _value_sort_key(evidence.index),
        evidence.scale if evidence.scale is not None else 0,
    )


def _record_access(
    output: list[FieldAccessEvidence],
    *,
    kind: FieldAccessKind,
    address: SSAExpression,
    width: int,
    source: tuple[SourceRef, ...],
) -> None:
    path = normalize_access_path(address)
    if path is None or path.byte_offset < 0:
        return
    output.append(
        FieldAccessEvidence(
            kind=kind,
            root=path.root,
            byte_offset=path.byte_offset,
            width_bytes=width,
            index=path.index,
            scale=path.scale,
            source=source,
        )
    )


def _collect_expression(
    expression: SSAExpression,
    output: list[FieldAccessEvidence],
) -> None:
    if isinstance(expression, SSAMemoryReadExpression):
        _record_access(
            output,
            kind=FieldAccessKind.READ,
            address=expression.address,
            width=expression.width,
            source=expression.source,
        )
        _collect_expression(expression.address, output)
        return

    if isinstance(expression, SSAUnaryExpression):
        _collect_expression(expression.operand, output)
        return

    if isinstance(expression, SSABinaryExpression | SSACompareExpression):
        _collect_expression(expression.left, output)
        _collect_expression(expression.right, output)
        return

    if isinstance(expression, SSACallExpression):
        for argument in expression.arguments:
            _collect_expression(argument, output)


def collect_field_accesses(
    function: SSAFunction,
) -> tuple[FieldAccessEvidence, ...]:
    output: list[FieldAccessEvidence] = []

    for block in sorted(function.blocks, key=lambda candidate: candidate.address):
        for statement in block.statements:
            if isinstance(statement, SSAAssignmentStatement):
                _collect_expression(statement.value, output)
                continue

            if isinstance(statement, SSAMemoryWriteStatement):
                _record_access(
                    output,
                    kind=FieldAccessKind.WRITE,
                    address=statement.address,
                    width=statement.width,
                    source=statement.source,
                )
                _collect_expression(statement.address, output)
                _collect_expression(statement.value, output)
                continue

            if isinstance(statement, SSACallStatement):
                _collect_expression(statement.call, output)
                continue

            if isinstance(statement, SSAReturnStatement):
                if statement.value is not None:
                    _collect_expression(statement.value, output)
                continue

            if (
                isinstance(statement, SSABranchStatement)
                and statement.condition is not None
            ):
                _collect_expression(statement.condition, output)

    return tuple(sorted(output, key=_evidence_sort_key))
