from __future__ import annotations

from dataclasses import dataclass

from nds_disassembly_toolkit.analysis.decompiler.model import (
    BinaryOperator,
    ConstantExpression,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSABinaryExpression,
    SSAExpression,
    SSAReferenceExpression,
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
