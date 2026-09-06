from __future__ import annotations

from dataclasses import dataclass

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    BinaryOperator,
    ConstantExpression,
    UnaryOperator,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    PhiInput,
    PhiNode,
    SSAAssignmentStatement,
    SSABinaryExpression,
    SSABlock,
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
    SSAStatement,
    SSAStorage,
    SSAUnaryExpression,
    SSAValue,
    build_def_use_index,
)

_MASK32 = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class SSASimplificationResult:
    function: SSAFunction
    converged: bool
    iterations: int


def _u32(value: int) -> int:
    return value & _MASK32


def _s32(value: int) -> int:
    value &= _MASK32
    return value - (1 << 32) if value & 0x80000000 else value


def _is_pure_expression(expression: SSAExpression) -> bool:
    if isinstance(expression, ConstantExpression | AddressExpression | SSAReferenceExpression):
        return True
    if isinstance(expression, SSAUnaryExpression):
        return _is_pure_expression(expression.operand)
    if isinstance(expression, SSABinaryExpression | SSACompareExpression):
        return _is_pure_expression(expression.left) and _is_pure_expression(
            expression.right
        )
    return False


def _fold_binary(operator: BinaryOperator, left: int, right: int) -> int | None:
    if operator is BinaryOperator.ADD:
        return _u32(left + right)
    if operator is BinaryOperator.SUBTRACT:
        return _u32(left - right)
    if operator is BinaryOperator.MULTIPLY:
        return _u32(left * right)
    if operator is BinaryOperator.BITWISE_AND:
        return left & right
    if operator is BinaryOperator.BITWISE_OR:
        return left | right
    if operator is BinaryOperator.BITWISE_XOR:
        return left ^ right
    if not 0 <= right < 32:
        return None
    if operator is BinaryOperator.SHIFT_LEFT:
        return _u32(left << right)
    if operator is BinaryOperator.SHIFT_RIGHT_LOGICAL:
        return (left & _MASK32) >> right
    if operator is BinaryOperator.SHIFT_RIGHT_ARITHMETIC:
        return _u32(_s32(left) >> right)
    return None


def _resolve_replacement(
    value: SSAValue,
    replacements: dict[SSAValue, SSAExpression],
    visiting: frozenset[SSAValue] = frozenset(),
) -> SSAExpression | None:
    replacement = replacements.get(value)
    if replacement is None or value in visiting:
        return replacement
    if isinstance(replacement, SSAReferenceExpression) and replacement.value is not None:
        nested = _resolve_replacement(
            replacement.value,
            replacements,
            visiting | {value},
        )
        return nested if nested is not None else replacement
    return replacement


def _simplify_expression(
    expression: SSAExpression,
    replacements: dict[SSAValue, SSAExpression],
) -> SSAExpression:
    if isinstance(expression, ConstantExpression | AddressExpression):
        return expression
    if isinstance(expression, SSAReferenceExpression):
        if expression.value is None:
            return expression
        replacement = _resolve_replacement(expression.value, replacements)
        if replacement is None:
            return expression
        return _simplify_expression(replacement, replacements)
    if isinstance(expression, SSAUnaryExpression):
        operand = _simplify_expression(expression.operand, replacements)
        if isinstance(operand, ConstantExpression):
            if expression.operator is UnaryOperator.BITWISE_NOT:
                return ConstantExpression(_u32(~operand.value), expression.source)
            if expression.operator is UnaryOperator.NEGATE:
                return ConstantExpression(_u32(-operand.value), expression.source)
        return SSAUnaryExpression(expression.operator, operand, expression.source)
    if isinstance(expression, SSABinaryExpression):
        left = _simplify_expression(expression.left, replacements)
        right = _simplify_expression(expression.right, replacements)

        if isinstance(left, ConstantExpression) and isinstance(right, ConstantExpression):
            folded = _fold_binary(expression.operator, left.value, right.value)
            if folded is not None:
                return ConstantExpression(folded, expression.source)

        if isinstance(right, ConstantExpression):
            if expression.operator is BinaryOperator.ADD and right.value == 0:
                return left
            if expression.operator is BinaryOperator.SUBTRACT and right.value == 0:
                return left
            if expression.operator is BinaryOperator.BITWISE_OR and right.value == 0:
                return left
            if expression.operator is BinaryOperator.BITWISE_XOR and right.value == 0:
                return left
            if expression.operator is BinaryOperator.BITWISE_AND and right.value == _MASK32:
                return left
            if (
                expression.operator
                in {
                    BinaryOperator.SHIFT_LEFT,
                    BinaryOperator.SHIFT_RIGHT_LOGICAL,
                    BinaryOperator.SHIFT_RIGHT_ARITHMETIC,
                }
                and right.value == 0
            ):
                return left
            if (
                expression.operator is BinaryOperator.ADD
                and isinstance(left, SSABinaryExpression)
                and left.operator is BinaryOperator.ADD
                and isinstance(left.right, ConstantExpression)
            ):
                return SSABinaryExpression(
                    BinaryOperator.ADD,
                    left.left,
                    ConstantExpression(
                        _u32(left.right.value + right.value),
                        expression.source,
                    ),
                    expression.source,
                )

        return SSABinaryExpression(
            expression.operator,
            left,
            right,
            expression.source,
        )
    if isinstance(expression, SSACompareExpression):
        return SSACompareExpression(
            expression.condition,
            _simplify_expression(expression.left, replacements),
            _simplify_expression(expression.right, replacements),
            expression.source,
        )
    if isinstance(expression, SSAMemoryReadExpression):
        return SSAMemoryReadExpression(
            _simplify_expression(expression.address, replacements),
            expression.width,
            expression.source,
        )
    if isinstance(expression, SSACallExpression):
        return SSACallExpression(
            expression.name,
            expression.target_address,
            expression.target_instruction_set,
            expression.target_component,
            tuple(
                _simplify_expression(argument, replacements)
                for argument in expression.arguments
            ),
            expression.source,
        )
    return expression


def _rewrite_statement(
    statement: SSAStatement,
    replacements: dict[SSAValue, SSAExpression],
) -> SSAStatement:
    if isinstance(statement, SSAAssignmentStatement):
        return SSAAssignmentStatement(
            statement.target,
            _simplify_expression(statement.value, replacements),
            statement.source,
        )
    if isinstance(statement, SSAMemoryWriteStatement):
        return SSAMemoryWriteStatement(
            _simplify_expression(statement.address, replacements),
            _simplify_expression(statement.value, replacements),
            statement.width,
            statement.source,
        )
    if isinstance(statement, SSACallStatement):
        call = _simplify_expression(statement.call, replacements)
        if not isinstance(call, SSACallExpression):
            raise TypeError("call statement simplification lost its call expression")
        return SSACallStatement(call, statement.source)
    if isinstance(statement, SSAReturnStatement):
        return SSAReturnStatement(
            (
                None
                if statement.value is None
                else _simplify_expression(statement.value, replacements)
            ),
            statement.source,
        )
    if isinstance(statement, SSABranchStatement):
        return SSABranchStatement(
            (
                None
                if statement.condition is None
                else _simplify_expression(statement.condition, replacements)
            ),
            statement.target_address,
            statement.target_instruction_set,
            statement.source,
        )
    return statement


def _replacement_phi_value(
    value: SSAValue | None,
    replacements: dict[SSAValue, SSAExpression],
    expected_storage: SSAStorage,
) -> SSAValue | None:
    if value is None:
        return None
    replacement = _resolve_replacement(value, replacements)
    if (
        isinstance(replacement, SSAReferenceExpression)
        and replacement.value is not None
        and replacement.value.storage == expected_storage
    ):
        return replacement.value
    return value


def _rewrite_function(
    function: SSAFunction,
    replacements: dict[SSAValue, SSAExpression],
    removed_assignments: frozenset[SSAValue] = frozenset(),
    removed_phis: frozenset[SSAValue] = frozenset(),
) -> SSAFunction:
    blocks: list[SSABlock] = []
    for block in function.blocks:
        phis = tuple(
            PhiNode(
                phi.output,
                tuple(
                    PhiInput(
                        item.predecessor_address,
                        _replacement_phi_value(
                            item.value,
                            replacements,
                            phi.output.storage,
                        ),
                    )
                    for item in phi.inputs
                ),
            )
            for phi in block.phis
            if phi.output not in removed_phis
        )
        statements = tuple(
            _rewrite_statement(statement, replacements)
            for statement in block.statements
            if not (
                isinstance(statement, SSAAssignmentStatement)
                and statement.target in removed_assignments
            )
        )
        blocks.append(
            SSABlock(
                block.address,
                block.instruction_set,
                phis,
                statements,
                block.edges,
            )
        )
    return SSAFunction(
        component=function.component,
        address=function.address,
        instruction_set=function.instruction_set,
        name=function.name,
        parameters=function.parameters,
        locals=function.locals,
        blocks=tuple(blocks),
        entry_definitions=function.entry_definitions,
        warnings=function.warnings,
    )


def _expression_simplification_pass(function: SSAFunction) -> SSAFunction:
    return _rewrite_function(function, {})


def _propagation_pass(function: SSAFunction) -> SSAFunction:
    index = build_def_use_index(function)
    replacements: dict[SSAValue, SSAExpression] = {}
    removed_assignments: set[SSAValue] = set()

    for block in function.blocks:
        for statement in block.statements:
            if not isinstance(statement, SSAAssignmentStatement):
                continue
            value = statement.value
            if not _is_pure_expression(value):
                continue
            uses = index.uses(statement.target)
            has_phi_use = any(
                use.phi_predecessor_address is not None
                for use in uses
            )
            is_copy = (
                isinstance(value, SSAReferenceExpression)
                and value.value is not None
            )
            is_unconditional_value = isinstance(
                value,
                ConstantExpression | AddressExpression,
            )
            if has_phi_use and not is_copy:
                continue
            if is_copy or is_unconditional_value or len(uses) <= 1:
                replacements[statement.target] = value
                if not has_phi_use:
                    removed_assignments.add(statement.target)

    removed_phis: set[SSAValue] = set()
    for block in function.blocks:
        for phi in block.phis:
            resolved: list[SSAValue | None] = []
            for item in phi.inputs:
                if item.value is None:
                    resolved.append(None)
                    continue
                replacement = _resolve_replacement(item.value, replacements)
                if (
                    isinstance(replacement, SSAReferenceExpression)
                    and replacement.value is not None
                ):
                    resolved.append(replacement.value)
                else:
                    resolved.append(item.value)
            if not resolved or any(value is None for value in resolved):
                continue
            first = resolved[0]
            assert first is not None
            if all(value == first for value in resolved[1:]):
                replacements[phi.output] = SSAReferenceExpression(
                    first.storage,
                    first,
                    phi.output.source,
                )
                removed_phis.add(phi.output)

    if not replacements and not removed_phis:
        return function

    # Assignments feeding a PHI are retained until the PHI has been removed.
    # The following dead-definition pass then removes them if no other use remains.
    return _rewrite_function(
        function,
        replacements,
        frozenset(removed_assignments),
        frozenset(removed_phis),
    )


def _phi_pass(function: SSAFunction) -> SSAFunction:
    replacements: dict[SSAValue, SSAExpression] = {}
    removed: set[SSAValue] = set()

    for block in function.blocks:
        for phi in block.phis:
            incoming = [item.value for item in phi.inputs]
            if not incoming or any(value is None for value in incoming):
                continue
            first = incoming[0]
            assert first is not None
            if all(value == first for value in incoming[1:]):
                replacements[phi.output] = SSAReferenceExpression(
                    first.storage,
                    first,
                    phi.output.source,
                )
                removed.add(phi.output)

    if not replacements:
        return function
    return _rewrite_function(
        function,
        replacements,
        removed_phis=frozenset(removed),
    )


def _dead_assignment_pass(function: SSAFunction) -> SSAFunction:
    index = build_def_use_index(function)
    removed: set[SSAValue] = set()
    for block in function.blocks:
        for statement in block.statements:
            if (
                isinstance(statement, SSAAssignmentStatement)
                and not index.uses(statement.target)
                and _is_pure_expression(statement.value)
            ):
                removed.add(statement.target)
    if not removed:
        return function
    return _rewrite_function(
        function,
        {},
        removed_assignments=frozenset(removed),
    )


def _simplify_once(function: SSAFunction) -> SSAFunction:
    result = _expression_simplification_pass(function)
    result = _propagation_pass(result)
    result = _phi_pass(result)
    result = _dead_assignment_pass(result)
    result = _expression_simplification_pass(result)
    return result


def simplify_ssa_function(
    function: SSAFunction,
    *,
    iteration_cap: int = 32,
) -> SSASimplificationResult:
    if iteration_cap <= 0:
        raise ValueError("SSA simplification iteration cap must be positive")

    current = function
    for iteration in range(1, iteration_cap + 1):
        updated = _simplify_once(current)
        if updated == current:
            return SSASimplificationResult(
                function=current,
                converged=True,
                iterations=iteration,
            )
        current = updated

    warning = (
        f"SSA simplification did not converge within {iteration_cap} iterations"
    )
    if warning not in current.warnings:
        current = SSAFunction(
            component=current.component,
            address=current.address,
            instruction_set=current.instruction_set,
            name=current.name,
            parameters=current.parameters,
            locals=current.locals,
            blocks=current.blocks,
            entry_definitions=current.entry_definitions,
            warnings=(*current.warnings, warning),
        )
    return SSASimplificationResult(
        function=current,
        converged=False,
        iterations=iteration_cap,
    )
