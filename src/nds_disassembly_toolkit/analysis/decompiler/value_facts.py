from __future__ import annotations

from dataclasses import dataclass

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    BinaryOperator,
    ConstantExpression,
    SourceRef,
    UnaryOperator,
    UnknownExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAAssignmentStatement,
    SSABinaryExpression,
    SSACallExpression,
    SSACompareExpression,
    SSAExpression,
    SSAFunction,
    SSAMemoryReadExpression,
    SSAReferenceExpression,
    SSAUnaryExpression,
    SSAValue,
)

_MASK32 = 0xFFFFFFFF
_SIGN32 = 0x80000000
_S32_MIN = -(1 << 31)
_S32_MAX = (1 << 31) - 1


def _u32(value: int) -> int:
    return value & _MASK32


def _s32(value: int) -> int:
    value &= _MASK32
    return value - (1 << 32) if value & _SIGN32 else value


def _merge_sources(*groups: tuple[SourceRef, ...]) -> tuple[SourceRef, ...]:
    unique = {
        (source.address, source.instruction_set.value): source
        for group in groups
        for source in group
    }
    return tuple(
        unique[key]
        for key in sorted(unique)
    )


@dataclass(frozen=True, slots=True)
class ValueFacts:
    known_zero_bits: int = 0
    known_one_bits: int = 0
    address: int | None = None
    component: str | None = None
    provenance: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        if self.known_zero_bits & ~_MASK32:
            raise ValueError("known-zero bits must fit in 32 bits")
        if self.known_one_bits & ~_MASK32:
            raise ValueError("known-one bits must fit in 32 bits")
        if self.known_zero_bits & self.known_one_bits:
            raise ValueError("known-zero and known-one bits cannot overlap")
        if self.address is not None and not 0 <= self.address <= _MASK32:
            raise ValueError("address fact must fit in 32 bits")
        if self.address is None and self.component is not None:
            raise ValueError("address component requires a proven address")
        if self.component == "":
            raise ValueError("address component cannot be empty")

    @classmethod
    def unknown(cls, provenance: tuple[SourceRef, ...] = ()) -> ValueFacts:
        return cls(provenance=provenance)

    @classmethod
    def constant(
        cls,
        value: int,
        provenance: tuple[SourceRef, ...] = (),
    ) -> ValueFacts:
        normalized = _u32(value)
        return cls(
            known_zero_bits=(~normalized) & _MASK32,
            known_one_bits=normalized,
            provenance=provenance,
        )

    @classmethod
    def proven_address(
        cls,
        address: int,
        component: str | None,
        provenance: tuple[SourceRef, ...] = (),
    ) -> ValueFacts:
        normalized = _u32(address)
        return cls(
            known_zero_bits=(~normalized) & _MASK32,
            known_one_bits=normalized,
            address=normalized,
            component=component,
            provenance=provenance,
        )

    @property
    def exact_value(self) -> int | None:
        if (self.known_zero_bits | self.known_one_bits) == _MASK32:
            return self.known_one_bits
        return None

    @property
    def unsigned_min(self) -> int:
        return self.known_one_bits

    @property
    def unsigned_max(self) -> int:
        return (~self.known_zero_bits) & _MASK32

    @property
    def signed_min(self) -> int:
        if self.known_one_bits & _SIGN32:
            return _s32(self.unsigned_min)
        if self.known_zero_bits & _SIGN32:
            return self.unsigned_min
        return _S32_MIN

    @property
    def signed_max(self) -> int:
        if self.known_one_bits & _SIGN32:
            return _s32(self.unsigned_max)
        if self.known_zero_bits & _SIGN32:
            return self.unsigned_max
        return _S32_MAX

    @property
    def is_nonzero(self) -> bool:
        return self.known_one_bits != 0

    @property
    def is_address(self) -> bool:
        return self.address is not None

    @property
    def alignment(self) -> int:
        count = 0
        bits = self.known_zero_bits
        while count < 31 and bits & (1 << count):
            count += 1
        return 1 << count


@dataclass(frozen=True, slots=True)
class ValueFactsAnalysis:
    records: tuple[tuple[SSAValue, ValueFacts], ...]
    converged: bool
    iterations: int

    def facts_for(self, value: SSAValue) -> ValueFacts:
        for candidate, facts in self.records:
            if candidate == value:
                return facts
        return ValueFacts.unknown(value.source)


def _with_provenance(facts: ValueFacts, source: tuple[SourceRef, ...]) -> ValueFacts:
    return ValueFacts(
        known_zero_bits=facts.known_zero_bits,
        known_one_bits=facts.known_one_bits,
        address=facts.address,
        component=facts.component,
        provenance=_merge_sources(facts.provenance, source),
    )


def _join_facts(facts: tuple[ValueFacts, ...]) -> ValueFacts:
    if not facts:
        return ValueFacts.unknown()

    known_zero = _MASK32
    known_one = _MASK32
    for item in facts:
        known_zero &= item.known_zero_bits
        known_one &= item.known_one_bits

    all_addresses = all(item.address is not None for item in facts)
    addresses = {item.address for item in facts if item.address is not None}
    address = (
        next(iter(addresses))
        if all_addresses and len(addresses) == 1
        else None
    )

    component: str | None = None
    if address is not None:
        components = {item.component for item in facts}
        if len(components) == 1:
            component = next(iter(components))

    return ValueFacts(
        known_zero_bits=known_zero,
        known_one_bits=known_one,
        address=address,
        component=component,
        provenance=_merge_sources(*(item.provenance for item in facts)),
    )


def _exact_binary(
    operator: BinaryOperator,
    left: int,
    right: int,
) -> int | None:
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


def _shift_left(value: ValueFacts, amount: int) -> ValueFacts:
    if not 0 <= amount < 32:
        return ValueFacts.unknown(value.provenance)
    inserted_zero = (1 << amount) - 1 if amount else 0
    return ValueFacts(
        known_zero_bits=((value.known_zero_bits << amount) | inserted_zero) & _MASK32,
        known_one_bits=(value.known_one_bits << amount) & _MASK32,
        provenance=value.provenance,
    )


def _shift_right_logical(value: ValueFacts, amount: int) -> ValueFacts:
    if not 0 <= amount < 32:
        return ValueFacts.unknown(value.provenance)
    inserted_zero = (
        (_MASK32 << (32 - amount)) & _MASK32
        if amount
        else 0
    )
    return ValueFacts(
        known_zero_bits=(value.known_zero_bits >> amount) | inserted_zero,
        known_one_bits=value.known_one_bits >> amount,
        provenance=value.provenance,
    )


def _shift_right_arithmetic(value: ValueFacts, amount: int) -> ValueFacts:
    if not 0 <= amount < 32:
        return ValueFacts.unknown(value.provenance)
    high_mask = (
        (_MASK32 << (32 - amount)) & _MASK32
        if amount
        else 0
    )
    known_zero = value.known_zero_bits >> amount
    known_one = value.known_one_bits >> amount
    if value.known_zero_bits & _SIGN32:
        known_zero |= high_mask
    elif value.known_one_bits & _SIGN32:
        known_one |= high_mask
    return ValueFacts(
        known_zero_bits=known_zero,
        known_one_bits=known_one,
        provenance=value.provenance,
    )


def _binary_facts(
    expression: SSABinaryExpression,
    facts_by_value: dict[SSAValue, ValueFacts],
) -> ValueFacts:
    left = _expression_facts(expression.left, facts_by_value)
    right = _expression_facts(expression.right, facts_by_value)
    provenance = _merge_sources(left.provenance, right.provenance, expression.source)

    left_exact = left.exact_value
    right_exact = right.exact_value
    if left_exact is not None and right_exact is not None:
        exact = _exact_binary(expression.operator, left_exact, right_exact)
        if exact is not None:
            return ValueFacts.constant(exact, provenance)

    if expression.operator is BinaryOperator.BITWISE_AND:
        return ValueFacts(
            known_zero_bits=left.known_zero_bits | right.known_zero_bits,
            known_one_bits=left.known_one_bits & right.known_one_bits,
            provenance=provenance,
        )
    if expression.operator is BinaryOperator.BITWISE_OR:
        return ValueFacts(
            known_zero_bits=left.known_zero_bits & right.known_zero_bits,
            known_one_bits=left.known_one_bits | right.known_one_bits,
            provenance=provenance,
        )
    if expression.operator is BinaryOperator.BITWISE_XOR:
        return ValueFacts(
            known_zero_bits=(
                (left.known_zero_bits & right.known_zero_bits)
                | (left.known_one_bits & right.known_one_bits)
            ),
            known_one_bits=(
                (left.known_zero_bits & right.known_one_bits)
                | (left.known_one_bits & right.known_zero_bits)
            ),
            provenance=provenance,
        )

    if right_exact is not None:
        if expression.operator is BinaryOperator.SHIFT_LEFT:
            return _with_provenance(_shift_left(left, right_exact), expression.source)
        if expression.operator is BinaryOperator.SHIFT_RIGHT_LOGICAL:
            return _with_provenance(
                _shift_right_logical(left, right_exact),
                expression.source,
            )
        if expression.operator is BinaryOperator.SHIFT_RIGHT_ARITHMETIC:
            return _with_provenance(
                _shift_right_arithmetic(left, right_exact),
                expression.source,
            )

    return ValueFacts.unknown(provenance)


def _expression_facts(
    expression: SSAExpression,
    facts_by_value: dict[SSAValue, ValueFacts],
) -> ValueFacts:
    if isinstance(expression, ConstantExpression):
        return ValueFacts.constant(expression.value, expression.source)
    if isinstance(expression, AddressExpression):
        return ValueFacts.proven_address(
            expression.address,
            expression.component,
            expression.source,
        )
    if isinstance(expression, UnknownExpression):
        return ValueFacts.unknown(expression.source)
    if isinstance(expression, SSAReferenceExpression):
        if expression.value is None:
            return ValueFacts.unknown(expression.source)
        return _with_provenance(
            facts_by_value.get(
                expression.value,
                ValueFacts.unknown(expression.value.source),
            ),
            expression.source,
        )
    if isinstance(expression, SSAUnaryExpression):
        operand = _expression_facts(expression.operand, facts_by_value)
        provenance = _merge_sources(operand.provenance, expression.source)
        if expression.operator is UnaryOperator.BITWISE_NOT:
            return ValueFacts(
                known_zero_bits=operand.known_one_bits,
                known_one_bits=operand.known_zero_bits,
                provenance=provenance,
            )
        if expression.operator is UnaryOperator.NEGATE:
            exact = operand.exact_value
            if exact is not None:
                return ValueFacts.constant(_u32(-exact), provenance)
        return ValueFacts.unknown(provenance)
    if isinstance(expression, SSABinaryExpression):
        return _binary_facts(expression, facts_by_value)
    if isinstance(expression, SSACompareExpression):
        return ValueFacts.unknown(
            _merge_sources(
                _expression_facts(expression.left, facts_by_value).provenance,
                _expression_facts(expression.right, facts_by_value).provenance,
                expression.source,
            )
        )
    if isinstance(expression, SSAMemoryReadExpression):
        return ValueFacts.unknown(
            _merge_sources(
                _expression_facts(expression.address, facts_by_value).provenance,
                expression.source,
            )
        )
    if isinstance(expression, SSACallExpression):
        argument_sources = tuple(
            _expression_facts(argument, facts_by_value).provenance
            for argument in expression.arguments
        )
        return ValueFacts.unknown(
            _merge_sources(*argument_sources, expression.source)
        )
    raise TypeError(f"unsupported SSA expression: {type(expression).__name__}")


def analyze_value_facts(
    function: SSAFunction,
    *,
    iteration_cap: int | None = None,
) -> ValueFactsAnalysis:
    assignments: list[tuple[SSAValue, SSAExpression]] = []
    phis = []
    all_values: set[SSAValue] = set(function.entry_definitions)

    for block in function.blocks:
        for phi in block.phis:
            phis.append(phi)
            all_values.add(phi.output)
            for incoming in phi.inputs:
                if incoming.value is not None:
                    all_values.add(incoming.value)
        for statement in block.statements:
            if isinstance(statement, SSAAssignmentStatement):
                assignments.append((statement.target, statement.value))
                all_values.add(statement.target)

    ordered_values = tuple(
        sorted(
            all_values,
            key=lambda value: (
                value.storage.kind.value,
                value.storage.register.value if value.storage.register else "",
                value.storage.stack_offset if value.storage.stack_offset is not None else 0,
                value.storage.temporary_name or "",
                value.version,
            ),
        )
    )
    facts_by_value = {
        value: ValueFacts.unknown(value.source)
        for value in ordered_values
    }

    cap = iteration_cap if iteration_cap is not None else max(8, len(ordered_values) * 4)
    if cap <= 0:
        raise ValueError("value-facts iteration cap must be positive")

    converged = False
    iterations = 0
    for iteration in range(1, cap + 1):
        iterations = iteration
        changed = False

        for phi in phis:
            incoming = tuple(
                (
                    ValueFacts.unknown()
                    if item.value is None
                    else facts_by_value.get(item.value, ValueFacts.unknown(item.value.source))
                )
                for item in phi.inputs
            )
            updated = _join_facts(incoming)
            if updated != facts_by_value[phi.output]:
                facts_by_value[phi.output] = updated
                changed = True

        for target, expression in assignments:
            updated = _expression_facts(expression, facts_by_value)
            if updated != facts_by_value[target]:
                facts_by_value[target] = updated
                changed = True

        if not changed:
            converged = True
            break

    return ValueFactsAnalysis(
        records=tuple((value, facts_by_value[value]) for value in ordered_values),
        converged=converged,
        iterations=iterations,
    )
