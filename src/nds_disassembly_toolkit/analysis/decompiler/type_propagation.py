from __future__ import annotations

from dataclasses import dataclass

from nds_disassembly_toolkit.analysis.decompiler.access_paths import (
    collect_field_accesses,
    normalize_access_path,
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
    build_def_use_index,
)
from nds_disassembly_toolkit.analysis.decompiler.structure_recovery import (
    LocalStructureRecovery,
    canonical_pointer_root,
    recover_local_structures,
)
from nds_disassembly_toolkit.analysis.decompiler.type_model import (
    IntegerType,
    PointerType,
    RecoveredSignedness,
    RecoveredType,
    TypeEvidence,
    TypeEvidenceKind,
)
from nds_disassembly_toolkit.analysis.decompiler.value_facts import (
    ValueFactsAnalysis,
    analyze_value_facts,
)
from nds_disassembly_toolkit.analysis.model import ConditionCode

_SIGNED_CONDITIONS = frozenset(
    {
        ConditionCode.GE,
        ConditionCode.LT,
        ConditionCode.GT,
        ConditionCode.LE,
    }
)
_UNSIGNED_CONDITIONS = frozenset(
    {
        ConditionCode.HS,
        ConditionCode.LO,
        ConditionCode.HI,
        ConditionCode.LS,
    }
)


def _value_sort_key(value: SSAValue) -> tuple[object, ...]:
    storage = value.storage
    return (
        storage.kind.value,
        storage.register.value if storage.register is not None else "",
        storage.stack_offset if storage.stack_offset is not None else 0,
        storage.temporary_name or "",
        value.version,
    )


def _evidence_sort_key(evidence: TypeEvidence) -> tuple[object, ...]:
    return (
        tuple(
            (source.address, source.instruction_set.value)
            for source in evidence.source
        ),
        evidence.kind.value,
        evidence.description,
    )


def _unique_evidence(
    evidence: list[TypeEvidence],
) -> tuple[TypeEvidence, ...]:
    return tuple(sorted(set(evidence), key=_evidence_sort_key))


@dataclass(frozen=True, slots=True)
class ValueTypeBinding:
    value: SSAValue
    recovered_type: RecoveredType
    evidence: tuple[TypeEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class FieldTypeBinding:
    root: SSAValue
    byte_offset: int
    recovered_type: IntegerType
    evidence: tuple[TypeEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class LocalTypeEnvironment:
    value_bindings: tuple[ValueTypeBinding, ...]
    field_bindings: tuple[FieldTypeBinding, ...]
    structures: LocalStructureRecovery

    def type_for_value(self, value: SSAValue) -> RecoveredType | None:
        for binding in self.value_bindings:
            if binding.value == value:
                return binding.recovered_type
        return None

    def type_for_field(
        self,
        root: SSAValue,
        byte_offset: int,
    ) -> IntegerType | None:
        for binding in self.field_bindings:
            if binding.root == root and binding.byte_offset == byte_offset:
                return binding.recovered_type
        return None


def _assignment_map(
    function: SSAFunction,
) -> dict[SSAValue, SSAAssignmentStatement]:
    return {
        statement.target: statement
        for block in function.blocks
        for statement in block.statements
        if isinstance(statement, SSAAssignmentStatement)
    }


def _visit_compares(
    expression: SSAExpression,
    output: list[SSACompareExpression],
) -> None:
    if isinstance(expression, SSACompareExpression):
        output.append(expression)
        _visit_compares(expression.left, output)
        _visit_compares(expression.right, output)
        return
    if isinstance(expression, SSAUnaryExpression):
        _visit_compares(expression.operand, output)
        return
    if isinstance(expression, SSABinaryExpression):
        _visit_compares(expression.left, output)
        _visit_compares(expression.right, output)
        return
    if isinstance(expression, SSAMemoryReadExpression):
        _visit_compares(expression.address, output)
        return
    if isinstance(expression, SSACallExpression):
        for argument in expression.arguments:
            _visit_compares(argument, output)


def _compare_expressions(
    function: SSAFunction,
) -> tuple[SSACompareExpression, ...]:
    output: list[SSACompareExpression] = []
    for block in function.blocks:
        for statement in block.statements:
            if isinstance(statement, SSAAssignmentStatement):
                _visit_compares(statement.value, output)
                continue
            if isinstance(statement, SSAMemoryWriteStatement):
                _visit_compares(statement.address, output)
                _visit_compares(statement.value, output)
                continue
            if isinstance(statement, SSACallStatement):
                _visit_compares(statement.call, output)
                continue
            if isinstance(statement, SSAReturnStatement):
                if statement.value is not None:
                    _visit_compares(statement.value, output)
                continue
            if (
                isinstance(statement, SSABranchStatement)
                and statement.condition is not None
            ):
                _visit_compares(statement.condition, output)
    return tuple(output)


def _signedness_for_condition(
    condition: ConditionCode,
) -> RecoveredSignedness | None:
    if condition in _SIGNED_CONDITIONS:
        return RecoveredSignedness.SIGNED
    if condition in _UNSIGNED_CONDITIONS:
        return RecoveredSignedness.UNSIGNED
    return None


def _merge_signedness(
    values: set[RecoveredSignedness],
) -> RecoveredSignedness:
    if not values:
        return RecoveredSignedness.UNKNOWN
    if len(values) == 1:
        return next(iter(values))
    return RecoveredSignedness.UNKNOWN


def infer_local_types(
    function: SSAFunction,
    *,
    structures: LocalStructureRecovery | None = None,
    facts: ValueFactsAnalysis | None = None,
) -> LocalTypeEnvironment:
    structure_result = (
        structures
        if structures is not None
        else recover_local_structures(function)
    )
    fact_analysis = facts if facts is not None else analyze_value_facts(function)
    index = build_def_use_index(function)
    assignments = _assignment_map(function)

    pointer_evidence: dict[SSAValue, list[TypeEvidence]] = {}
    pointer_components: dict[SSAValue, set[str | None]] = {}
    candidate_by_root = {
        candidate.root: candidate
        for candidate in structure_result.candidates
    }

    for access in collect_field_accesses(function):
        root = canonical_pointer_root(function, access.root, index=index)
        pointer_evidence.setdefault(root, []).append(
            TypeEvidence(
                TypeEvidenceKind.POINTER_DEREFERENCE,
                access.source,
                (
                    f"{access.kind.value} {access.width_bytes} byte(s) "
                    f"at +0x{access.byte_offset:x}"
                ),
            )
        )

    for value, value_facts in fact_analysis.records:
        if value_facts.address is None:
            continue
        root = canonical_pointer_root(function, value, index=index)
        pointer_evidence.setdefault(root, []).append(
            TypeEvidence(
                TypeEvidenceKind.EXACT_ADDRESS,
                value_facts.provenance,
                f"proven address 0x{value_facts.address:08x}",
            )
        )
        pointer_components.setdefault(root, set()).add(value_facts.component)

    value_signedness: dict[
        SSAValue,
        set[RecoveredSignedness],
    ] = {}
    value_evidence: dict[SSAValue, list[TypeEvidence]] = {}
    field_signedness: dict[
        tuple[SSAValue, int],
        set[RecoveredSignedness],
    ] = {}
    field_evidence: dict[
        tuple[SSAValue, int],
        list[TypeEvidence],
    ] = {}

    def classify_reference(
        reference: SSAReferenceExpression,
        signedness: RecoveredSignedness,
        evidence: TypeEvidence,
    ) -> None:
        if reference.value is None:
            return
        value = canonical_pointer_root(
            function,
            reference.value,
            index=index,
        )
        assignment = assignments.get(value)
        if (
            assignment is not None
            and isinstance(assignment.value, SSAMemoryReadExpression)
        ):
            path = normalize_access_path(assignment.value.address)
            if (
                path is not None
                and path.byte_offset >= 0
                and path.index is None
            ):
                root = canonical_pointer_root(
                    function,
                    path.root,
                    index=index,
                )
                key = (root, path.byte_offset)
                field_signedness.setdefault(key, set()).add(signedness)
                field_evidence.setdefault(key, []).append(evidence)
                return

        value_signedness.setdefault(value, set()).add(signedness)
        value_evidence.setdefault(value, []).append(evidence)

    for compare in _compare_expressions(function):
        signedness = _signedness_for_condition(compare.condition)
        if signedness is None:
            continue
        kind = (
            TypeEvidenceKind.SIGNED_COMPARE
            if signedness is RecoveredSignedness.SIGNED
            else TypeEvidenceKind.UNSIGNED_COMPARE
        )
        compare_evidence = TypeEvidence(
            kind,
            compare.source,
            f"condition {compare.condition.value}",
        )
        if isinstance(compare.left, SSAReferenceExpression):
            classify_reference(compare.left, signedness, compare_evidence)
        if isinstance(compare.right, SSAReferenceExpression):
            classify_reference(compare.right, signedness, compare_evidence)

    field_bindings: list[FieldTypeBinding] = []
    for candidate in structure_result.candidates:
        for field in candidate.fields:
            key = (candidate.root, field.offset)
            signedness = _merge_signedness(
                field_signedness.get(key, set())
            )
            binding_evidence = list(field_evidence.get(key, ()))
            binding_evidence.extend(
                TypeEvidence(
                    (
                        TypeEvidenceKind.MEMORY_READ
                        if access.kind.value == "read"
                        else TypeEvidenceKind.MEMORY_WRITE
                    ),
                    access.source,
                    f"{access.width_bytes} byte(s) at +0x{access.byte_offset:x}",
                )
                for access in candidate.accesses
                if access.byte_offset == field.offset
            )
            field_bindings.append(
                FieldTypeBinding(
                    root=candidate.root,
                    byte_offset=field.offset,
                    recovered_type=IntegerType(
                        field.width_bytes,
                        signedness,
                    ),
                    evidence=_unique_evidence(binding_evidence),
                )
            )

    loaded_types: dict[SSAValue, IntegerType] = {}
    loaded_evidence: dict[SSAValue, list[TypeEvidence]] = {}
    for target, assignment in assignments.items():
        if not isinstance(assignment.value, SSAMemoryReadExpression):
            continue
        signedness = _merge_signedness(
            value_signedness.get(target, set())
        )
        loaded_types[target] = IntegerType(
            assignment.value.width,
            signedness,
        )
        loaded_evidence.setdefault(target, []).append(
            TypeEvidence(
                TypeEvidenceKind.MEMORY_READ,
                assignment.value.source,
                f"{assignment.value.width} byte memory result",
            )
        )
        loaded_evidence[target].extend(value_evidence.get(target, ()))

    value_bindings: list[ValueTypeBinding] = []
    all_values = (
        set(pointer_evidence)
        | set(loaded_types)
        | set(value_signedness)
    )
    for value in sorted(all_values, key=_value_sort_key):
        if value in pointer_evidence:
            structure_candidate = candidate_by_root.get(value)
            components = pointer_components.get(value, set())
            component: str | None = None
            if len(components) == 1:
                component = next(iter(components))
            value_bindings.append(
                ValueTypeBinding(
                    value=value,
                    recovered_type=PointerType(
                        pointee_name=(
                            structure_candidate.name
                            if structure_candidate is not None
                            else None
                        ),
                        component=component,
                    ),
                    evidence=_unique_evidence(
                        pointer_evidence[value]
                    ),
                )
            )
            continue

        loaded = loaded_types.get(value)
        if loaded is not None:
            value_bindings.append(
                ValueTypeBinding(
                    value=value,
                    recovered_type=loaded,
                    evidence=_unique_evidence(
                        loaded_evidence.get(value, [])
                    ),
                )
            )
            continue

        signedness = _merge_signedness(
            value_signedness.get(value, set())
        )
        value_bindings.append(
            ValueTypeBinding(
                value=value,
                recovered_type=IntegerType(4, signedness),
                evidence=_unique_evidence(
                    value_evidence.get(value, [])
                ),
            )
        )

    return LocalTypeEnvironment(
        value_bindings=tuple(value_bindings),
        field_bindings=tuple(
            sorted(
                field_bindings,
                key=lambda binding: (
                    _value_sort_key(binding.root),
                    binding.byte_offset,
                ),
            )
        ),
        structures=structure_result,
    )



@dataclass(frozen=True, slots=True)
class RenderStructField:
    type_name: str
    name: str
    offset: int


@dataclass(frozen=True, slots=True)
class RenderStructType:
    name: str
    fields: tuple[RenderStructField, ...]


@dataclass(frozen=True, slots=True)
class RenderTypeContext:
    parameter_types: tuple[tuple[str, str], ...] = ()
    local_types: tuple[tuple[str, str], ...] = ()
    structures: tuple[RenderStructType, ...] = ()

    def parameter_type(self, variable_name: str) -> str | None:
        for name, type_name in self.parameter_types:
            if name == variable_name:
                return type_name
        return None

    def local_type(self, variable_name: str) -> str | None:
        for name, type_name in self.local_types:
            if name == variable_name:
                return type_name
        return None


def _integer_c_type(value: IntegerType) -> str:
    prefix = (
        "int"
        if value.signedness is RecoveredSignedness.SIGNED
        else "uint"
    )
    return f"{prefix}{value.width_bytes * 8}_t"


def build_render_type_context(
    function: SSAFunction,
    environment: LocalTypeEnvironment,
) -> RenderTypeContext:
    renderable = {
        candidate.root: candidate
        for candidate in environment.structures.candidates
        if candidate.should_render and not candidate.conflicts
    }

    parameter_types: list[tuple[str, str]] = []
    for index, parameter in enumerate(function.parameters):
        if index >= len(function.entry_definitions):
            continue
        entry = function.entry_definitions[index]
        candidate = renderable.get(entry)
        recovered = environment.type_for_value(entry)
        if (
            candidate is not None
            and isinstance(recovered, PointerType)
            and recovered.pointee_name == candidate.name
        ):
            parameter_types.append(
                (parameter.name, f"struct {candidate.name} *")
            )
            continue
        if isinstance(recovered, IntegerType):
            parameter_types.append(
                (parameter.name, _integer_c_type(recovered))
            )

    structures: list[RenderStructType] = []
    for candidate in sorted(
        renderable.values(),
        key=lambda item: (
            item.component,
            item.function_address,
            item.instruction_set.value,
            item.name,
        ),
    ):
        fields: list[RenderStructField] = []
        for field in candidate.fields:
            recovered_field = environment.type_for_field(
                candidate.root,
                field.offset,
            )
            type_name = (
                _integer_c_type(recovered_field)
                if recovered_field is not None
                else _integer_c_type(
                    IntegerType(
                        field.width_bytes,
                        RecoveredSignedness.UNKNOWN,
                    )
                )
            )
            fields.append(
                RenderStructField(
                    type_name=type_name,
                    name=field.name,
                    offset=field.offset,
                )
            )
        structures.append(
            RenderStructType(
                name=candidate.name,
                fields=tuple(fields),
            )
        )

    return RenderTypeContext(
        parameter_types=tuple(parameter_types),
        structures=tuple(structures),
    )
