from __future__ import annotations

from dataclasses import dataclass, replace
from itertools import pairwise

from nds_disassembly_toolkit.analysis.decompiler.model import SourceRef
from nds_disassembly_toolkit.analysis.decompiler.access_paths import (
    FieldAccessEvidence,
    collect_field_accesses,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    DefUseIndex,
    PhiNode,
    SSAAssignmentStatement,
    SSADefinitionKind,
    SSAFunction,
    SSAReferenceExpression,
    SSAStorageKind,
    SSAValue,
    build_def_use_index,
)
from nds_disassembly_toolkit.analysis.decompiler.type_model import (
    IntegerType,
    RecoveredSignedness,
    RecoveredStructField,
    RecoveredStructType,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet


def _value_sort_key(value: SSAValue) -> tuple[object, ...]:
    storage = value.storage
    return (
        storage.kind.value,
        storage.register.value if storage.register is not None else "",
        storage.stack_offset if storage.stack_offset is not None else 0,
        storage.temporary_name or "",
        value.version,
    )


def _source_sort_key(source: tuple[SourceRef, ...]) -> tuple[object, ...]:
    return tuple(
        (
            item.address,
            item.instruction_set.value,
        )
        for item in source
    )


def _canonical_sources(
    accesses: tuple[FieldAccessEvidence, ...],
) -> tuple[SourceRef, ...]:
    sources = {
        item
        for access in accesses
        for item in access.source
    }
    return tuple(
        sorted(
            sources,
            key=lambda item: (item.address, item.instruction_set.value),
        )
    )


def _sanitize_identifier(value: str) -> str:
    normalized = "".join(
        character if character.isalnum() or character == "_" else "_"
        for character in value
    )
    if not normalized:
        return "value"
    if normalized[0].isdigit():
        return f"n_{normalized}"
    return normalized


def _root_label(function: SSAFunction, root: SSAValue) -> str:
    for index, entry in enumerate(function.entry_definitions):
        if entry != root:
            continue
        if index < len(function.parameters):
            return _sanitize_identifier(function.parameters[index].name)
        return f"arg{index}"

    storage = root.storage
    if storage.kind is SSAStorageKind.REGISTER:
        assert storage.register is not None
        return f"{storage.register.value}_v{root.version}"
    if storage.kind is SSAStorageKind.STACK:
        assert storage.stack_offset is not None
        prefix = "m" if storage.stack_offset < 0 else "p"
        return f"stack_{prefix}{abs(storage.stack_offset):x}_v{root.version}"
    assert storage.temporary_name is not None
    return f"{_sanitize_identifier(storage.temporary_name)}_v{root.version}"


def _field_name(offset: int) -> str:
    width = 2 if offset <= 0xFF else 4
    return f"field_{offset:0{width}x}"


def _assignment_for_value(
    function: SSAFunction,
    index: DefUseIndex,
    value: SSAValue,
) -> SSAAssignmentStatement | None:
    definition = index.definition(value)
    if (
        definition is None
        or definition.kind is not SSADefinitionKind.ASSIGNMENT
        or definition.statement_index is None
    ):
        return None
    statement = function.block(definition.block_address).statements[
        definition.statement_index
    ]
    if not isinstance(statement, SSAAssignmentStatement):
        return None
    if statement.target != value:
        return None
    return statement


def _phi_for_value(
    function: SSAFunction,
    index: DefUseIndex,
    value: SSAValue,
) -> PhiNode | None:
    definition = index.definition(value)
    if definition is None or definition.kind is not SSADefinitionKind.PHI:
        return None
    for phi in function.block(definition.block_address).phis:
        if phi.output == value:
            return phi
    return None


def canonical_pointer_root(
    function: SSAFunction,
    value: SSAValue,
    *,
    index: DefUseIndex | None = None,
) -> SSAValue:
    def_use = index if index is not None else build_def_use_index(function)
    memo: dict[SSAValue, SSAValue] = {}

    def resolve(
        current: SSAValue,
        visiting: frozenset[SSAValue],
    ) -> SSAValue:
        cached = memo.get(current)
        if cached is not None:
            return cached
        if current in visiting:
            return current

        next_visiting = visiting | {current}
        assignment = _assignment_for_value(function, def_use, current)
        if (
            assignment is not None
            and isinstance(assignment.value, SSAReferenceExpression)
            and assignment.value.value is not None
        ):
            root = resolve(assignment.value.value, next_visiting)
            memo[current] = root
            return root

        phi = _phi_for_value(function, def_use, current)
        if phi is not None:
            if not phi.inputs or any(item.value is None for item in phi.inputs):
                memo[current] = current
                return current
            roots = tuple(
                resolve(item.value, next_visiting)
                for item in phi.inputs
                if item.value is not None
            )
            first = roots[0]
            if all(root == first for root in roots[1:]):
                memo[current] = first
                return first

        memo[current] = current
        return current

    return resolve(value, frozenset())


@dataclass(frozen=True, slots=True)
class StructureCandidate:
    component: str
    function_address: int
    instruction_set: InstructionSet
    root: SSAValue
    name: str
    fields: tuple[RecoveredStructField, ...]
    accesses: tuple[FieldAccessEvidence, ...]
    conflicts: tuple[str, ...] = ()
    interprocedural_support: bool = False

    @property
    def should_render(self) -> bool:
        if self.conflicts or not self.fields:
            return False
        if self.interprocedural_support or len(self.fields) >= 2:
            return True

        for field in self.fields:
            sites = {
                (
                    source.address,
                    source.instruction_set,
                )
                for access in self.accesses
                if access.byte_offset == field.offset
                for source in access.source
            }
            if len(sites) >= 2:
                return True
        return False

    def to_struct_type(self) -> RecoveredStructType | None:
        if self.conflicts or not self.fields:
            return None
        return RecoveredStructType(self.name, self.fields)


@dataclass(frozen=True, slots=True)
class LocalStructureRecovery:
    candidates: tuple[StructureCandidate, ...]
    indexed_accesses: tuple[FieldAccessEvidence, ...] = ()


def _candidate_for_root(
    function: SSAFunction,
    root: SSAValue,
    accesses: tuple[FieldAccessEvidence, ...],
) -> StructureCandidate:
    by_offset: dict[int, list[FieldAccessEvidence]] = {}
    for access in accesses:
        by_offset.setdefault(access.byte_offset, []).append(access)

    fields: list[RecoveredStructField] = []
    conflicts: list[str] = []

    for offset in sorted(by_offset):
        offset_accesses = tuple(by_offset[offset])
        widths = sorted({access.width_bytes for access in offset_accesses})
        if len(widths) != 1:
            conflicts.append(
                f"field 0x{offset:x} has conflicting widths "
                + "/".join(str(width) for width in widths)
            )
            continue
        width = widths[0]
        fields.append(
            RecoveredStructField(
                offset=offset,
                width_bytes=width,
                name=_field_name(offset),
                field_type=IntegerType(
                    width,
                    RecoveredSignedness.UNKNOWN,
                ),
                source=_canonical_sources(offset_accesses),
            )
        )

    ordered_fields = tuple(sorted(fields, key=lambda field: field.offset))
    for previous, current in pairwise(ordered_fields):
        if current.offset < previous.offset + previous.width_bytes:
            conflicts.append(
                "field overlap: "
                f"{previous.name} [{previous.offset:#x},"
                f"{previous.offset + previous.width_bytes:#x}) and "
                f"{current.name} [{current.offset:#x},"
                f"{current.offset + current.width_bytes:#x})"
            )

    name = (
        f"struct_{_sanitize_identifier(function.name)}_"
        f"{_root_label(function, root)}"
    )
    return StructureCandidate(
        component=function.component,
        function_address=function.address,
        instruction_set=function.instruction_set,
        root=root,
        name=name,
        fields=ordered_fields,
        accesses=tuple(
            sorted(
                accesses,
                key=lambda access: (
                    _source_sort_key(access.source),
                    access.byte_offset,
                    access.width_bytes,
                    access.kind.value,
                ),
            )
        ),
        conflicts=tuple(sorted(set(conflicts))),
    )


def recover_local_structures(
    function: SSAFunction,
) -> LocalStructureRecovery:
    accesses = collect_field_accesses(function)
    index = build_def_use_index(function)

    direct_by_root: dict[SSAValue, list[FieldAccessEvidence]] = {}
    indexed: list[FieldAccessEvidence] = []

    for access in accesses:
        canonical = canonical_pointer_root(
            function,
            access.root,
            index=index,
        )
        normalized = replace(access, root=canonical)
        if not normalized.is_direct_field:
            indexed.append(normalized)
            continue
        direct_by_root.setdefault(canonical, []).append(normalized)

    candidates = tuple(
        _candidate_for_root(
            function,
            root,
            tuple(direct_by_root[root]),
        )
        for root in sorted(direct_by_root, key=_value_sort_key)
    )

    return LocalStructureRecovery(
        candidates=candidates,
        indexed_accesses=tuple(
            sorted(
                indexed,
                key=lambda access: (
                    _source_sort_key(access.source),
                    _value_sort_key(access.root),
                    access.byte_offset,
                    access.width_bytes,
                ),
            )
        ),
    )
