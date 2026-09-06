from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    AssignmentStatement,
    BinaryExpression,
    BinaryOperator,
    BranchStatement,
    CallExpression,
    CallStatement,
    CompareExpression,
    ConstantExpression,
    DecompiledFunction,
    DecompilerVariable,
    DecompilerVariableKind,
    MemoryReadExpression,
    MemoryWriteStatement,
    RegisterExpression,
    ReturnStatement,
    SourceRef,
    UnaryExpression,
    UnaryOperator,
    UnknownExpression,
    UnknownStatement,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.model import (
    CFGEdge,
    CFGEdgeKind,
    ConditionCode,
    InstructionSet,
    Register,
)

_U32_MAX = 0xFFFFFFFF
_CALL_CLOBBER_REGISTERS = (
    Register.R0,
    Register.R1,
    Register.R2,
    Register.R3,
    Register.R12,
    Register.LR,
)


def _validate_u32(value: int, *, name: str) -> None:
    if not 0 <= value <= _U32_MAX:
        raise ValueError(f"{name} must be an unsigned 32-bit value")


class SSAStorageKind(StrEnum):
    REGISTER = "register"
    STACK = "stack"
    TEMPORARY = "temporary"


@dataclass(frozen=True, slots=True)
class SSAStorage:
    kind: SSAStorageKind
    register: Register | None = None
    stack_offset: int | None = None
    temporary_name: str | None = None

    def __post_init__(self) -> None:
        if self.kind is SSAStorageKind.REGISTER:
            if (
                self.register is None
                or self.stack_offset is not None
                or self.temporary_name is not None
            ):
                raise ValueError("register SSA storage requires exactly one register")
            return
        if self.kind is SSAStorageKind.STACK:
            if (
                self.stack_offset is None
                or self.register is not None
                or self.temporary_name is not None
            ):
                raise ValueError("stack SSA storage requires exactly one stack offset")
            return
        if (
            not self.temporary_name
            or self.register is not None
            or self.stack_offset is not None
        ):
            raise ValueError("temporary SSA storage requires exactly one temporary name")


@dataclass(frozen=True, slots=True)
class SSAValue:
    storage: SSAStorage
    version: int
    source: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        if self.version < 0:
            raise ValueError("SSA value version must be non-negative")


@dataclass(frozen=True, slots=True)
class PhiInput:
    predecessor_address: int
    value: SSAValue | None

    def __post_init__(self) -> None:
        _validate_u32(self.predecessor_address, name="PHI predecessor address")


@dataclass(frozen=True, slots=True)
class PhiNode:
    output: SSAValue
    inputs: tuple[PhiInput, ...]

    def __post_init__(self) -> None:
        normalized = tuple(sorted(self.inputs, key=lambda item: item.predecessor_address))
        addresses = tuple(item.predecessor_address for item in normalized)
        if len(addresses) != len(set(addresses)):
            raise ValueError("PHI predecessor addresses must be unique")
        for item in normalized:
            if item.value is not None and item.value.storage != self.output.storage:
                raise ValueError("PHI input storage must match PHI output storage")
        object.__setattr__(self, "inputs", normalized)


@dataclass(frozen=True, slots=True)
class DominatorInfo:
    entry_address: int
    reachable_blocks: tuple[int, ...]
    immediate_dominators: tuple[tuple[int, int | None], ...]
    dominance_frontiers: tuple[tuple[int, tuple[int, ...]], ...]

    def idom(self, address: int) -> int | None:
        for block_address, immediate in self.immediate_dominators:
            if block_address == address:
                return immediate
        return None

    def frontier(self, address: int) -> tuple[int, ...]:
        for block_address, frontier in self.dominance_frontiers:
            if block_address == address:
                return frontier
        return ()


def _reachable_successors(function: DecompiledFunction) -> dict[int, tuple[int, ...]]:
    block_addresses = {block.address for block in function.blocks}
    successors: dict[int, tuple[int, ...]] = {}
    for block in function.blocks:
        targets = {
            edge.target_address
            for edge in block.edges
            if edge.kind is not CFGEdgeKind.CALL and edge.target_address in block_addresses
        }
        successors[block.address] = tuple(sorted(targets))
    return successors


def _find_reachable(
    entry_address: int,
    successors: dict[int, tuple[int, ...]],
) -> tuple[int, ...]:
    if entry_address not in successors:
        raise ValueError("decompiled function entry block is missing")
    seen: set[int] = set()
    pending = [entry_address]
    while pending:
        address = pending.pop()
        if address in seen:
            continue
        seen.add(address)
        pending.extend(reversed(successors[address]))
    return tuple(sorted(seen))


def _predecessors(
    reachable: tuple[int, ...],
    successors: dict[int, tuple[int, ...]],
) -> dict[int, tuple[int, ...]]:
    reachable_set = set(reachable)
    incoming: dict[int, set[int]] = {address: set() for address in reachable}
    for source in reachable:
        for target in successors[source]:
            if target in reachable_set:
                incoming[target].add(source)
    return {
        address: tuple(sorted(predecessors))
        for address, predecessors in incoming.items()
    }


def _dominator_sets(
    entry_address: int,
    reachable: tuple[int, ...],
    predecessors: dict[int, tuple[int, ...]],
) -> dict[int, set[int]]:
    all_blocks = set(reachable)
    dominators: dict[int, set[int]] = {
        address: ({entry_address} if address == entry_address else set(all_blocks))
        for address in reachable
    }

    changed = True
    while changed:
        changed = False
        for address in reachable:
            if address == entry_address:
                continue
            preds = predecessors[address]
            if not preds:
                new_set = {address}
            else:
                intersection = set(dominators[preds[0]])
                for predecessor in preds[1:]:
                    intersection.intersection_update(dominators[predecessor])
                new_set = {address, *intersection}
            if new_set != dominators[address]:
                dominators[address] = new_set
                changed = True
    return dominators


def _immediate_dominators(
    entry_address: int,
    reachable: tuple[int, ...],
    dominators: dict[int, set[int]],
) -> dict[int, int | None]:
    immediate: dict[int, int | None] = {entry_address: None}
    for address in reachable:
        if address == entry_address:
            continue
        strict = dominators[address] - {address}
        if not strict:
            immediate[address] = None
            continue
        immediate[address] = max(
            strict,
            key=lambda candidate: (len(dominators[candidate]), candidate),
        )
    return immediate


def _dominance_frontiers(
    reachable: tuple[int, ...],
    predecessors: dict[int, tuple[int, ...]],
    dominators: dict[int, set[int]],
) -> dict[int, tuple[int, ...]]:
    frontiers: dict[int, set[int]] = {address: set() for address in reachable}
    for candidate in reachable:
        for join in reachable:
            if not predecessors[join]:
                continue
            dominates_a_predecessor = any(
                candidate in dominators[predecessor]
                for predecessor in predecessors[join]
            )
            strictly_dominates_join = (
                candidate != join and candidate in dominators[join]
            )
            if dominates_a_predecessor and not strictly_dominates_join:
                frontiers[candidate].add(join)
    return {
        address: tuple(sorted(frontiers[address]))
        for address in reachable
    }


def compute_dominator_info(function: DecompiledFunction) -> DominatorInfo:
    if not function.blocks:
        raise ValueError("decompiled function has no blocks")
    addresses = [block.address for block in function.blocks]
    if len(addresses) != len(set(addresses)):
        raise ValueError("decompiled function contains duplicate block addresses")

    successors = _reachable_successors(function)
    reachable = _find_reachable(function.address, successors)
    predecessors = _predecessors(reachable, successors)
    dominators = _dominator_sets(function.address, reachable, predecessors)
    immediate = _immediate_dominators(function.address, reachable, dominators)
    frontiers = _dominance_frontiers(reachable, predecessors, dominators)

    return DominatorInfo(
        entry_address=function.address,
        reachable_blocks=reachable,
        immediate_dominators=tuple(
            (address, immediate[address])
            for address in reachable
        ),
        dominance_frontiers=tuple(
            (address, frontiers[address])
            for address in reachable
        ),
    )


@dataclass(frozen=True, slots=True)
class SSAReferenceExpression:
    storage: SSAStorage
    value: SSAValue | None
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class SSAUnaryExpression:
    operator: UnaryOperator
    operand: SSAExpression
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class SSABinaryExpression:
    operator: BinaryOperator
    left: SSAExpression
    right: SSAExpression
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class SSACompareExpression:
    condition: ConditionCode
    left: SSAExpression
    right: SSAExpression
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class SSAMemoryReadExpression:
    address: SSAExpression
    width: int
    source: tuple[SourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class SSACallExpression:
    name: str
    target_address: int
    target_instruction_set: InstructionSet
    target_component: str | None
    arguments: tuple[SSAExpression, ...] = ()
    source: tuple[SourceRef, ...] = ()


SSAExpression: TypeAlias = (
    ConstantExpression
    | AddressExpression
    | UnknownExpression
    | SSAReferenceExpression
    | SSAUnaryExpression
    | SSABinaryExpression
    | SSACompareExpression
    | SSAMemoryReadExpression
    | SSACallExpression
)


@dataclass(frozen=True, slots=True)
class SSAAssignmentStatement:
    target: SSAValue
    value: SSAExpression
    source: tuple[SourceRef, ...]


@dataclass(frozen=True, slots=True)
class SSAMemoryWriteStatement:
    address: SSAExpression
    value: SSAExpression
    width: int
    source: tuple[SourceRef, ...]


@dataclass(frozen=True, slots=True)
class SSACallStatement:
    call: SSACallExpression
    source: tuple[SourceRef, ...]
    result: SSAValue | None = None


@dataclass(frozen=True, slots=True)
class SSAReturnStatement:
    value: SSAExpression | None
    source: tuple[SourceRef, ...]


@dataclass(frozen=True, slots=True)
class SSABranchStatement:
    condition: SSAExpression | None
    target_address: int
    target_instruction_set: InstructionSet
    source: tuple[SourceRef, ...]


SSAStatement: TypeAlias = (
    SSAAssignmentStatement
    | SSAMemoryWriteStatement
    | SSACallStatement
    | SSAReturnStatement
    | SSABranchStatement
    | UnknownStatement
)


@dataclass(frozen=True, slots=True)
class SSABlock:
    address: int
    instruction_set: InstructionSet
    phis: tuple[PhiNode, ...]
    statements: tuple[SSAStatement, ...]
    edges: tuple[CFGEdge, ...]


@dataclass(frozen=True, slots=True)
class SSAFunction:
    component: str
    address: int
    instruction_set: InstructionSet
    name: str
    parameters: tuple[DecompilerVariable, ...]
    locals: tuple[DecompilerVariable, ...]
    blocks: tuple[SSABlock, ...]
    entry_definitions: tuple[SSAValue, ...] = ()
    warnings: tuple[str, ...] = ()

    def block(self, address: int) -> SSABlock:
        for block in self.blocks:
            if block.address == address:
                return block
        raise KeyError(f"SSA block 0x{address:08X} does not exist")


class SSADefinitionKind(StrEnum):
    ENTRY = "entry"
    PHI = "phi"
    ASSIGNMENT = "assignment"
    CALL_RESULT = "call_result"


@dataclass(frozen=True, slots=True)
class SSADefinition:
    value: SSAValue
    kind: SSADefinitionKind
    block_address: int
    statement_index: int | None = None


@dataclass(frozen=True, slots=True)
class SSAUse:
    value: SSAValue
    block_address: int
    statement_index: int | None
    phi_predecessor_address: int | None = None


@dataclass(frozen=True, slots=True)
class DefUseIndex:
    definitions: tuple[SSADefinition, ...]
    use_records: tuple[SSAUse, ...]
    phi_records: tuple[tuple[int, PhiNode], ...]

    def definition(self, value: SSAValue) -> SSADefinition | None:
        for definition in self.definitions:
            if definition.value == value:
                return definition
        return None

    def uses(self, value: SSAValue) -> tuple[SSAUse, ...]:
        return tuple(use for use in self.use_records if use.value == value)

    def phi_for(self, storage: SSAStorage, block_address: int) -> PhiNode | None:
        for address, phi in self.phi_records:
            if address == block_address and phi.output.storage == storage:
                return phi
        return None


def _storage_sort_key(storage: SSAStorage) -> tuple[int, str]:
    if storage.kind is SSAStorageKind.REGISTER:
        assert storage.register is not None
        return (0, storage.register.value)
    if storage.kind is SSAStorageKind.STACK:
        assert storage.stack_offset is not None
        return (1, f"{storage.stack_offset:+011d}")
    assert storage.temporary_name is not None
    return (2, storage.temporary_name)


def _storage_for_variable(variable: DecompilerVariable) -> SSAStorage:
    if variable.register is not None:
        return SSAStorage(SSAStorageKind.REGISTER, register=variable.register)
    if variable.stack_offset is not None:
        return SSAStorage(SSAStorageKind.STACK, stack_offset=variable.stack_offset)
    if variable.kind is DecompilerVariableKind.TEMPORARY:
        return SSAStorage(SSAStorageKind.TEMPORARY, temporary_name=variable.name)
    raise ValueError(f"variable {variable.name!r} has no promotable storage")


def _storage_for_target(
    target: VariableExpression | RegisterExpression,
) -> SSAStorage:
    if isinstance(target, RegisterExpression):
        return SSAStorage(SSAStorageKind.REGISTER, register=target.register)
    return _storage_for_variable(target.variable)


def _current_value(
    storage: SSAStorage,
    stacks: dict[SSAStorage, list[SSAValue | None]],
) -> SSAValue | None:
    stack = stacks.get(storage)
    return stack[-1] if stack else None


def _rename_expression(
    expression: object,
    stacks: dict[SSAStorage, list[SSAValue | None]],
) -> SSAExpression:
    if isinstance(expression, ConstantExpression | AddressExpression | UnknownExpression):
        return expression
    if isinstance(expression, RegisterExpression):
        storage = SSAStorage(SSAStorageKind.REGISTER, register=expression.register)
        return SSAReferenceExpression(
            storage,
            _current_value(storage, stacks),
            expression.source,
        )
    if isinstance(expression, VariableExpression):
        storage = _storage_for_variable(expression.variable)
        return SSAReferenceExpression(
            storage,
            _current_value(storage, stacks),
            expression.source,
        )
    if isinstance(expression, UnaryExpression):
        return SSAUnaryExpression(
            expression.operator,
            _rename_expression(expression.operand, stacks),
            expression.source,
        )
    if isinstance(expression, BinaryExpression):
        return SSABinaryExpression(
            expression.operator,
            _rename_expression(expression.left, stacks),
            _rename_expression(expression.right, stacks),
            expression.source,
        )
    if isinstance(expression, CompareExpression):
        return SSACompareExpression(
            expression.condition,
            _rename_expression(expression.left, stacks),
            _rename_expression(expression.right, stacks),
            expression.source,
        )
    if isinstance(expression, MemoryReadExpression):
        return SSAMemoryReadExpression(
            _rename_expression(expression.address, stacks),
            expression.width,
            expression.source,
        )
    if isinstance(expression, CallExpression):
        return SSACallExpression(
            expression.name,
            expression.target_address,
            expression.target_instruction_set,
            expression.target_component,
            tuple(_rename_expression(argument, stacks) for argument in expression.arguments),
            expression.source,
        )
    raise TypeError(f"unsupported decompiler expression: {type(expression).__name__}")


def _definition_sites(
    function: DecompiledFunction,
    reachable: tuple[int, ...],
) -> dict[SSAStorage, set[int]]:
    reachable_set = set(reachable)
    sites: dict[SSAStorage, set[int]] = {}
    for block in function.blocks:
        if block.address not in reachable_set:
            continue
        for statement in block.statements:
            if isinstance(statement, AssignmentStatement):
                storage = _storage_for_target(statement.target)
                sites.setdefault(storage, set()).add(block.address)
                continue
            if isinstance(statement, CallStatement):
                for register in _CALL_CLOBBER_REGISTERS:
                    storage = SSAStorage(
                        SSAStorageKind.REGISTER,
                        register=register,
                    )
                    sites.setdefault(storage, set()).add(block.address)
    return sites


def _place_phi_storages(
    info: DominatorInfo,
    definition_sites: dict[SSAStorage, set[int]],
) -> dict[int, set[SSAStorage]]:
    placements: dict[int, set[SSAStorage]] = {
        address: set() for address in info.reachable_blocks
    }
    for storage in sorted(definition_sites, key=_storage_sort_key):
        work = list(sorted(definition_sites[storage], reverse=True))
        queued = set(definition_sites[storage])
        while work:
            address = work.pop()
            for frontier in info.frontier(address):
                if storage in placements[frontier]:
                    continue
                placements[frontier].add(storage)
                if frontier not in queued:
                    queued.add(frontier)
                    work.append(frontier)
                    work.sort(reverse=True)
    return placements


def _dominator_children(info: DominatorInfo) -> dict[int, tuple[int, ...]]:
    children: dict[int, list[int]] = {
        address: [] for address in info.reachable_blocks
    }
    for address in info.reachable_blocks:
        parent = info.idom(address)
        if parent is not None:
            children[parent].append(address)
    return {
        address: tuple(sorted(child_addresses))
        for address, child_addresses in children.items()
    }


def _new_value(
    storage: SSAStorage,
    source: tuple[SourceRef, ...],
    counters: dict[SSAStorage, int],
) -> SSAValue:
    version = counters.get(storage, 0)
    counters[storage] = version + 1
    return SSAValue(storage, version, source)


def _rename_statement(
    statement: object,
    stacks: dict[SSAStorage, list[SSAValue | None]],
    counters: dict[SSAStorage, int],
    pushed: list[SSAStorage],
) -> SSAStatement:
    if isinstance(statement, AssignmentStatement):
        assigned_value = _rename_expression(statement.value, stacks)
        storage = _storage_for_target(statement.target)
        target = _new_value(storage, statement.source, counters)
        stacks.setdefault(storage, []).append(target)
        pushed.append(storage)
        return SSAAssignmentStatement(target, assigned_value, statement.source)
    if isinstance(statement, MemoryWriteStatement):
        return SSAMemoryWriteStatement(
            _rename_expression(statement.address, stacks),
            _rename_expression(statement.value, stacks),
            statement.width,
            statement.source,
        )
    if isinstance(statement, CallStatement):
        call = _rename_expression(statement.call, stacks)
        if not isinstance(call, SSACallExpression):
            raise TypeError("call statement did not produce an SSA call expression")

        result_storage = SSAStorage(
            SSAStorageKind.REGISTER,
            register=Register.R0,
        )
        result = _new_value(
            result_storage,
            statement.source,
            counters,
        )
        stacks.setdefault(result_storage, []).append(result)
        pushed.append(result_storage)

        for register in _CALL_CLOBBER_REGISTERS:
            if register is Register.R0:
                continue
            storage = SSAStorage(
                SSAStorageKind.REGISTER,
                register=register,
            )
            stacks.setdefault(storage, []).append(None)
            pushed.append(storage)
        return SSACallStatement(call, statement.source, result)
    if isinstance(statement, ReturnStatement):
        return_value = (
            None
            if statement.value is None
            else _rename_expression(statement.value, stacks)
        )
        return SSAReturnStatement(return_value, statement.source)
    if isinstance(statement, BranchStatement):
        condition = (
            None
            if statement.condition is None
            else _rename_expression(statement.condition, stacks)
        )
        return SSABranchStatement(
            condition,
            statement.target_address,
            statement.target_instruction_set,
            statement.source,
        )
    if isinstance(statement, UnknownStatement):
        return statement
    raise TypeError(f"unsupported decompiler statement: {type(statement).__name__}")


def build_ssa_function(function: DecompiledFunction) -> SSAFunction:
    info = compute_dominator_info(function)
    reachable = set(info.reachable_blocks)
    successors = _reachable_successors(function)
    predecessors = _predecessors(info.reachable_blocks, successors)
    definitions = _definition_sites(function, info.reachable_blocks)
    phi_storages = _place_phi_storages(info, definitions)
    children = _dominator_children(info)
    blocks_by_address = {block.address: block for block in function.blocks}

    counters: dict[SSAStorage, int] = {}
    stacks: dict[SSAStorage, list[SSAValue | None]] = {}
    entry_definitions: list[SSAValue] = []
    entry_storages: set[SSAStorage] = set()
    for parameter in function.parameters:
        storage = _storage_for_variable(parameter)
        if storage in entry_storages:
            raise ValueError("function parameters contain duplicate SSA storage")
        entry_storages.add(storage)
        value = _new_value(storage, (), counters)
        stacks.setdefault(storage, []).append(value)
        entry_definitions.append(value)

    renamed_statements: dict[int, tuple[SSAStatement, ...]] = {}
    phi_outputs: dict[tuple[int, SSAStorage], SSAValue] = {}
    phi_inputs: dict[
        tuple[int, SSAStorage],
        dict[int, SSAValue | None],
    ] = {}

    def rename_block(address: int) -> None:
        pushed: list[SSAStorage] = []
        for storage in sorted(phi_storages[address], key=_storage_sort_key):
            output = _new_value(storage, (), counters)
            phi_outputs[(address, storage)] = output
            stacks.setdefault(storage, []).append(output)
            pushed.append(storage)

        block = blocks_by_address[address]
        statements: list[SSAStatement] = []
        for statement in block.statements:
            statements.append(
                _rename_statement(statement, stacks, counters, pushed)
            )
        renamed_statements[address] = tuple(statements)

        for successor in successors[address]:
            if successor not in reachable:
                continue
            for storage in sorted(
                phi_storages[successor],
                key=_storage_sort_key,
            ):
                phi_inputs.setdefault((successor, storage), {})[address] = (
                    _current_value(storage, stacks)
                )

        for child in children[address]:
            rename_block(child)

        for storage in reversed(pushed):
            stack = stacks[storage]
            stack.pop()
            if not stack:
                stacks.pop(storage)

    rename_block(function.address)

    # Unreachable blocks are retained for conservative fallback rendering, but
    # processed only after reachable SSA so they cannot perturb reachable versions.
    for block in sorted(function.blocks, key=lambda candidate: candidate.address):
        if block.address in reachable:
            continue
        local_stacks: dict[SSAStorage, list[SSAValue | None]] = {}
        local_pushed: list[SSAStorage] = []
        statements: list[SSAStatement] = []
        for statement in block.statements:
            statements.append(
                _rename_statement(
                    statement,
                    local_stacks,
                    counters,
                    local_pushed,
                )
            )
        renamed_statements[block.address] = tuple(statements)

    result_blocks: list[SSABlock] = []
    for block in sorted(function.blocks, key=lambda candidate: candidate.address):
        phis: list[PhiNode] = []
        if block.address in reachable:
            for storage in sorted(
                phi_storages[block.address],
                key=_storage_sort_key,
            ):
                output = phi_outputs[(block.address, storage)]
                incoming = phi_inputs.get((block.address, storage), {})
                phis.append(
                    PhiNode(
                        output,
                        tuple(
                            PhiInput(
                                predecessor,
                                incoming.get(predecessor),
                            )
                            for predecessor in predecessors[block.address]
                        ),
                    )
                )
        result_blocks.append(
            SSABlock(
                block.address,
                block.instruction_set,
                tuple(phis),
                renamed_statements[block.address],
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
        blocks=tuple(result_blocks),
        entry_definitions=tuple(entry_definitions),
        warnings=function.warnings,
    )



def _expression_values(expression: SSAExpression) -> tuple[SSAValue, ...]:
    values: list[SSAValue] = []

    def visit(current: SSAExpression) -> None:
        if isinstance(current, SSAReferenceExpression):
            if current.value is not None:
                values.append(current.value)
            return
        if isinstance(current, SSAUnaryExpression):
            visit(current.operand)
            return
        if isinstance(current, SSABinaryExpression | SSACompareExpression):
            visit(current.left)
            visit(current.right)
            return
        if isinstance(current, SSAMemoryReadExpression):
            visit(current.address)
            return
        if isinstance(current, SSACallExpression):
            for argument in current.arguments:
                visit(argument)

    visit(expression)
    return tuple(values)


def _statement_values(statement: SSAStatement) -> tuple[SSAValue, ...]:
    if isinstance(statement, SSAAssignmentStatement):
        return _expression_values(statement.value)
    if isinstance(statement, SSAMemoryWriteStatement):
        return (
            *_expression_values(statement.address),
            *_expression_values(statement.value),
        )
    if isinstance(statement, SSACallStatement):
        return _expression_values(statement.call)
    if isinstance(statement, SSAReturnStatement):
        return () if statement.value is None else _expression_values(statement.value)
    if isinstance(statement, SSABranchStatement):
        return (
            ()
            if statement.condition is None
            else _expression_values(statement.condition)
        )
    return ()


def build_def_use_index(function: SSAFunction) -> DefUseIndex:
    definitions: list[SSADefinition] = [
        SSADefinition(
            value=value,
            kind=SSADefinitionKind.ENTRY,
            block_address=function.address,
            statement_index=None,
        )
        for value in function.entry_definitions
    ]
    uses: list[SSAUse] = []
    phi_records: list[tuple[int, PhiNode]] = []

    for block in function.blocks:
        for phi in block.phis:
            definitions.append(
                SSADefinition(
                    value=phi.output,
                    kind=SSADefinitionKind.PHI,
                    block_address=block.address,
                    statement_index=None,
                )
            )
            phi_records.append((block.address, phi))
            for incoming in phi.inputs:
                if incoming.value is None:
                    continue
                uses.append(
                    SSAUse(
                        value=incoming.value,
                        block_address=block.address,
                        statement_index=None,
                        phi_predecessor_address=incoming.predecessor_address,
                    )
                )

        for statement_index, statement in enumerate(block.statements):
            if isinstance(statement, SSAAssignmentStatement):
                definitions.append(
                    SSADefinition(
                        value=statement.target,
                        kind=SSADefinitionKind.ASSIGNMENT,
                        block_address=block.address,
                        statement_index=statement_index,
                    )
                )
            elif (
                isinstance(statement, SSACallStatement)
                and statement.result is not None
            ):
                definitions.append(
                    SSADefinition(
                        value=statement.result,
                        kind=SSADefinitionKind.CALL_RESULT,
                        block_address=block.address,
                        statement_index=statement_index,
                    )
                )
            for value in _statement_values(statement):
                uses.append(
                    SSAUse(
                        value=value,
                        block_address=block.address,
                        statement_index=statement_index,
                    )
                )

    return DefUseIndex(
        definitions=tuple(definitions),
        use_records=tuple(uses),
        phi_records=tuple(phi_records),
    )
