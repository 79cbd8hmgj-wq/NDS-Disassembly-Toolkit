from __future__ import annotations

from dataclasses import dataclass, field

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    AssignmentStatement,
    BinaryExpression,
    BranchStatement,
    CallExpression,
    CallStatement,
    CompareExpression,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    DecompilerExpression,
    DecompilerStatement,
    DecompilerVariable,
    DecompilerVariableKind,
    FieldAddressExpression,
    MemoryReadExpression,
    MemoryWriteStatement,
    RegisterExpression,
    ReturnStatement,
    UnaryExpression,
    UnknownExpression,
    UnknownStatement,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.access_paths import normalize_access_path
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
    SSAStatement,
    SSAStorage,
    SSAStorageKind,
    SSAUnaryExpression,
    SSAValue,
)
from nds_disassembly_toolkit.analysis.decompiler.structure_recovery import (
    canonical_pointer_root,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    LocalTypeEnvironment,
)


@dataclass(slots=True)
class _LoweringContext:
    function: SSAFunction
    type_environment: LocalTypeEnvironment | None = None
    entry_variables: dict[SSAValue, DecompilerVariable] = field(default_factory=dict)
    storage_variables: dict[SSAStorage, DecompilerVariable] = field(default_factory=dict)
    extra_locals: list[DecompilerVariable] = field(default_factory=list)


def _parameter_storage(variable: DecompilerVariable) -> SSAStorage | None:
    if variable.register is not None:
        return SSAStorage(SSAStorageKind.REGISTER, register=variable.register)
    if variable.stack_offset is not None:
        return SSAStorage(SSAStorageKind.STACK, stack_offset=variable.stack_offset)
    return None


def _make_context(
    function: SSAFunction,
    type_environment: LocalTypeEnvironment | None = None,
) -> _LoweringContext:
    context = _LoweringContext(
        function=function,
        type_environment=type_environment,
    )
    entry_by_storage = {
        value.storage: value
        for value in function.entry_definitions
    }
    for parameter in function.parameters:
        storage = _parameter_storage(parameter)
        if storage is None:
            continue
        entry = entry_by_storage.get(storage)
        if entry is not None:
            context.entry_variables[entry] = parameter
        if storage.kind is SSAStorageKind.STACK:
            context.storage_variables[storage] = parameter

    for variable in function.locals:
        if variable.stack_offset is not None:
            context.storage_variables[
                SSAStorage(
                    SSAStorageKind.STACK,
                    stack_offset=variable.stack_offset,
                )
            ] = variable
        elif variable.kind is DecompilerVariableKind.TEMPORARY:
            context.storage_variables[
                SSAStorage(
                    SSAStorageKind.TEMPORARY,
                    temporary_name=variable.name,
                )
            ] = variable
    return context


def _variable_for_storage(
    storage: SSAStorage,
    context: _LoweringContext,
) -> DecompilerVariable:
    existing = context.storage_variables.get(storage)
    if existing is not None:
        return existing

    if storage.kind is SSAStorageKind.STACK:
        assert storage.stack_offset is not None
        offset = storage.stack_offset
        prefix = "local" if offset < 0 else "stack"
        variable = DecompilerVariable(
            f"{prefix}_{abs(offset):02x}",
            DecompilerVariableKind.LOCAL,
            stack_offset=offset,
        )
    elif storage.kind is SSAStorageKind.TEMPORARY:
        assert storage.temporary_name is not None
        variable = DecompilerVariable(
            storage.temporary_name,
            DecompilerVariableKind.TEMPORARY,
        )
    else:
        raise ValueError("register storage does not require a source variable")

    context.storage_variables[storage] = variable
    context.extra_locals.append(variable)
    return variable


def _reference_expression(
    reference: SSAReferenceExpression,
    context: _LoweringContext,
) -> DecompilerExpression:
    if reference.value is None:
        storage = reference.storage
        if storage.kind is SSAStorageKind.REGISTER:
            assert storage.register is not None
            return RegisterExpression(storage.register, reference.source)
        return VariableExpression(
            _variable_for_storage(storage, context),
            reference.source,
        )

    entry_variable = context.entry_variables.get(reference.value)
    if entry_variable is not None:
        return VariableExpression(entry_variable, reference.source)

    storage = reference.value.storage
    if storage.kind is SSAStorageKind.REGISTER:
        assert storage.register is not None
        return RegisterExpression(storage.register, reference.source)

    return VariableExpression(
        _variable_for_storage(storage, context),
        reference.source,
    )


def _typed_field_address(
    address: SSAExpression,
    *,
    width: int,
    source: tuple,
    context: _LoweringContext,
) -> FieldAddressExpression | None:
    environment = context.type_environment
    if environment is None:
        return None

    path = normalize_access_path(address)
    if (
        path is None
        or path.byte_offset < 0
        or path.index is not None
    ):
        return None

    root = canonical_pointer_root(context.function, path.root)
    for candidate in environment.structures.candidates:
        if (
            candidate.root != root
            or not candidate.should_render
            or candidate.conflicts
        ):
            continue
        for field in candidate.fields:
            if (
                field.offset != path.byte_offset
                or field.width_bytes != width
            ):
                continue
            base = _reference_expression(
                SSAReferenceExpression(
                    root.storage,
                    root,
                    address.source,
                ),
                context,
            )
            return FieldAddressExpression(
                base=base,
                structure_name=candidate.name,
                field_name=field.name,
                offset=field.offset,
                width=field.width_bytes,
                source=source,
            )
    return None


def _lower_expression(
    expression: SSAExpression,
    context: _LoweringContext,
) -> DecompilerExpression:
    if isinstance(expression, ConstantExpression | AddressExpression | UnknownExpression):
        return expression
    if isinstance(expression, SSAReferenceExpression):
        return _reference_expression(expression, context)
    if isinstance(expression, SSAUnaryExpression):
        return UnaryExpression(
            expression.operator,
            _lower_expression(expression.operand, context),
            expression.source,
        )
    if isinstance(expression, SSABinaryExpression):
        return BinaryExpression(
            expression.operator,
            _lower_expression(expression.left, context),
            _lower_expression(expression.right, context),
            expression.source,
        )
    if isinstance(expression, SSACompareExpression):
        return CompareExpression(
            expression.condition,
            _lower_expression(expression.left, context),
            _lower_expression(expression.right, context),
            expression.source,
        )
    if isinstance(expression, SSAMemoryReadExpression):
        typed_address = _typed_field_address(
            expression.address,
            width=expression.width,
            source=expression.source,
            context=context,
        )
        return MemoryReadExpression(
            (
                typed_address
                if typed_address is not None
                else _lower_expression(expression.address, context)
            ),
            expression.width,
            expression.source,
        )
    if isinstance(expression, SSACallExpression):
        return CallExpression(
            expression.name,
            expression.target_address,
            expression.target_instruction_set,
            expression.target_component,
            tuple(
                _lower_expression(argument, context)
                for argument in expression.arguments
            ),
            expression.source,
        )
    raise TypeError(f"unsupported SSA expression: {type(expression).__name__}")


def _target_expression(
    target: SSAValue,
    context: _LoweringContext,
) -> VariableExpression | RegisterExpression:
    storage = target.storage
    if storage.kind is SSAStorageKind.REGISTER:
        assert storage.register is not None
        return RegisterExpression(storage.register, target.source)
    return VariableExpression(
        _variable_for_storage(storage, context),
        target.source,
    )


def _lower_statement(
    statement: SSAStatement,
    context: _LoweringContext,
) -> DecompilerStatement:
    if isinstance(statement, SSAAssignmentStatement):
        return AssignmentStatement(
            _target_expression(statement.target, context),
            _lower_expression(statement.value, context),
            statement.source,
        )
    if isinstance(statement, SSAMemoryWriteStatement):
        typed_address = _typed_field_address(
            statement.address,
            width=statement.width,
            source=statement.source,
            context=context,
        )
        return MemoryWriteStatement(
            (
                typed_address
                if typed_address is not None
                else _lower_expression(statement.address, context)
            ),
            _lower_expression(statement.value, context),
            statement.width,
            statement.source,
        )
    if isinstance(statement, SSACallStatement):
        call = _lower_expression(statement.call, context)
        if not isinstance(call, CallExpression):
            raise TypeError("SSA call statement lowered to non-call expression")
        return CallStatement(call, statement.source)
    if isinstance(statement, SSAReturnStatement):
        return ReturnStatement(
            (
                None
                if statement.value is None
                else _lower_expression(statement.value, context)
            ),
            statement.source,
        )
    if isinstance(statement, SSABranchStatement):
        return BranchStatement(
            (
                None
                if statement.condition is None
                else _lower_expression(statement.condition, context)
            ),
            statement.target_address,
            statement.target_instruction_set,
            statement.source,
        )
    if isinstance(statement, UnknownStatement):
        return statement
    raise TypeError(f"unsupported SSA statement: {type(statement).__name__}")


def lower_ssa_function(
    function: SSAFunction,
    *,
    type_environment: LocalTypeEnvironment | None = None,
) -> DecompiledFunction:
    context = _make_context(function, type_environment)
    blocks = tuple(
        DecompiledBlock(
            block.address,
            block.instruction_set,
            tuple(
                _lower_statement(statement, context)
                for statement in block.statements
            ),
            block.edges,
        )
        for block in function.blocks
    )

    locals_by_name = {variable.name: variable for variable in function.locals}
    for variable in context.extra_locals:
        locals_by_name.setdefault(variable.name, variable)

    return DecompiledFunction(
        component=function.component,
        address=function.address,
        instruction_set=function.instruction_set,
        name=function.name,
        parameters=function.parameters,
        locals=tuple(
            locals_by_name[name]
            for name in sorted(locals_by_name)
        ),
        blocks=blocks,
        warnings=function.warnings,
    )
