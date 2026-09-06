from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TypeVar

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    ConstantExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAExpression,
    SSAFunction,
    SSACallExpression,
    SSACallStatement,
    SSAMemoryReadExpression,
    SSAReferenceExpression,
    SSAReturnStatement,
    SSAValue,
    build_def_use_index,
)
from nds_disassembly_toolkit.analysis.decompiler.structure_recovery import (
    canonical_pointer_root,
)
from nds_disassembly_toolkit.analysis.decompiler.type_model import (
    IntegerType,
    PointerType,
    RecoveredSignedness,
    RecoveredStructType,
    RecoveredType,
    UnknownType,
    VoidType,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    FunctionTypeIdentity,
    LocalTypeEnvironment,
)
from nds_disassembly_toolkit.analysis.model import Register


@dataclass(frozen=True, slots=True)
class PrototypeParameter:
    position: int
    name: str
    register: Register | None
    stack_offset: int | None
    recovered_type: RecoveredType

    def __post_init__(self) -> None:
        if self.position < 0:
            raise ValueError("prototype parameter position must be non-negative")
        if not self.name:
            raise ValueError("prototype parameter name cannot be empty")
        if (self.register is None) == (self.stack_offset is None):
            raise ValueError(
                "prototype parameter requires exactly one ABI location"
            )


@dataclass(frozen=True, slots=True)
class FunctionPrototype:
    identity: FunctionTypeIdentity
    name: str
    parameters: tuple[PrototypeParameter, ...]
    return_type: RecoveredType
    conflicts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("function prototype name cannot be empty")
        positions = tuple(parameter.position for parameter in self.parameters)
        if positions != tuple(sorted(positions)) or len(positions) != len(set(positions)):
            raise ValueError(
                "prototype parameters must have unique ordered positions"
            )
        object.__setattr__(
            self,
            "conflicts",
            tuple(sorted(set(self.conflicts))),
        )


def _type_name(value: RecoveredType) -> str:
    return value.kind.value


def merge_recovered_types(
    left: RecoveredType,
    right: RecoveredType,
) -> tuple[RecoveredType, tuple[str, ...]]:
    if isinstance(left, UnknownType):
        return right, ()
    if isinstance(right, UnknownType):
        return left, ()

    if isinstance(left, VoidType) or isinstance(right, VoidType):
        if isinstance(left, VoidType) and isinstance(right, VoidType):
            return VoidType(), ()
        return UnknownType(), ("type conflict: void and value",)

    if isinstance(left, IntegerType) and isinstance(right, IntegerType):
        if left.width_bytes != right.width_bytes:
            return (
                UnknownType(),
                (
                    "return type conflict: integer widths "
                    f"{left.width_bytes} and {right.width_bytes}",
                ),
            )
        signedness = (
            left.signedness
            if left.signedness is right.signedness
            else RecoveredSignedness.UNKNOWN
        )
        return IntegerType(left.width_bytes, signedness), ()

    if isinstance(left, PointerType) and isinstance(right, PointerType):
        if (
            left.pointee_name is not None
            and right.pointee_name is not None
            and left.pointee_name != right.pointee_name
        ):
            return (
                UnknownType(),
                (
                    "pointer pointee conflict: "
                    f"{left.pointee_name} vs {right.pointee_name}",
                ),
            )
        if (
            left.component is not None
            and right.component is not None
            and left.component != right.component
        ):
            return (
                UnknownType(),
                (
                    "pointer component conflict: "
                    f"{left.component} vs {right.component}",
                ),
            )
        return (
            PointerType(
                pointee_name=left.pointee_name or right.pointee_name,
                component=left.component or right.component,
            ),
            (),
        )

    if isinstance(left, RecoveredStructType) and isinstance(
        right,
        RecoveredStructType,
    ):
        if left == right:
            return left, ()
        return (
            UnknownType(),
            (
                "recovered structure conflict: "
                f"{left.name} vs {right.name}",
            ),
        )

    if left == right:
        return left, ()

    return (
        UnknownType(),
        (
            "incompatible recovered types: "
            f"{_type_name(left)} vs {_type_name(right)}",
        ),
    )


def _return_expression_type(
    expression: SSAExpression,
    environment: LocalTypeEnvironment,
) -> RecoveredType:
    if isinstance(expression, ConstantExpression):
        return IntegerType(4, RecoveredSignedness.UNKNOWN)
    if isinstance(expression, AddressExpression):
        return PointerType(component=expression.component)
    if isinstance(expression, SSAReferenceExpression):
        if expression.value is None:
            return UnknownType()
        recovered = environment.type_for_value(expression.value)
        return recovered if recovered is not None else UnknownType()
    if isinstance(expression, SSAMemoryReadExpression):
        return IntegerType(
            expression.width,
            RecoveredSignedness.UNKNOWN,
        )
    return UnknownType()


def _recover_return_type(
    function: SSAFunction,
    environment: LocalTypeEnvironment,
) -> tuple[RecoveredType, tuple[str, ...]]:
    returns = tuple(
        statement
        for block in sorted(function.blocks, key=lambda item: item.address)
        for statement in block.statements
        if isinstance(statement, SSAReturnStatement)
    )
    if not returns:
        return UnknownType(), ()

    void_count = sum(statement.value is None for statement in returns)
    if void_count == len(returns):
        return VoidType(), ()
    if void_count:
        return (
            UnknownType(),
            ("return type conflict: void and value returns",),
        )

    recovered: RecoveredType = UnknownType()
    conflicts: list[str] = []
    for statement in returns:
        assert statement.value is not None
        candidate = _return_expression_type(
            statement.value,
            environment,
        )
        merged, merge_conflicts = merge_recovered_types(
            recovered,
            candidate,
        )
        recovered = merged
        conflicts.extend(merge_conflicts)

    if conflicts:
        recovered = UnknownType()
    return recovered, tuple(sorted(set(conflicts)))


def recover_local_prototype(
    function: SSAFunction,
    environment: LocalTypeEnvironment,
) -> FunctionPrototype:
    parameters: list[PrototypeParameter] = []
    for position, variable in enumerate(function.parameters):
        recovered: RecoveredType = UnknownType()
        if position < len(function.entry_definitions):
            candidate = environment.type_for_value(
                function.entry_definitions[position]
            )
            if candidate is not None:
                recovered = candidate
        parameters.append(
            PrototypeParameter(
                position=position,
                name=variable.name,
                register=variable.register,
                stack_offset=variable.stack_offset,
                recovered_type=recovered,
            )
        )

    return_type, conflicts = _recover_return_type(
        function,
        environment,
    )
    return FunctionPrototype(
        identity=FunctionTypeIdentity(
            function.component,
            function.address,
            function.instruction_set,
        ),
        name=function.name,
        parameters=tuple(parameters),
        return_type=return_type,
        conflicts=conflicts,
    )



@dataclass(frozen=True, slots=True)
class PrototypePropagationResult:
    prototypes: tuple[FunctionPrototype, ...]
    value_types: tuple[
        tuple[FunctionTypeIdentity, SSAValue, RecoveredType],
        ...,
    ]
    converged: bool
    iterations: int
    warnings: tuple[str, ...] = ()

    def prototype_for(
        self,
        identity: FunctionTypeIdentity,
    ) -> FunctionPrototype | None:
        for prototype in self.prototypes:
            if prototype.identity == identity:
                return prototype
        return None

    def type_for_value(
        self,
        identity: FunctionTypeIdentity,
        value: SSAValue,
    ) -> RecoveredType | None:
        for candidate_identity, candidate, recovered in self.value_types:
            if candidate_identity == identity and candidate == value:
                return recovered
        return None


_ValueKey = tuple[FunctionTypeIdentity, SSAValue]
_ParameterKey = tuple[FunctionTypeIdentity, int]


def _identity_sort_key(
    identity: FunctionTypeIdentity,
) -> tuple[object, ...]:
    return (
        identity.component,
        identity.address,
        identity.instruction_set.value,
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


def _value_key_sort_key(key: _ValueKey) -> tuple[object, ...]:
    identity, value = key
    return (*_identity_sort_key(identity), *_value_sort_key(value))


def _parameter_key_sort_key(
    key: _ParameterKey,
) -> tuple[object, ...]:
    identity, position = key
    return (*_identity_sort_key(identity), position)


def _function_identity(
    function: SSAFunction,
) -> FunctionTypeIdentity:
    return FunctionTypeIdentity(
        function.component,
        function.address,
        function.instruction_set,
    )


def _resolve_call_target_identity(
    call: SSACallExpression,
    functions_by_identity: dict[FunctionTypeIdentity, SSAFunction],
) -> FunctionTypeIdentity | None:
    if call.target_component is not None:
        candidate = FunctionTypeIdentity(
            call.target_component,
            call.target_address,
            call.target_instruction_set,
        )
        return candidate if candidate in functions_by_identity else None

    matches = tuple(
        identity
        for identity in functions_by_identity
        if (
            identity.address == call.target_address
            and identity.instruction_set == call.target_instruction_set
        )
    )
    if len(matches) != 1:
        return None
    return matches[0]


@dataclass(frozen=True, slots=True)
class _ArgumentConstraint:
    caller_identity: FunctionTypeIdentity
    caller_value: SSAValue
    callee_identity: FunctionTypeIdentity
    parameter_position: int
    callee_value: SSAValue


@dataclass(frozen=True, slots=True)
class _CallReturnConstraint:
    callee_identity: FunctionTypeIdentity
    caller_identity: FunctionTypeIdentity
    caller_result: SSAValue


@dataclass(frozen=True, slots=True)
class _LocalReturnConstraint:
    identity: FunctionTypeIdentity
    returned_value: SSAValue


def _build_constraints(
    functions: tuple[SSAFunction, ...],
    functions_by_identity: dict[FunctionTypeIdentity, SSAFunction],
) -> tuple[
    tuple[_ArgumentConstraint, ...],
    tuple[_CallReturnConstraint, ...],
    tuple[_LocalReturnConstraint, ...],
]:
    arguments: list[_ArgumentConstraint] = []
    call_returns: list[_CallReturnConstraint] = []
    local_returns: list[_LocalReturnConstraint] = []

    for function in functions:
        identity = _function_identity(function)
        index = build_def_use_index(function)

        for block in sorted(function.blocks, key=lambda item: item.address):
            for statement in block.statements:
                if isinstance(statement, SSAReturnStatement):
                    if (
                        isinstance(statement.value, SSAReferenceExpression)
                        and statement.value.value is not None
                    ):
                        local_returns.append(
                            _LocalReturnConstraint(
                                identity=identity,
                                returned_value=canonical_pointer_root(
                                    function,
                                    statement.value.value,
                                    index=index,
                                ),
                            )
                        )
                    continue

                if not isinstance(statement, SSACallStatement):
                    continue
                target_identity = _resolve_call_target_identity(
                    statement.call,
                    functions_by_identity,
                )
                if target_identity is None:
                    continue
                callee = functions_by_identity[target_identity]
                callee_index = build_def_use_index(callee)

                for position, argument in enumerate(
                    statement.call.arguments
                ):
                    if (
                        position >= len(callee.entry_definitions)
                        or not isinstance(argument, SSAReferenceExpression)
                        or argument.value is None
                    ):
                        continue
                    arguments.append(
                        _ArgumentConstraint(
                            caller_identity=identity,
                            caller_value=canonical_pointer_root(
                                function,
                                argument.value,
                                index=index,
                            ),
                            callee_identity=target_identity,
                            parameter_position=position,
                            callee_value=canonical_pointer_root(
                                callee,
                                callee.entry_definitions[position],
                                index=callee_index,
                            ),
                        )
                    )

                if statement.result is not None:
                    call_returns.append(
                        _CallReturnConstraint(
                            callee_identity=target_identity,
                            caller_identity=identity,
                            caller_result=statement.result,
                        )
                    )

    arguments.sort(
        key=lambda item: (
            *_identity_sort_key(item.caller_identity),
            *_value_sort_key(item.caller_value),
            *_identity_sort_key(item.callee_identity),
            item.parameter_position,
            *_value_sort_key(item.callee_value),
        )
    )
    call_returns.sort(
        key=lambda item: (
            *_identity_sort_key(item.callee_identity),
            *_identity_sort_key(item.caller_identity),
            *_value_sort_key(item.caller_result),
        )
    )
    local_returns.sort(
        key=lambda item: (
            *_identity_sort_key(item.identity),
            *_value_sort_key(item.returned_value),
        )
    )
    return tuple(arguments), tuple(call_returns), tuple(local_returns)


def _merge_pair(
    left: RecoveredType,
    right: RecoveredType,
) -> tuple[RecoveredType, tuple[str, ...]]:
    return merge_recovered_types(left, right)


def _record_conflicts(
    conflicts: dict[FunctionTypeIdentity, set[str]],
    identities: tuple[FunctionTypeIdentity, ...],
    prefix: str,
    messages: tuple[str, ...],
) -> None:
    if not messages:
        return
    for identity in identities:
        target = conflicts.setdefault(identity, set())
        target.update(f"{prefix}: {message}" for message in messages)


def propagate_prototypes(
    functions: tuple[SSAFunction, ...],
    environments: tuple[LocalTypeEnvironment, ...],
    *,
    iteration_cap: int = 32,
) -> PrototypePropagationResult:
    if iteration_cap <= 0:
        raise ValueError("prototype propagation iteration cap must be positive")
    if len(functions) != len(environments):
        raise ValueError("functions and type environments must align")

    functions_by_identity: dict[FunctionTypeIdentity, SSAFunction] = {}
    environments_by_identity: dict[
        FunctionTypeIdentity,
        LocalTypeEnvironment,
    ] = {}
    prototypes_by_identity: dict[
        FunctionTypeIdentity,
        FunctionPrototype,
    ] = {}

    for function, environment in zip(
        functions,
        environments,
        strict=True,
    ):
        identity = _function_identity(function)
        if identity in functions_by_identity:
            raise ValueError("duplicate function prototype identity")
        functions_by_identity[identity] = function
        environments_by_identity[identity] = environment
        prototypes_by_identity[identity] = recover_local_prototype(
            function,
            environment,
        )

    ordered_functions = tuple(
        functions_by_identity[identity]
        for identity in sorted(
            functions_by_identity,
            key=_identity_sort_key,
        )
    )
    (
        argument_constraints,
        call_return_constraints,
        local_return_constraints,
    ) = _build_constraints(
        ordered_functions,
        functions_by_identity,
    )

    parameter_types: dict[_ParameterKey, RecoveredType] = {}
    return_types: dict[FunctionTypeIdentity, RecoveredType] = {}
    value_types: dict[_ValueKey, RecoveredType] = {}
    conflicts: dict[FunctionTypeIdentity, set[str]] = {
        identity: set(prototype.conflicts)
        for identity, prototype in prototypes_by_identity.items()
    }
    locked_return_conflicts = {
        identity
        for identity, prototype in prototypes_by_identity.items()
        if prototype.conflicts
    }
    parameter_conflicts: set[_ParameterKey] = set()
    return_conflicts: set[FunctionTypeIdentity] = set(
        locked_return_conflicts
    )
    value_conflicts: set[_ValueKey] = set()

    for identity, prototype in prototypes_by_identity.items():
        return_types[identity] = prototype.return_type
        function = functions_by_identity[identity]
        for parameter in prototype.parameters:
            key = (identity, parameter.position)
            parameter_types[key] = parameter.recovered_type
            if parameter.position < len(function.entry_definitions):
                value_types[
                    (identity, function.entry_definitions[parameter.position])
                ] = parameter.recovered_type

    for identity, environment in environments_by_identity.items():
        for binding in environment.value_bindings:
            key = (identity, binding.value)
            current = value_types.get(key, UnknownType())
            merged, messages = _merge_pair(
                current,
                binding.recovered_type,
            )
            if messages:
                value_conflicts.add(key)
                value_types[key] = UnknownType()
            else:
                value_types[key] = merged
            _record_conflicts(
                conflicts,
                (identity,),
                "local value",
                messages,
            )

    for constraint in call_return_constraints:
        value_types.setdefault(
            (
                constraint.caller_identity,
                constraint.caller_result,
            ),
            UnknownType(),
        )

    for constraint in local_return_constraints:
        value_types.setdefault(
            (constraint.identity, constraint.returned_value),
            UnknownType(),
        )

    for iteration in range(1, iteration_cap + 1):
        next_parameters = dict(parameter_types)
        next_returns = dict(return_types)
        next_values = dict(value_types)
        next_conflicts = {
            identity: set(messages)
            for identity, messages in conflicts.items()
        }
        next_parameter_conflicts = set(parameter_conflicts)
        next_return_conflicts = set(return_conflicts)
        next_value_conflicts = set(value_conflicts)

        # Keep each parameter slot and its entry SSA value equivalent.
        for identity, function in functions_by_identity.items():
            for position in range(
                min(
                    len(function.parameters),
                    len(function.entry_definitions),
                )
            ):
                parameter_key = (identity, position)
                value_key = (
                    identity,
                    function.entry_definitions[position],
                )
                left = parameter_types.get(
                    parameter_key,
                    UnknownType(),
                )
                right = value_types.get(
                    value_key,
                    UnknownType(),
                )
                merged, messages = _merge_pair(left, right)
                resolved = UnknownType() if messages else merged
                parameter_messages = _accumulate_type(
                    next_parameters,
                    parameter_key,
                    resolved,
                    poisoned=next_parameter_conflicts,
                    source_conflicts=messages,
                )
                value_messages = _accumulate_type(
                    next_values,
                    value_key,
                    resolved,
                    poisoned=next_value_conflicts,
                    source_conflicts=messages,
                )
                _record_conflicts(
                    next_conflicts,
                    (identity,),
                    f"parameter {position}",
                    tuple(
                        sorted(
                            set(
                                (
                                    *messages,
                                    *parameter_messages,
                                    *value_messages,
                                )
                            )
                        )
                    ),
                )

        # Returned SSA values constrain the function return type.
        for constraint in local_return_constraints:
            if constraint.identity in locked_return_conflicts:
                continue
            return_type = return_types.get(
                constraint.identity,
                UnknownType(),
            )
            value_key = (
                constraint.identity,
                constraint.returned_value,
            )
            value_type = value_types.get(
                value_key,
                UnknownType(),
            )
            merged, messages = _merge_pair(
                return_type,
                value_type,
            )
            resolved = UnknownType() if messages else merged
            return_messages = _accumulate_type(
                next_returns,
                constraint.identity,
                resolved,
                poisoned=next_return_conflicts,
                source_conflicts=messages,
            )
            value_messages = _accumulate_type(
                next_values,
                value_key,
                resolved,
                poisoned=next_value_conflicts,
                source_conflicts=messages,
            )
            _record_conflicts(
                next_conflicts,
                (constraint.identity,),
                "return value",
                tuple(
                    sorted(
                        set(
                            (
                                *messages,
                                *return_messages,
                                *value_messages,
                            )
                        )
                    )
                ),
            )

        # Caller argument values and callee parameter slots are equivalent.
        for constraint in argument_constraints:
            caller_key = (
                constraint.caller_identity,
                constraint.caller_value,
            )
            parameter_key = (
                constraint.callee_identity,
                constraint.parameter_position,
            )
            caller_type = value_types.get(
                caller_key,
                UnknownType(),
            )
            callee_type = parameter_types.get(
                parameter_key,
                UnknownType(),
            )
            merged, messages = _merge_pair(
                caller_type,
                callee_type,
            )
            resolved = UnknownType() if messages else merged
            callee_value_key = (
                constraint.callee_identity,
                constraint.callee_value,
            )
            caller_messages = _accumulate_type(
                next_values,
                caller_key,
                resolved,
                poisoned=next_value_conflicts,
                source_conflicts=messages,
            )
            parameter_messages = _accumulate_type(
                next_parameters,
                parameter_key,
                resolved,
                poisoned=next_parameter_conflicts,
                source_conflicts=messages,
            )
            callee_value_messages = _accumulate_type(
                next_values,
                callee_value_key,
                resolved,
                poisoned=next_value_conflicts,
                source_conflicts=messages,
            )
            _record_conflicts(
                next_conflicts,
                (
                    constraint.caller_identity,
                    constraint.callee_identity,
                ),
                f"call parameter {constraint.parameter_position}",
                tuple(
                    sorted(
                        set(
                            (
                                *messages,
                                *caller_messages,
                                *parameter_messages,
                                *callee_value_messages,
                            )
                        )
                    )
                ),
            )

        # Callee return type and caller r0 call-result definition are equivalent.
        for constraint in call_return_constraints:
            if constraint.callee_identity in locked_return_conflicts:
                continue
            caller_key = (
                constraint.caller_identity,
                constraint.caller_result,
            )
            callee_type = return_types.get(
                constraint.callee_identity,
                UnknownType(),
            )
            caller_type = value_types.get(
                caller_key,
                UnknownType(),
            )
            merged, messages = _merge_pair(
                callee_type,
                caller_type,
            )
            resolved = UnknownType() if messages else merged
            return_messages = _accumulate_type(
                next_returns,
                constraint.callee_identity,
                resolved,
                poisoned=next_return_conflicts,
                source_conflicts=messages,
            )
            value_messages = _accumulate_type(
                next_values,
                caller_key,
                resolved,
                poisoned=next_value_conflicts,
                source_conflicts=messages,
            )
            _record_conflicts(
                next_conflicts,
                (
                    constraint.callee_identity,
                    constraint.caller_identity,
                ),
                "call return",
                tuple(
                    sorted(
                        set(
                            (
                                *messages,
                                *return_messages,
                                *value_messages,
                            )
                        )
                    )
                ),
            )

        if (
            next_parameters == parameter_types
            and next_returns == return_types
            and next_values == value_types
            and next_conflicts == conflicts
            and next_parameter_conflicts == parameter_conflicts
            and next_return_conflicts == return_conflicts
            and next_value_conflicts == value_conflicts
        ):
            return _prototype_propagation_result(
                functions_by_identity,
                prototypes_by_identity,
                next_parameters,
                next_returns,
                next_values,
                next_conflicts,
                converged=True,
                iterations=iteration,
            )

        parameter_types = next_parameters
        return_types = next_returns
        value_types = next_values
        conflicts = next_conflicts
        parameter_conflicts = next_parameter_conflicts
        return_conflicts = next_return_conflicts
        value_conflicts = next_value_conflicts

    return _prototype_propagation_result(
        functions_by_identity,
        prototypes_by_identity,
        parameter_types,
        return_types,
        value_types,
        conflicts,
        converged=False,
        iterations=iteration_cap,
        warnings=(
            f"prototype propagation reached iteration cap "
            f"{iteration_cap}",
        ),
    )


def _prototype_propagation_result(
    functions_by_identity: dict[FunctionTypeIdentity, SSAFunction],
    prototypes_by_identity: dict[
        FunctionTypeIdentity,
        FunctionPrototype,
    ],
    parameter_types: dict[_ParameterKey, RecoveredType],
    return_types: dict[FunctionTypeIdentity, RecoveredType],
    value_types: dict[_ValueKey, RecoveredType],
    conflicts: dict[FunctionTypeIdentity, set[str]],
    *,
    converged: bool,
    iterations: int,
    warnings: tuple[str, ...] = (),
) -> PrototypePropagationResult:
    prototypes: list[FunctionPrototype] = []
    for identity in sorted(
        prototypes_by_identity,
        key=_identity_sort_key,
    ):
        prototype = prototypes_by_identity[identity]
        parameters = tuple(
            replace(
                parameter,
                recovered_type=parameter_types.get(
                    (identity, parameter.position),
                    parameter.recovered_type,
                ),
            )
            for parameter in prototype.parameters
        )
        prototypes.append(
            replace(
                prototype,
                parameters=parameters,
                return_type=return_types.get(
                    identity,
                    prototype.return_type,
                ),
                conflicts=tuple(
                    sorted(
                        set(
                            (
                                *prototype.conflicts,
                                *conflicts.get(identity, set()),
                            )
                        )
                    )
                ),
            )
        )

    value_records = tuple(
        (
            identity,
            value,
            value_types[(identity, value)],
        )
        for identity, value in sorted(
            value_types,
            key=_value_key_sort_key,
        )
    )

    return PrototypePropagationResult(
        prototypes=tuple(prototypes),
        value_types=value_records,
        converged=converged,
        iterations=iterations,
        warnings=warnings,
    )



@dataclass(frozen=True, slots=True)
class PrototypePropagationResult:
    prototypes: tuple[FunctionPrototype, ...]
    value_types: tuple[
        tuple[FunctionTypeIdentity, SSAValue, RecoveredType],
        ...,
    ]
    converged: bool
    iterations: int
    warnings: tuple[str, ...] = ()

    def prototype_for(
        self,
        identity: FunctionTypeIdentity,
    ) -> FunctionPrototype | None:
        for prototype in self.prototypes:
            if prototype.identity == identity:
                return prototype
        return None

    def type_for_value(
        self,
        identity: FunctionTypeIdentity,
        value: SSAValue,
    ) -> RecoveredType | None:
        for candidate_identity, candidate_value, recovered in self.value_types:
            if candidate_identity == identity and candidate_value == value:
                return recovered
        return None


@dataclass(frozen=True, slots=True)
class _CallConstraint:
    caller: FunctionTypeIdentity
    callee: FunctionTypeIdentity
    statement: SSACallStatement


_ValueKey = tuple[FunctionTypeIdentity, SSAValue]


def _identity(function: SSAFunction) -> FunctionTypeIdentity:
    return FunctionTypeIdentity(
        function.component,
        function.address,
        function.instruction_set,
    )


def _identity_sort_key(
    identity: FunctionTypeIdentity,
) -> tuple[str, int, str]:
    return (
        identity.component,
        identity.address,
        identity.instruction_set.value,
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


def _value_key_sort_key(key: _ValueKey) -> tuple[object, ...]:
    identity, value = key
    return (*_identity_sort_key(identity), *_value_sort_key(value))


def _resolve_call_identity(
    call: SSACallStatement,
    functions: dict[FunctionTypeIdentity, SSAFunction],
) -> FunctionTypeIdentity | None:
    expression = call.call
    if expression.target_component is not None:
        candidate = FunctionTypeIdentity(
            expression.target_component,
            expression.target_address,
            expression.target_instruction_set,
        )
        return candidate if candidate in functions else None

    matches = tuple(
        identity
        for identity in functions
        if (
            identity.address == expression.target_address
            and identity.instruction_set
            is expression.target_instruction_set
        )
    )
    if len(matches) != 1:
        return None
    return matches[0]


def _call_constraints(
    functions: dict[FunctionTypeIdentity, SSAFunction],
) -> tuple[_CallConstraint, ...]:
    output: list[_CallConstraint] = []
    for caller in sorted(functions, key=_identity_sort_key):
        function = functions[caller]
        for block in sorted(function.blocks, key=lambda item: item.address):
            for statement in block.statements:
                if not isinstance(statement, SSACallStatement):
                    continue
                callee = _resolve_call_identity(statement, functions)
                if callee is None:
                    continue
                output.append(
                    _CallConstraint(
                        caller=caller,
                        callee=callee,
                        statement=statement,
                    )
                )
    return tuple(output)


def _expression_type_from_state(
    expression: SSAExpression,
    *,
    identity: FunctionTypeIdentity,
    value_types: dict[_ValueKey, RecoveredType],
    blocked_values: set[_ValueKey],
) -> RecoveredType:
    if isinstance(expression, ConstantExpression):
        return IntegerType(4, RecoveredSignedness.UNKNOWN)
    if isinstance(expression, AddressExpression):
        return PointerType(component=expression.component)
    if isinstance(expression, SSAReferenceExpression):
        if expression.value is None:
            return UnknownType()
        key = (identity, expression.value)
        if key in blocked_values:
            return UnknownType()
        return value_types.get(key, UnknownType())
    if isinstance(expression, SSAMemoryReadExpression):
        return IntegerType(
            expression.width,
            RecoveredSignedness.UNKNOWN,
        )
    return UnknownType()


def _parameter_type_from_state(
    function: SSAFunction,
    prototype: FunctionPrototype,
    position: int,
    value_types: dict[_ValueKey, RecoveredType],
    blocked_values: set[_ValueKey],
) -> RecoveredType:
    if position < len(function.entry_definitions):
        key = (prototype.identity, function.entry_definitions[position])
        if key in blocked_values:
            return UnknownType()
        return value_types.get(
            key,
            prototype.parameters[position].recovered_type,
        )
    return prototype.parameters[position].recovered_type


def _with_final_types(
    function: SSAFunction,
    base: FunctionPrototype,
    *,
    value_types: dict[_ValueKey, RecoveredType],
    blocked_values: set[_ValueKey],
    return_type: RecoveredType,
    conflicts: set[str],
) -> FunctionPrototype:
    parameters = tuple(
        replace(
            parameter,
            recovered_type=_parameter_type_from_state(
                function,
                base,
                parameter.position,
                value_types,
                blocked_values,
            ),
        )
        for parameter in base.parameters
    )
    return replace(
        base,
        parameters=parameters,
        return_type=return_type,
        conflicts=tuple(sorted(conflicts)),
    )


def _record_merge(
    left: RecoveredType,
    right: RecoveredType,
) -> tuple[RecoveredType, tuple[str, ...]]:
    return merge_recovered_types(left, right)


def _accumulate_type(
    existing: RecoveredType,
    candidate: RecoveredType,
) -> tuple[RecoveredType, tuple[str, ...]]:
    # UNKNOWN is absence of precision, not evidence that can erase a more
    # precise fact discovered by another constraint in the same iteration.
    return merge_recovered_types(existing, candidate)


def propagate_prototypes(
    functions: tuple[SSAFunction, ...],
    environments: tuple[LocalTypeEnvironment, ...],
    *,
    iteration_cap: int = 32,
) -> PrototypePropagationResult:
    if iteration_cap <= 0:
        raise ValueError("prototype propagation iteration cap must be positive")
    if len(functions) != len(environments):
        raise ValueError("functions and local type environments must align")

    function_map: dict[FunctionTypeIdentity, SSAFunction] = {}
    environment_map: dict[FunctionTypeIdentity, LocalTypeEnvironment] = {}
    base_prototypes: dict[FunctionTypeIdentity, FunctionPrototype] = {}

    for function, environment in zip(
        functions,
        environments,
        strict=True,
    ):
        identity = _identity(function)
        if identity in function_map:
            raise ValueError("duplicate function prototype identity")
        function_map[identity] = function
        environment_map[identity] = environment
        base_prototypes[identity] = recover_local_prototype(
            function,
            environment,
        )

    value_types: dict[_ValueKey, RecoveredType] = {}
    for identity in sorted(function_map, key=_identity_sort_key):
        environment = environment_map[identity]
        function = function_map[identity]
        prototype = base_prototypes[identity]

        for binding in environment.value_bindings:
            value_types[(identity, binding.value)] = binding.recovered_type

        for parameter in prototype.parameters:
            if parameter.position >= len(function.entry_definitions):
                continue
            key = (
                identity,
                function.entry_definitions[parameter.position],
            )
            value_types.setdefault(key, parameter.recovered_type)

        for block in function.blocks:
            for statement in block.statements:
                if (
                    isinstance(statement, SSACallStatement)
                    and statement.result is not None
                ):
                    value_types.setdefault(
                        (identity, statement.result),
                        UnknownType(),
                    )

    return_types = {
        identity: prototype.return_type
        for identity, prototype in base_prototypes.items()
    }
    conflicts = {
        identity: set(prototype.conflicts)
        for identity, prototype in base_prototypes.items()
    }
    blocked_values: set[_ValueKey] = set()
    blocked_returns: set[FunctionTypeIdentity] = set()
    calls = _call_constraints(function_map)

    return_refs: dict[
        FunctionTypeIdentity,
        tuple[SSAValue, ...],
    ] = {}
    for identity, function in function_map.items():
        values: list[SSAValue] = []
        for block in sorted(function.blocks, key=lambda item: item.address):
            for statement in block.statements:
                if (
                    isinstance(statement, SSAReturnStatement)
                    and isinstance(
                        statement.value,
                        SSAReferenceExpression,
                    )
                    and statement.value.value is not None
                ):
                    values.append(statement.value.value)
        return_refs[identity] = tuple(values)

    for iteration in range(1, iteration_cap + 1):
        next_value_types = dict(value_types)
        next_return_types = dict(return_types)
        next_conflicts = {
            identity: set(items)
            for identity, items in conflicts.items()
        }
        next_blocked_values = set(blocked_values)
        next_blocked_returns = set(blocked_returns)

        # Keep a function return type linked to the SSA values returned by the
        # function. This is what lets a call result returned directly by its
        # caller carry a callee type through a transitive chain.
        for identity in sorted(function_map, key=_identity_sort_key):
            if identity in blocked_returns:
                next_return_types[identity] = UnknownType()
                continue
            for value in return_refs[identity]:
                value_key = (identity, value)
                if value_key in blocked_values:
                    continue
                merged, merge_conflicts = _record_merge(
                    return_types[identity],
                    value_types.get(value_key, UnknownType()),
                )
                if merge_conflicts:
                    next_return_types[identity] = UnknownType()
                    next_value_types[value_key] = UnknownType()
                    next_blocked_returns.add(identity)
                    next_blocked_values.add(value_key)
                    next_conflicts[identity].update(merge_conflicts)
                    break
                accumulated_return, return_conflicts = _accumulate_type(
                    next_return_types[identity],
                    merged,
                )
                accumulated_value, value_conflicts = _accumulate_type(
                    next_value_types.get(value_key, UnknownType()),
                    merged,
                )
                accumulated_conflicts = (
                    *return_conflicts,
                    *value_conflicts,
                )
                if accumulated_conflicts:
                    next_return_types[identity] = UnknownType()
                    next_value_types[value_key] = UnknownType()
                    next_blocked_returns.add(identity)
                    next_blocked_values.add(value_key)
                    next_conflicts[identity].update(
                        accumulated_conflicts
                    )
                    break
                next_return_types[identity] = accumulated_return
                next_value_types[value_key] = accumulated_value

        for constraint in calls:
            caller_function = function_map[constraint.caller]
            callee_function = function_map[constraint.callee]
            callee_prototype = base_prototypes[constraint.callee]

            for position, argument in enumerate(
                constraint.statement.call.arguments
            ):
                if position >= len(callee_prototype.parameters):
                    break

                caller_value_key: _ValueKey | None = None
                if (
                    isinstance(argument, SSAReferenceExpression)
                    and argument.value is not None
                ):
                    caller_value_key = (
                        constraint.caller,
                        argument.value,
                    )

                callee_value_key: _ValueKey | None = None
                if position < len(callee_function.entry_definitions):
                    callee_value_key = (
                        constraint.callee,
                        callee_function.entry_definitions[position],
                    )

                caller_type = _expression_type_from_state(
                    argument,
                    identity=constraint.caller,
                    value_types=value_types,
                    blocked_values=blocked_values,
                )
                callee_type = (
                    _parameter_type_from_state(
                        callee_function,
                        callee_prototype,
                        position,
                        value_types,
                        blocked_values,
                    )
                )

                merged, merge_conflicts = _record_merge(
                    caller_type,
                    callee_type,
                )
                if merge_conflicts:
                    if caller_value_key is not None:
                        next_value_types[caller_value_key] = UnknownType()
                        next_blocked_values.add(caller_value_key)
                    if callee_value_key is not None:
                        next_value_types[callee_value_key] = UnknownType()
                        next_blocked_values.add(callee_value_key)
                    next_conflicts[constraint.caller].update(
                        merge_conflicts
                    )
                    next_conflicts[constraint.callee].update(
                        merge_conflicts
                    )
                    continue

                if (
                    caller_value_key is not None
                    and caller_value_key not in blocked_values
                ):
                    accumulated, accumulation_conflicts = _accumulate_type(
                        next_value_types.get(
                            caller_value_key,
                            UnknownType(),
                        ),
                        merged,
                    )
                    if accumulation_conflicts:
                        next_value_types[caller_value_key] = UnknownType()
                        next_blocked_values.add(caller_value_key)
                        next_conflicts[constraint.caller].update(
                            accumulation_conflicts
                        )
                    else:
                        next_value_types[caller_value_key] = accumulated
                if (
                    callee_value_key is not None
                    and callee_value_key not in blocked_values
                ):
                    accumulated, accumulation_conflicts = _accumulate_type(
                        next_value_types.get(
                            callee_value_key,
                            UnknownType(),
                        ),
                        merged,
                    )
                    if accumulation_conflicts:
                        next_value_types[callee_value_key] = UnknownType()
                        next_blocked_values.add(callee_value_key)
                        next_conflicts[constraint.callee].update(
                            accumulation_conflicts
                        )
                    else:
                        next_value_types[callee_value_key] = accumulated

            result = constraint.statement.result
            if result is None:
                continue
            result_key = (constraint.caller, result)
            callee_return = (
                UnknownType()
                if constraint.callee in blocked_returns
                else return_types[constraint.callee]
            )
            result_type = (
                UnknownType()
                if result_key in blocked_values
                else value_types.get(result_key, UnknownType())
            )

            if isinstance(callee_return, VoidType):
                if not isinstance(result_type, UnknownType):
                    conflict = "call result conflict: void callee used as value"
                    next_value_types[result_key] = UnknownType()
                    next_blocked_values.add(result_key)
                    next_blocked_returns.add(constraint.callee)
                    next_conflicts[constraint.caller].add(conflict)
                    next_conflicts[constraint.callee].add(conflict)
                continue

            merged, merge_conflicts = _record_merge(
                callee_return,
                result_type,
            )
            if merge_conflicts:
                next_value_types[result_key] = UnknownType()
                next_return_types[constraint.callee] = UnknownType()
                next_blocked_values.add(result_key)
                next_blocked_returns.add(constraint.callee)
                next_conflicts[constraint.caller].update(
                    merge_conflicts
                )
                next_conflicts[constraint.callee].update(
                    merge_conflicts
                )
                continue

            if result_key not in blocked_values:
                accumulated_result, result_conflicts = _accumulate_type(
                    next_value_types.get(result_key, UnknownType()),
                    merged,
                )
                if result_conflicts:
                    next_value_types[result_key] = UnknownType()
                    next_blocked_values.add(result_key)
                    next_conflicts[constraint.caller].update(
                        result_conflicts
                    )
                else:
                    next_value_types[result_key] = accumulated_result
            if constraint.callee not in blocked_returns:
                accumulated_return, return_conflicts = _accumulate_type(
                    next_return_types[constraint.callee],
                    merged,
                )
                if return_conflicts:
                    next_return_types[constraint.callee] = UnknownType()
                    next_blocked_returns.add(constraint.callee)
                    next_conflicts[constraint.callee].update(
                        return_conflicts
                    )
                else:
                    next_return_types[constraint.callee] = accumulated_return

        unchanged = (
            next_value_types == value_types
            and next_return_types == return_types
            and next_conflicts == conflicts
            and next_blocked_values == blocked_values
            and next_blocked_returns == blocked_returns
        )
        value_types = next_value_types
        return_types = next_return_types
        conflicts = next_conflicts
        blocked_values = next_blocked_values
        blocked_returns = next_blocked_returns

        if unchanged:
            return _prototype_propagation_result(
                function_map,
                base_prototypes,
                value_types,
                blocked_values,
                return_types,
                conflicts,
                converged=True,
                iterations=iteration,
            )

    return _prototype_propagation_result(
        function_map,
        base_prototypes,
        value_types,
        blocked_values,
        return_types,
        conflicts,
        converged=False,
        iterations=iteration_cap,
        warnings=(
            f"prototype propagation reached iteration cap {iteration_cap}",
        ),
    )


def _prototype_propagation_result(
    functions: dict[FunctionTypeIdentity, SSAFunction],
    base_prototypes: dict[FunctionTypeIdentity, FunctionPrototype],
    value_types: dict[_ValueKey, RecoveredType],
    blocked_values: set[_ValueKey],
    return_types: dict[FunctionTypeIdentity, RecoveredType],
    conflicts: dict[FunctionTypeIdentity, set[str]],
    *,
    converged: bool,
    iterations: int,
    warnings: tuple[str, ...] = (),
) -> PrototypePropagationResult:
    prototypes = tuple(
        _with_final_types(
            functions[identity],
            base_prototypes[identity],
            value_types=value_types,
            blocked_values=blocked_values,
            return_type=return_types[identity],
            conflicts=conflicts[identity],
        )
        for identity in sorted(functions, key=_identity_sort_key)
    )
    records = tuple(
        (
            identity,
            value,
            (
                UnknownType()
                if key in blocked_values
                else value_types[key]
            ),
        )
        for key in sorted(value_types, key=_value_key_sort_key)
        for identity, value in (key,)
    )
    return PrototypePropagationResult(
        prototypes=prototypes,
        value_types=records,
        converged=converged,
        iterations=iterations,
        warnings=warnings,
    )
