from __future__ import annotations

from dataclasses import dataclass

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    ConstantExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAExpression,
    SSAFunction,
    SSAMemoryReadExpression,
    SSAReferenceExpression,
    SSAReturnStatement,
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
