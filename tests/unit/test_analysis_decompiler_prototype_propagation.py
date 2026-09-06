from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    DecompilerVariable,
    DecompilerVariableKind,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.prototype import (
    propagate_prototypes,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSABlock,
    SSACallExpression,
    SSACallStatement,
    SSAFunction,
    SSAReferenceExpression,
    SSAReturnStatement,
    SSAStorage,
    SSAStorageKind,
    SSAValue,
)
from nds_disassembly_toolkit.analysis.decompiler.structure_recovery import (
    LocalStructureRecovery,
)
from nds_disassembly_toolkit.analysis.decompiler.type_model import (
    IntegerType,
    PointerType,
    RecoveredSignedness,
    UnknownType,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    FunctionTypeIdentity,
    LocalTypeEnvironment,
    ValueTypeBinding,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x02009000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _reg(
    register: Register,
    version: int = 0,
    address: int = BASE,
) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=register),
        version,
        _source(address),
    )


def _arg(name: str, register: Register) -> DecompilerVariable:
    return DecompilerVariable(
        name,
        DecompilerVariableKind.ARGUMENT,
        register=register,
    )


def _ref(value: SSAValue, address: int) -> SSAReferenceExpression:
    return SSAReferenceExpression(value.storage, value, _source(address))


def _identity(function: SSAFunction) -> FunctionTypeIdentity:
    return FunctionTypeIdentity(
        function.component,
        function.address,
        function.instruction_set,
    )


def _environment(
    *bindings: tuple[SSAValue, object],
) -> LocalTypeEnvironment:
    return LocalTypeEnvironment(
        value_bindings=tuple(
            ValueTypeBinding(value, recovered_type)  # type: ignore[arg-type]
            for value, recovered_type in bindings
        ),
        field_bindings=(),
        structures=LocalStructureRecovery(()),
    )


def _function(
    *,
    address: int,
    name: str,
    component: str = "arm9",
    entry: SSAValue | None = None,
    statements: tuple[object, ...] = (),
) -> SSAFunction:
    parameters = () if entry is None else (_arg("arg0", Register.R0),)
    entries = () if entry is None else (entry,)
    return SSAFunction(
        component=component,
        address=address,
        instruction_set=InstructionSet.ARM,
        name=name,
        parameters=parameters,
        locals=(),
        blocks=(
            SSABlock(
                address,
                InstructionSet.ARM,
                (),
                tuple(statements),  # type: ignore[arg-type]
                (),
            ),
        ),
        entry_definitions=entries,
    )


def _call(
    *,
    address: int,
    target: SSAFunction,
    argument: SSAValue | None = None,
    result: SSAValue | None = None,
    target_component: str | object | None = ...,
) -> SSACallStatement:
    component = (
        target.component
        if target_component is ...
        else target_component
    )
    arguments = (
        ()
        if argument is None
        else (_ref(argument, address),)
    )
    source = _source(address)
    return SSACallStatement(
        SSACallExpression(
            target.name,
            target.address,
            target.instruction_set,
            component,  # type: ignore[arg-type]
            arguments,
            source,
        ),
        source,
        result,
    )


def test_caller_argument_type_propagates_to_callee_parameter() -> None:
    caller_arg = _reg(Register.R0, 0, BASE)
    callee_arg = _reg(Register.R0, 0, BASE + 0x100)
    callee = _function(
        address=BASE + 0x100,
        name="callee",
        entry=callee_arg,
        statements=(
            SSAReturnStatement(None, _source(BASE + 0x104)),
        ),
    )
    caller = _function(
        address=BASE,
        name="caller",
        entry=caller_arg,
        statements=(
            _call(
                address=BASE + 4,
                target=callee,
                argument=caller_arg,
            ),
            SSAReturnStatement(None, _source(BASE + 8)),
        ),
    )
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )

    result = propagate_prototypes(
        (caller, callee),
        (
            _environment((caller_arg, pointer)),
            _environment(),
        ),
    )

    prototype = result.prototype_for(_identity(callee))
    assert prototype is not None
    assert prototype.parameters[0].recovered_type == pointer


def test_callee_parameter_type_propagates_back_to_caller_value() -> None:
    caller_arg = _reg(Register.R0, 0, BASE)
    callee_arg = _reg(Register.R0, 0, BASE + 0x100)
    callee = _function(
        address=BASE + 0x100,
        name="callee",
        entry=callee_arg,
        statements=(
            SSAReturnStatement(None, _source(BASE + 0x104)),
        ),
    )
    caller = _function(
        address=BASE,
        name="caller",
        entry=caller_arg,
        statements=(
            _call(
                address=BASE + 4,
                target=callee,
                argument=caller_arg,
            ),
            SSAReturnStatement(None, _source(BASE + 8)),
        ),
    )
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )

    result = propagate_prototypes(
        (caller, callee),
        (
            _environment(),
            _environment((callee_arg, pointer)),
        ),
    )

    assert result.type_for_value(
        _identity(caller),
        caller_arg,
    ) == pointer


def test_callee_return_type_propagates_to_call_result() -> None:
    callee_value = _reg(Register.R0, 1, BASE + 0x104)
    callee = _function(
        address=BASE + 0x100,
        name="callee",
        statements=(
            SSAReturnStatement(
                _ref(callee_value, BASE + 0x104),
                _source(BASE + 0x104),
            ),
        ),
    )
    call_result = _reg(Register.R0, 1, BASE + 4)
    caller = _function(
        address=BASE,
        name="caller",
        statements=(
            _call(
                address=BASE + 4,
                target=callee,
                result=call_result,
            ),
            SSAReturnStatement(None, _source(BASE + 8)),
        ),
    )
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )

    result = propagate_prototypes(
        (caller, callee),
        (
            _environment(),
            _environment((callee_value, pointer)),
        ),
    )

    assert result.type_for_value(
        _identity(caller),
        call_result,
    ) == pointer


def test_call_result_use_refines_callee_return_type() -> None:
    callee_value = _reg(Register.R0, 1, BASE + 0x104)
    callee = _function(
        address=BASE + 0x100,
        name="callee",
        statements=(
            SSAReturnStatement(
                _ref(callee_value, BASE + 0x104),
                _source(BASE + 0x104),
            ),
        ),
    )
    call_result = _reg(Register.R0, 1, BASE + 4)
    caller = _function(
        address=BASE,
        name="caller",
        statements=(
            _call(
                address=BASE + 4,
                target=callee,
                result=call_result,
            ),
            SSAReturnStatement(None, _source(BASE + 8)),
        ),
    )
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )

    result = propagate_prototypes(
        (caller, callee),
        (
            _environment((call_result, pointer)),
            _environment(),
        ),
    )

    prototype = result.prototype_for(_identity(callee))
    assert prototype is not None
    assert prototype.return_type == pointer


def test_transitive_return_propagation_reaches_fixed_point() -> None:
    c_value = _reg(Register.R0, 1, BASE + 0x204)
    c = _function(
        address=BASE + 0x200,
        name="c",
        statements=(
            SSAReturnStatement(
                _ref(c_value, BASE + 0x204),
                _source(BASE + 0x204),
            ),
        ),
    )

    b_result = _reg(Register.R0, 1, BASE + 0x104)
    b = _function(
        address=BASE + 0x100,
        name="b",
        statements=(
            _call(
                address=BASE + 0x104,
                target=c,
                result=b_result,
            ),
            SSAReturnStatement(
                _ref(b_result, BASE + 0x108),
                _source(BASE + 0x108),
            ),
        ),
    )

    a_result = _reg(Register.R0, 1, BASE + 4)
    a = _function(
        address=BASE,
        name="a",
        statements=(
            _call(
                address=BASE + 4,
                target=b,
                result=a_result,
            ),
            SSAReturnStatement(
                _ref(a_result, BASE + 8),
                _source(BASE + 8),
            ),
        ),
    )
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )

    result = propagate_prototypes(
        (a, b, c),
        (
            _environment(),
            _environment(),
            _environment((c_value, pointer)),
        ),
    )

    assert result.converged is True
    assert result.prototype_for(_identity(a)).return_type == pointer  # type: ignore[union-attr]
    assert result.prototype_for(_identity(b)).return_type == pointer  # type: ignore[union-attr]
    assert result.prototype_for(_identity(c)).return_type == pointer  # type: ignore[union-attr]
    assert result.type_for_value(_identity(a), a_result) == pointer
    assert result.type_for_value(_identity(b), b_result) == pointer


def test_recursive_cycle_converges_from_one_pointer_seed() -> None:
    a_arg = _reg(Register.R0, 0, BASE)
    b_arg = _reg(Register.R0, 0, BASE + 0x100)
    a = _function(
        address=BASE,
        name="a",
        entry=a_arg,
    )
    b = _function(
        address=BASE + 0x100,
        name="b",
        entry=b_arg,
    )
    a = _function(
        address=a.address,
        name=a.name,
        entry=a_arg,
        statements=(
            _call(
                address=BASE + 4,
                target=b,
                argument=a_arg,
            ),
            SSAReturnStatement(None, _source(BASE + 8)),
        ),
    )
    b = _function(
        address=b.address,
        name=b.name,
        entry=b_arg,
        statements=(
            _call(
                address=BASE + 0x104,
                target=a,
                argument=b_arg,
            ),
            SSAReturnStatement(None, _source(BASE + 0x108)),
        ),
    )
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )

    result = propagate_prototypes(
        (a, b),
        (
            _environment((a_arg, pointer)),
            _environment(),
        ),
    )

    assert result.converged is True
    assert result.prototype_for(_identity(b)).parameters[0].recovered_type == pointer  # type: ignore[union-attr]


def test_incompatible_parameter_widths_record_conflict() -> None:
    caller_arg = _reg(Register.R0, 0, BASE)
    callee_arg = _reg(Register.R0, 0, BASE + 0x100)
    callee = _function(
        address=BASE + 0x100,
        name="callee",
        entry=callee_arg,
        statements=(
            SSAReturnStatement(None, _source(BASE + 0x104)),
        ),
    )
    caller = _function(
        address=BASE,
        name="caller",
        entry=caller_arg,
        statements=(
            _call(
                address=BASE + 4,
                target=callee,
                argument=caller_arg,
            ),
            SSAReturnStatement(None, _source(BASE + 8)),
        ),
    )

    result = propagate_prototypes(
        (caller, callee),
        (
            _environment(
                (
                    caller_arg,
                    IntegerType(
                        4,
                        RecoveredSignedness.UNKNOWN,
                    ),
                )
            ),
            _environment(
                (
                    callee_arg,
                    IntegerType(
                        2,
                        RecoveredSignedness.UNKNOWN,
                    ),
                )
            ),
        ),
    )

    prototype = result.prototype_for(_identity(callee))
    assert prototype is not None
    assert isinstance(
        prototype.parameters[0].recovered_type,
        UnknownType,
    )
    assert any(
        "integer widths 4 and 2" in conflict
        or "integer widths 2 and 4" in conflict
        for conflict in prototype.conflicts
    )


def test_componentless_overlay_ambiguity_does_not_propagate() -> None:
    caller_arg = _reg(Register.R0, 0, BASE)
    shared = BASE + 0x100
    a_arg = _reg(Register.R0, 0, shared)
    b_arg = _reg(Register.R0, 0, shared)
    overlay_a = _function(
        component="overlay_a",
        address=shared,
        name="target_a",
        entry=a_arg,
        statements=(
            SSAReturnStatement(None, _source(shared + 4)),
        ),
    )
    overlay_b = _function(
        component="overlay_b",
        address=shared,
        name="target_b",
        entry=b_arg,
        statements=(
            SSAReturnStatement(None, _source(shared + 4)),
        ),
    )
    source = _source(BASE + 4)
    caller = _function(
        address=BASE,
        name="caller",
        entry=caller_arg,
        statements=(
            SSACallStatement(
                SSACallExpression(
                    "ambiguous",
                    shared,
                    InstructionSet.ARM,
                    None,
                    (_ref(caller_arg, BASE + 4),),
                    source,
                ),
                source,
                _reg(Register.R0, 1, BASE + 4),
            ),
            SSAReturnStatement(None, _source(BASE + 8)),
        ),
    )
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )

    result = propagate_prototypes(
        (caller, overlay_a, overlay_b),
        (
            _environment((caller_arg, pointer)),
            _environment(),
            _environment(),
        ),
    )

    assert isinstance(
        result.prototype_for(_identity(overlay_a)).parameters[0].recovered_type,  # type: ignore[union-attr]
        UnknownType,
    )
    assert isinstance(
        result.prototype_for(_identity(overlay_b)).parameters[0].recovered_type,  # type: ignore[union-attr]
        UnknownType,
    )


def test_component_qualified_overlay_call_propagates_only_to_target() -> None:
    caller_arg = _reg(Register.R0, 0, BASE)
    shared = BASE + 0x100
    a_arg = _reg(Register.R0, 0, shared)
    b_arg = _reg(Register.R0, 0, shared)
    overlay_a = _function(
        component="overlay_a",
        address=shared,
        name="target_a",
        entry=a_arg,
        statements=(
            SSAReturnStatement(None, _source(shared + 4)),
        ),
    )
    overlay_b = _function(
        component="overlay_b",
        address=shared,
        name="target_b",
        entry=b_arg,
        statements=(
            SSAReturnStatement(None, _source(shared + 4)),
        ),
    )
    source = _source(BASE + 4)
    caller = _function(
        address=BASE,
        name="caller",
        entry=caller_arg,
        statements=(
            SSACallStatement(
                SSACallExpression(
                    "target_a",
                    shared,
                    InstructionSet.ARM,
                    "overlay_a",
                    (_ref(caller_arg, BASE + 4),),
                    source,
                ),
                source,
                _reg(Register.R0, 1, BASE + 4),
            ),
            SSAReturnStatement(None, _source(BASE + 8)),
        ),
    )
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )

    result = propagate_prototypes(
        (caller, overlay_a, overlay_b),
        (
            _environment((caller_arg, pointer)),
            _environment(),
            _environment(),
        ),
    )

    assert result.prototype_for(_identity(overlay_a)).parameters[0].recovered_type == pointer  # type: ignore[union-attr]
    assert isinstance(
        result.prototype_for(_identity(overlay_b)).parameters[0].recovered_type,  # type: ignore[union-attr]
        UnknownType,
    )


def test_iteration_cap_is_deterministic_and_explicit() -> None:
    c_value = _reg(Register.R0, 1, BASE + 0x204)
    c = _function(
        address=BASE + 0x200,
        name="c",
        statements=(
            SSAReturnStatement(
                _ref(c_value, BASE + 0x204),
                _source(BASE + 0x204),
            ),
        ),
    )
    b_result = _reg(Register.R0, 1, BASE + 0x104)
    b = _function(
        address=BASE + 0x100,
        name="b",
        statements=(
            _call(
                address=BASE + 0x104,
                target=c,
                result=b_result,
            ),
            SSAReturnStatement(
                _ref(b_result, BASE + 0x108),
                _source(BASE + 0x108),
            ),
        ),
    )
    a_result = _reg(Register.R0, 1, BASE + 4)
    a = _function(
        address=BASE,
        name="a",
        statements=(
            _call(
                address=BASE + 4,
                target=b,
                result=a_result,
            ),
            SSAReturnStatement(
                _ref(a_result, BASE + 8),
                _source(BASE + 8),
            ),
        ),
    )
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )
    args = (
        (a, b, c),
        (
            _environment(),
            _environment(),
            _environment((c_value, pointer)),
        ),
    )

    first = propagate_prototypes(
        *args,
        iteration_cap=1,
    )
    second = propagate_prototypes(
        *args,
        iteration_cap=1,
    )

    assert first == second
    assert first.converged is False
    assert first.iterations == 1
    assert first.warnings == (
        "prototype propagation reached iteration cap 1",
    )
