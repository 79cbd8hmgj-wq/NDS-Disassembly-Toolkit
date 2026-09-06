from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    ConstantExpression,
    DecompilerVariable,
    DecompilerVariableKind,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.prototype import (
    FunctionPrototype,
    PrototypeParameter,
    recover_local_prototype,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSABlock,
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
    VoidType,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    LocalTypeEnvironment,
    ValueTypeBinding,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x02008000


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _reg(register: Register, version: int = 0) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=register),
        version,
        _source(),
    )


def _stack(offset: int, version: int = 0) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.STACK, stack_offset=offset),
        version,
        _source(),
    )


def _temp(name: str, version: int = 0) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.TEMPORARY, temporary_name=name),
        version,
        _source(),
    )


def _ref(value: SSAValue, address: int) -> SSAReferenceExpression:
    return SSAReferenceExpression(value.storage, value, _source(address))


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
    parameters: tuple[DecompilerVariable, ...] = (),
    entries: tuple[SSAValue, ...] = (),
    returns: tuple[object, ...] = (),
    name: str = "entry",
) -> SSAFunction:
    return SSAFunction(
        component="arm9",
        address=BASE,
        instruction_set=InstructionSet.ARM,
        name=name,
        parameters=parameters,
        locals=(),
        blocks=(
            SSABlock(
                BASE,
                InstructionSet.ARM,
                (),
                tuple(returns),  # type: ignore[arg-type]
                (),
            ),
        ),
        entry_definitions=entries,
    )


def _reg_arg(name: str, register: Register) -> DecompilerVariable:
    return DecompilerVariable(
        name,
        DecompilerVariableKind.ARGUMENT,
        register=register,
    )


def _stack_arg(name: str, offset: int) -> DecompilerVariable:
    return DecompilerVariable(
        name,
        DecompilerVariableKind.ARGUMENT,
        stack_offset=offset,
    )


def test_unknown_register_parameter_seed_preserves_abi_location() -> None:
    arg0 = _reg(Register.R0)
    function = _function(
        parameters=(_reg_arg("arg0", Register.R0),),
        entries=(arg0,),
    )

    prototype = recover_local_prototype(
        function,
        _environment(),
    )

    assert isinstance(prototype, FunctionPrototype)
    assert len(prototype.parameters) == 1
    parameter = prototype.parameters[0]
    assert isinstance(parameter, PrototypeParameter)
    assert parameter.position == 0
    assert parameter.name == "arg0"
    assert parameter.register is Register.R0
    assert parameter.stack_offset is None
    assert isinstance(parameter.recovered_type, UnknownType)


def test_parameter_seed_uses_phase_7l_pointer_type() -> None:
    arg0 = _reg(Register.R0)
    pointer = PointerType(
        pointee_name="struct_actor",
        component="arm9",
    )
    function = _function(
        parameters=(_reg_arg("arg0", Register.R0),),
        entries=(arg0,),
    )

    prototype = recover_local_prototype(
        function,
        _environment((arg0, pointer)),
    )

    assert prototype.parameters[0].recovered_type == pointer


def test_stack_parameter_preserves_entry_sp_offset_without_guessing_abi_index() -> None:
    entry = _stack(8)
    function = _function(
        parameters=(_stack_arg("arg_stack_08", 8),),
        entries=(entry,),
    )

    parameter = recover_local_prototype(
        function,
        _environment(),
    ).parameters[0]

    assert parameter.position == 0
    assert parameter.register is None
    assert parameter.stack_offset == 8
    assert isinstance(parameter.recovered_type, UnknownType)


def test_parameter_order_is_stable_and_matches_source_variables() -> None:
    arg0 = _reg(Register.R0)
    arg1 = _reg(Register.R1)
    function = _function(
        parameters=(
            _reg_arg("arg0", Register.R0),
            _reg_arg("arg1", Register.R1),
        ),
        entries=(arg0, arg1),
    )

    prototype = recover_local_prototype(
        function,
        _environment(),
    )

    assert tuple(item.name for item in prototype.parameters) == (
        "arg0",
        "arg1",
    )
    assert tuple(item.position for item in prototype.parameters) == (0, 1)


def test_all_valueless_returns_seed_void() -> None:
    source = _source(BASE + 4)
    function = _function(
        returns=(SSAReturnStatement(None, source),),
    )

    prototype = recover_local_prototype(
        function,
        _environment(),
    )

    assert isinstance(prototype.return_type, VoidType)
    assert prototype.conflicts == ()


def test_numeric_constant_return_seeds_32_bit_integer() -> None:
    source = _source(BASE + 4)
    function = _function(
        returns=(
            SSAReturnStatement(
                ConstantExpression(7, source),
                source,
            ),
        ),
    )

    prototype = recover_local_prototype(
        function,
        _environment(),
    )

    assert prototype.return_type == IntegerType(
        4,
        RecoveredSignedness.UNKNOWN,
    )


def test_address_return_seeds_component_owned_pointer() -> None:
    source = _source(BASE + 4)
    function = _function(
        returns=(
            SSAReturnStatement(
                AddressExpression(
                    0x02010000,
                    "arm9",
                    source,
                ),
                source,
            ),
        ),
    )

    prototype = recover_local_prototype(
        function,
        _environment(),
    )

    assert prototype.return_type == PointerType(component="arm9")


def test_ssa_return_uses_phase_7l_value_type() -> None:
    value = _temp("result")
    source = _source(BASE + 4)
    recovered = IntegerType(
        2,
        RecoveredSignedness.UNSIGNED,
    )
    function = _function(
        returns=(SSAReturnStatement(_ref(value, BASE + 4), source),),
    )

    prototype = recover_local_prototype(
        function,
        _environment((value, recovered)),
    )

    assert prototype.return_type == recovered


def test_compatible_integer_return_sites_widen_signedness_only() -> None:
    first = _temp("first")
    second = _temp("second")
    function = _function(
        returns=(
            SSAReturnStatement(
                _ref(first, BASE + 4),
                _source(BASE + 4),
            ),
            SSAReturnStatement(
                _ref(second, BASE + 8),
                _source(BASE + 8),
            ),
        ),
    )
    environment = _environment(
        (
            first,
            IntegerType(4, RecoveredSignedness.SIGNED),
        ),
        (
            second,
            IntegerType(4, RecoveredSignedness.UNSIGNED),
        ),
    )

    prototype = recover_local_prototype(
        function,
        environment,
    )

    assert prototype.return_type == IntegerType(
        4,
        RecoveredSignedness.UNKNOWN,
    )
    assert prototype.conflicts == ()


def test_incompatible_return_widths_fall_back_to_unknown_with_conflict() -> None:
    first = _temp("first")
    second = _temp("second")
    function = _function(
        returns=(
            SSAReturnStatement(
                _ref(first, BASE + 4),
                _source(BASE + 4),
            ),
            SSAReturnStatement(
                _ref(second, BASE + 8),
                _source(BASE + 8),
            ),
        ),
    )
    environment = _environment(
        (
            first,
            IntegerType(1, RecoveredSignedness.UNKNOWN),
        ),
        (
            second,
            IntegerType(4, RecoveredSignedness.UNKNOWN),
        ),
    )

    prototype = recover_local_prototype(
        function,
        environment,
    )

    assert isinstance(prototype.return_type, UnknownType)
    assert prototype.conflicts == (
        "return type conflict: integer widths 1 and 4",
    )


def test_void_and_value_return_sites_are_conservative_conflict() -> None:
    value = _temp("value")
    function = _function(
        returns=(
            SSAReturnStatement(None, _source(BASE + 4)),
            SSAReturnStatement(
                _ref(value, BASE + 8),
                _source(BASE + 8),
            ),
        ),
    )

    prototype = recover_local_prototype(
        function,
        _environment(
            (
                value,
                IntegerType(
                    4,
                    RecoveredSignedness.UNKNOWN,
                ),
            )
        ),
    )

    assert isinstance(prototype.return_type, UnknownType)
    assert prototype.conflicts == (
        "return type conflict: void and value returns",
    )
