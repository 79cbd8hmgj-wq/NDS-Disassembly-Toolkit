from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    BinaryOperator,
    ConstantExpression,
    DecompilerVariable,
    DecompilerVariableKind,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAAssignmentStatement,
    SSABinaryExpression,
    SSABlock,
    SSABranchStatement,
    SSACompareExpression,
    SSAFunction,
    SSAMemoryReadExpression,
    SSAReferenceExpression,
    SSAStorage,
    SSAStorageKind,
    SSAValue,
)
from nds_disassembly_toolkit.analysis.decompiler.type_model import (
    IntegerType,
    PointerType,
    RecoveredSignedness,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    infer_local_types,
)
from nds_disassembly_toolkit.analysis.model import (
    ConditionCode,
    InstructionSet,
    Register,
)

BASE = 0x02003000


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _reg(register: Register, version: int = 0) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=register),
        version,
        _source(),
    )


def _temp(name: str, version: int = 0) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.TEMPORARY, temporary_name=name),
        version,
        _source(),
    )


def _ref(value: SSAValue, address: int = BASE) -> SSAReferenceExpression:
    return SSAReferenceExpression(value.storage, value, _source(address))


def _address(
    root: SSAValue,
    offset: int,
    address: int,
):
    if offset == 0:
        return _ref(root, address)
    return SSABinaryExpression(
        BinaryOperator.ADD,
        _ref(root, address),
        ConstantExpression(offset, _source(address)),
        _source(address),
    )


def _arg(name: str, register: Register) -> DecompilerVariable:
    return DecompilerVariable(
        name,
        DecompilerVariableKind.ARGUMENT,
        register=register,
    )


def _function(
    statements: tuple[object, ...],
    *,
    parameters: tuple[DecompilerVariable, ...] = (),
    entry_definitions: tuple[SSAValue, ...] = (),
) -> SSAFunction:
    return SSAFunction(
        component="arm9",
        address=BASE,
        instruction_set=InstructionSet.ARM,
        name="entry",
        parameters=parameters,
        locals=(),
        blocks=(
            SSABlock(
                BASE,
                InstructionSet.ARM,
                (),
                statements,  # type: ignore[arg-type]
                (),
            ),
        ),
        entry_definitions=entry_definitions,
    )


def _field_read(
    root: SSAValue,
    offset: int,
    width: int,
    target: SSAValue,
    address: int,
) -> SSAAssignmentStatement:
    source = _source(address)
    return SSAAssignmentStatement(
        target,
        SSAMemoryReadExpression(
            _address(root, offset, address),
            width,
            source,
        ),
        source,
    )


def test_dereference_proves_pointer_like_root() -> None:
    arg0 = _reg(Register.R0)
    loaded = _temp("loaded")
    function = _function(
        (_field_read(arg0, 4, 4, loaded, BASE + 4),),
        parameters=(_arg("arg0", Register.R0),),
        entry_definitions=(arg0,),
    )

    environment = infer_local_types(function)
    recovered = environment.type_for_value(arg0)

    assert isinstance(recovered, PointerType)
    assert recovered.pointee_name == "struct_entry_arg0"


def test_access_width_proves_scalar_field_width() -> None:
    arg0 = _reg(Register.R0)
    loaded = _temp("loaded")
    function = _function(
        (_field_read(arg0, 4, 2, loaded, BASE + 4),),
        parameters=(_arg("arg0", Register.R0),),
        entry_definitions=(arg0,),
    )

    environment = infer_local_types(function)
    recovered = environment.type_for_field(arg0, 4)

    assert recovered == IntegerType(2, RecoveredSignedness.UNKNOWN)


def test_signed_compare_refines_loaded_field_signedness() -> None:
    arg0 = _reg(Register.R0)
    loaded = _temp("loaded")
    compare_source = _source(BASE + 8)
    function = _function(
        (
            _field_read(arg0, 4, 4, loaded, BASE + 4),
            SSABranchStatement(
                SSACompareExpression(
                    ConditionCode.LT,
                    _ref(loaded, BASE + 8),
                    ConstantExpression(10, compare_source),
                    compare_source,
                ),
                BASE + 0x20,
                InstructionSet.ARM,
                compare_source,
            ),
        ),
        parameters=(_arg("arg0", Register.R0),),
        entry_definitions=(arg0,),
    )

    recovered = infer_local_types(function).type_for_field(arg0, 4)

    assert recovered == IntegerType(4, RecoveredSignedness.SIGNED)


def test_unsigned_compare_refines_loaded_field_signedness() -> None:
    arg0 = _reg(Register.R0)
    loaded = _temp("loaded")
    compare_source = _source(BASE + 8)
    function = _function(
        (
            _field_read(arg0, 4, 4, loaded, BASE + 4),
            SSABranchStatement(
                SSACompareExpression(
                    ConditionCode.LO,
                    _ref(loaded, BASE + 8),
                    ConstantExpression(10, compare_source),
                    compare_source,
                ),
                BASE + 0x20,
                InstructionSet.ARM,
                compare_source,
            ),
        ),
        parameters=(_arg("arg0", Register.R0),),
        entry_definitions=(arg0,),
    )

    recovered = infer_local_types(function).type_for_field(arg0, 4)

    assert recovered == IntegerType(4, RecoveredSignedness.UNSIGNED)


def test_conflicting_signedness_widens_to_unknown() -> None:
    arg0 = _reg(Register.R0)
    loaded = _temp("loaded")
    first_source = _source(BASE + 8)
    second_source = _source(BASE + 12)
    function = _function(
        (
            _field_read(arg0, 4, 4, loaded, BASE + 4),
            SSABranchStatement(
                SSACompareExpression(
                    ConditionCode.LT,
                    _ref(loaded, BASE + 8),
                    ConstantExpression(10, first_source),
                    first_source,
                ),
                BASE + 0x20,
                InstructionSet.ARM,
                first_source,
            ),
            SSABranchStatement(
                SSACompareExpression(
                    ConditionCode.LO,
                    _ref(loaded, BASE + 12),
                    ConstantExpression(10, second_source),
                    second_source,
                ),
                BASE + 0x24,
                InstructionSet.ARM,
                second_source,
            ),
        ),
        parameters=(_arg("arg0", Register.R0),),
        entry_definitions=(arg0,),
    )

    recovered = infer_local_types(function).type_for_field(arg0, 4)

    assert recovered == IntegerType(4, RecoveredSignedness.UNKNOWN)


def test_proven_address_value_retains_component_ownership() -> None:
    target = _reg(Register.R0)
    source = _source(BASE)
    function = _function(
        (
            SSAAssignmentStatement(
                target,
                AddressExpression(0x02004000, "arm9", source),
                source,
            ),
        )
    )

    recovered = infer_local_types(function).type_for_value(target)

    assert isinstance(recovered, PointerType)
    assert recovered.component == "arm9"


def test_naked_numeric_constant_is_not_promoted_to_pointer() -> None:
    target = _reg(Register.R0)
    source = _source(BASE)
    function = _function(
        (
            SSAAssignmentStatement(
                target,
                ConstantExpression(0x02004000, source),
                source,
            ),
        )
    )

    recovered = infer_local_types(function).type_for_value(target)

    assert not isinstance(recovered, PointerType)


def test_loaded_value_gets_access_width_type() -> None:
    arg0 = _reg(Register.R0)
    loaded = _temp("loaded")
    function = _function(
        (_field_read(arg0, 4, 1, loaded, BASE + 4),),
        parameters=(_arg("arg0", Register.R0),),
        entry_definitions=(arg0,),
    )

    recovered = infer_local_types(function).type_for_value(loaded)

    assert recovered == IntegerType(1, RecoveredSignedness.UNKNOWN)
