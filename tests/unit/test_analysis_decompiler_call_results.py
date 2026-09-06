from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.lower import lower_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.model import (
    BinaryOperator,
    ConstantExpression,
    FieldAddressExpression,
    MemoryReadExpression,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.render import render_pseudo_c
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSABinaryExpression,
    SSABlock,
    SSACallExpression,
    SSACallStatement,
    SSAFunction,
    SSAMemoryReadExpression,
    SSAReferenceExpression,
    SSAReturnStatement,
    SSAStorage,
    SSAStorageKind,
    SSAValue,
)
from nds_disassembly_toolkit.analysis.decompiler.structure import structure_function
from nds_disassembly_toolkit.analysis.decompiler.structure_recovery import (
    LocalStructureRecovery,
    StructureCandidate,
)
from nds_disassembly_toolkit.analysis.decompiler.type_model import (
    IntegerType,
    PointerType,
    RecoveredSignedness,
    RecoveredStructField,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    LocalTypeEnvironment,
    ValueTypeBinding,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x0200A000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _result(version: int, address: int) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=Register.R0),
        version,
        _source(address),
    )


def _call(
    *,
    address: int,
    result: SSAValue,
    name: str = "foo",
) -> SSACallStatement:
    source = _source(address)
    return SSACallStatement(
        SSACallExpression(
            name,
            0x0200B000,
            InstructionSet.ARM,
            "arm9",
            (),
            source,
        ),
        source,
        result,
    )


def _ref(value: SSAValue, address: int) -> SSAReferenceExpression:
    return SSAReferenceExpression(value.storage, value, _source(address))


def _function(
    statements: tuple[object, ...],
) -> SSAFunction:
    return SSAFunction(
        component="arm9",
        address=BASE,
        instruction_set=InstructionSet.ARM,
        name="caller",
        parameters=(),
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
    )


def test_unused_call_result_remains_side_effect_only() -> None:
    result = _result(0, BASE)
    function = _function(
        (
            _call(address=BASE, result=result),
            SSAReturnStatement(None, _source(BASE + 4)),
        )
    )

    lowered = lower_ssa_function(function)
    pseudo_c = render_pseudo_c(structure_function(lowered))

    assert lowered.locals == ()
    assert "foo();" in pseudo_c
    assert "call_result_" not in pseudo_c


def test_used_call_result_gets_stable_source_temporary() -> None:
    result = _result(0, BASE)
    function = _function(
        (
            _call(address=BASE, result=result),
            SSAReturnStatement(
                _ref(result, BASE + 4),
                _source(BASE + 4),
            ),
        )
    )

    lowered = lower_ssa_function(function)
    pseudo_c = render_pseudo_c(structure_function(lowered))

    assert tuple(variable.name for variable in lowered.locals) == (
        "call_result_0",
    )
    assert "uint32_t call_result_0;" in pseudo_c
    assert "call_result_0 = foo();" in pseudo_c
    assert "return call_result_0;" in pseudo_c
    assert "_v0" not in pseudo_c


def test_two_used_call_results_get_deterministic_names() -> None:
    first = _result(0, BASE)
    second = _result(1, BASE + 4)
    function = _function(
        (
            _call(address=BASE, result=first, name="first"),
            _call(address=BASE + 4, result=second, name="second"),
            SSAReturnStatement(
                SSABinaryExpression(
                    BinaryOperator.ADD,
                    _ref(first, BASE + 8),
                    _ref(second, BASE + 8),
                    _source(BASE + 8),
                ),
                _source(BASE + 8),
            ),
        )
    )

    pseudo_c = render_pseudo_c(
        structure_function(lower_ssa_function(function))
    )

    assert "call_result_0 = first();" in pseudo_c
    assert "call_result_1 = second();" in pseudo_c
    assert "return (call_result_0 + call_result_1);" in pseudo_c


def test_used_call_result_can_be_base_of_recovered_field_access() -> None:
    result = _result(0, BASE)
    read_source = _source(BASE + 4)
    address = SSABinaryExpression(
        BinaryOperator.ADD,
        _ref(result, BASE + 4),
        ConstantExpression(4, read_source),
        read_source,
    )
    function = _function(
        (
            _call(address=BASE, result=result),
            SSAReturnStatement(
                SSAMemoryReadExpression(
                    address,
                    4,
                    read_source,
                ),
                read_source,
            ),
        )
    )
    candidate = StructureCandidate(
        component="arm9",
        function_address=BASE,
        instruction_set=InstructionSet.ARM,
        root=result,
        name="struct_result",
        fields=(
            RecoveredStructField(
                4,
                4,
                "field_04",
                IntegerType(4, RecoveredSignedness.UNKNOWN),
            ),
            RecoveredStructField(
                8,
                4,
                "field_08",
                IntegerType(4, RecoveredSignedness.UNKNOWN),
            ),
        ),
        accesses=(),
    )
    environment = LocalTypeEnvironment(
        value_bindings=(
            ValueTypeBinding(
                result,
                PointerType(
                    pointee_name="struct_result",
                    component="arm9",
                ),
            ),
        ),
        field_bindings=(),
        structures=LocalStructureRecovery((candidate,)),
    )

    lowered = lower_ssa_function(
        function,
        type_environment=environment,
    )
    returned = lowered.blocks[0].statements[-1]

    assert isinstance(returned.value, MemoryReadExpression)  # type: ignore[union-attr]
    assert isinstance(
        returned.value.address,  # type: ignore[union-attr]
        FieldAddressExpression,
    )
    pseudo_c = render_pseudo_c(structure_function(lowered))
    assert "call_result_0 = foo();" in pseudo_c
    assert "return call_result_0->field_04;" in pseudo_c
