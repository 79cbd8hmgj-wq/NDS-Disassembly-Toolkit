from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.lower import lower_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    CallExpression,
    CallStatement,
    ReturnStatement,
    SourceRef,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.render import render_pseudo_c
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
from nds_disassembly_toolkit.analysis.decompiler.structure import structure_function
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x0200A000
TARGET = 0x0200B000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _result(version: int, address: int) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=Register.R0),
        version,
        _source(address),
    )


def _call(
    address: int,
    result: SSAValue,
    *,
    name: str = "callee",
) -> SSACallStatement:
    source = _source(address)
    return SSACallStatement(
        SSACallExpression(
            name,
            TARGET,
            InstructionSet.ARM,
            "arm9",
            (),
            source,
        ),
        source,
        result,
    )


def _function(*statements: object) -> SSAFunction:
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
                tuple(statements),  # type: ignore[arg-type]
                (),
            ),
        ),
    )


def test_used_call_result_lowers_to_deterministic_temporary() -> None:
    result = _result(0, BASE)
    function = _function(
        _call(BASE, result),
        SSAReturnStatement(
            SSAReferenceExpression(
                result.storage,
                result,
                _source(BASE + 4),
            ),
            _source(BASE + 4),
        ),
    )

    lowered = lower_ssa_function(function)
    statements = lowered.blocks[0].statements

    assert len(statements) == 2
    assigned = statements[0]
    returned = statements[1]
    assert isinstance(assigned, AssignmentStatement)
    assert isinstance(assigned.target, VariableExpression)
    assert assigned.target.variable.name == "call_result_0"
    assert isinstance(assigned.value, CallExpression)
    assert isinstance(returned, ReturnStatement)
    assert isinstance(returned.value, VariableExpression)
    assert returned.value.variable == assigned.target.variable
    assert tuple(variable.name for variable in lowered.locals) == (
        "call_result_0",
    )


def test_unused_call_result_remains_side_effect_only_call() -> None:
    result = _result(0, BASE)
    function = _function(
        _call(BASE, result),
        SSAReturnStatement(None, _source(BASE + 4)),
    )

    lowered = lower_ssa_function(function)

    assert isinstance(lowered.blocks[0].statements[0], CallStatement)
    assert lowered.locals == ()


def test_multiple_used_results_get_stable_source_names() -> None:
    first = _result(0, BASE)
    second = _result(1, BASE + 4)
    function = _function(
        _call(BASE, first, name="first_call"),
        SSAReturnStatement(
            SSAReferenceExpression(
                first.storage,
                first,
                _source(BASE + 2),
            ),
            _source(BASE + 2),
        ),
        _call(BASE + 4, second, name="second_call"),
        SSAReturnStatement(
            SSAReferenceExpression(
                second.storage,
                second,
                _source(BASE + 8),
            ),
            _source(BASE + 8),
        ),
    )

    lowered = lower_ssa_function(function)

    assert tuple(variable.name for variable in lowered.locals) == (
        "call_result_0",
        "call_result_1",
    )
    first_assignment = lowered.blocks[0].statements[0]
    second_assignment = lowered.blocks[0].statements[2]
    assert isinstance(first_assignment, AssignmentStatement)
    assert isinstance(second_assignment, AssignmentStatement)
    assert isinstance(first_assignment.target, VariableExpression)
    assert isinstance(second_assignment.target, VariableExpression)
    assert first_assignment.target.variable.name == "call_result_0"
    assert second_assignment.target.variable.name == "call_result_1"


def test_used_call_result_pseudo_c_has_no_ssa_suffixes() -> None:
    result = _result(7, BASE)
    function = _function(
        _call(BASE, result),
        SSAReturnStatement(
            SSAReferenceExpression(
                result.storage,
                result,
                _source(BASE + 4),
            ),
            _source(BASE + 4),
        ),
    )

    lowered = lower_ssa_function(function)
    pseudo_c = render_pseudo_c(structure_function(lowered))

    assert "uint32_t call_result_0;" in pseudo_c
    assert "call_result_0 = callee();" in pseudo_c
    assert "return call_result_0;" in pseudo_c
    assert "_v7" not in pseudo_c
    assert ".7" not in pseudo_c
