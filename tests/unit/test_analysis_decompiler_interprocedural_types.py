from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    DecompilerVariable,
    DecompilerVariableKind,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
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
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    FunctionTypeIdentity,
    infer_local_types,
    propagate_interprocedural_types,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x02005000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _reg(register: Register, address: int) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=register),
        0,
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


def _memory_read(
    root: SSAValue,
    offset: int,
    width: int,
    address: int,
) -> SSAMemoryReadExpression:
    from nds_disassembly_toolkit.analysis.decompiler.model import (
        BinaryOperator,
        ConstantExpression,
    )
    from nds_disassembly_toolkit.analysis.decompiler.ssa import (
        SSABinaryExpression,
    )

    source = _source(address)
    address_expression = SSABinaryExpression(
        BinaryOperator.ADD,
        _ref(root, address),
        ConstantExpression(offset, source),
        source,
    )
    return SSAMemoryReadExpression(address_expression, width, source)


def _function(
    *,
    component: str,
    address: int,
    name: str,
    parameter_register: Register = Register.R0,
    field_offset: int | None = None,
    calls: tuple[SSACallStatement, ...] = (),
) -> SSAFunction:
    entry = _reg(parameter_register, address)
    statements: list[object] = list(calls)
    if field_offset is not None:
        statements.append(
            SSAReturnStatement(
                _memory_read(
                    entry,
                    field_offset,
                    4,
                    address + 4,
                ),
                _source(address + 4),
            )
        )
    else:
        statements.append(SSAReturnStatement(None, _source(address + 4)))

    return SSAFunction(
        component=component,
        address=address,
        instruction_set=InstructionSet.ARM,
        name=name,
        parameters=(_arg("arg0", parameter_register),),
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
        entry_definitions=(entry,),
    )


def _call(
    *,
    address: int,
    target: int,
    target_component: str | None,
    argument: SSAValue,
) -> SSACallStatement:
    source = _source(address)
    return SSACallStatement(
        SSACallExpression(
            "callee",
            target,
            InstructionSet.ARM,
            target_component,
            (_ref(argument, address),),
            source,
        ),
        source,
    )


def _identity(function: SSAFunction) -> FunctionTypeIdentity:
    return FunctionTypeIdentity(
        function.component,
        function.address,
        function.instruction_set,
    )


def test_unique_direct_call_propagates_structure_to_callee_argument() -> None:
    callee_address = BASE + 0x100
    caller_entry = _reg(Register.R0, BASE)
    caller = _function(
        component="arm9",
        address=BASE,
        name="caller",
        field_offset=4,
        calls=(
            _call(
                address=BASE + 8,
                target=callee_address,
                target_component="arm9",
                argument=caller_entry,
            ),
        ),
    )
    # Rebuild call argument with the actual caller entry definition.
    caller = SSAFunction(
        component=caller.component,
        address=caller.address,
        instruction_set=caller.instruction_set,
        name=caller.name,
        parameters=caller.parameters,
        locals=caller.locals,
        blocks=(
            SSABlock(
                BASE,
                InstructionSet.ARM,
                (),
                (
                    SSACallStatement(
                        SSACallExpression(
                            "callee",
                            callee_address,
                            InstructionSet.ARM,
                            "arm9",
                            (
                                _ref(
                                    caller.entry_definitions[0],
                                    BASE + 8,
                                ),
                            ),
                            _source(BASE + 8),
                        ),
                        _source(BASE + 8),
                    ),
                    SSAReturnStatement(
                        _memory_read(
                            caller.entry_definitions[0],
                            4,
                            4,
                            BASE + 4,
                        ),
                        _source(BASE + 4),
                    ),
                ),
                (),
            ),
        ),
        entry_definitions=caller.entry_definitions,
    )
    callee = _function(
        component="arm9",
        address=callee_address,
        name="callee",
        field_offset=8,
    )
    environments = (
        infer_local_types(caller),
        infer_local_types(callee),
    )

    result = propagate_interprocedural_types(
        (caller, callee),
        environments,
    )

    caller_structure = result.structure_for(
        _identity(caller),
        caller.entry_definitions[0],
    )
    callee_structure = result.structure_for(
        _identity(callee),
        callee.entry_definitions[0],
    )
    assert caller_structure is not None
    assert callee_structure is not None
    assert caller_structure.name == callee_structure.name
    assert tuple(field.offset for field in caller_structure.fields) == (4, 8)
    assert tuple(field.offset for field in callee_structure.fields) == (4, 8)
    assert caller_structure.interprocedural_support is True
    assert callee_structure.interprocedural_support is True


def test_transitive_calls_reach_fixed_point() -> None:
    a_address = BASE
    b_address = BASE + 0x100
    c_address = BASE + 0x200

    a = _function(
        component="arm9",
        address=a_address,
        name="a",
        field_offset=4,
    )
    b = _function(
        component="arm9",
        address=b_address,
        name="b",
        field_offset=8,
    )
    c = _function(
        component="arm9",
        address=c_address,
        name="c",
        field_offset=12,
    )

    def with_call(
        function: SSAFunction,
        target: SSAFunction,
    ) -> SSAFunction:
        call_source = _source(function.address + 8)
        return SSAFunction(
            component=function.component,
            address=function.address,
            instruction_set=function.instruction_set,
            name=function.name,
            parameters=function.parameters,
            locals=function.locals,
            blocks=(
                SSABlock(
                    function.address,
                    function.instruction_set,
                    (),
                    (
                        SSACallStatement(
                            SSACallExpression(
                                target.name,
                                target.address,
                                target.instruction_set,
                                target.component,
                                (
                                    _ref(
                                        function.entry_definitions[0],
                                        function.address + 8,
                                    ),
                                ),
                                call_source,
                            ),
                            call_source,
                        ),
                        *function.blocks[0].statements,
                    ),
                    (),
                ),
            ),
            entry_definitions=function.entry_definitions,
        )

    a = with_call(a, b)
    b = with_call(b, c)

    result = propagate_interprocedural_types(
        (a, b, c),
        (
            infer_local_types(a),
            infer_local_types(b),
            infer_local_types(c),
        ),
    )

    for function in (a, b, c):
        structure = result.structure_for(
            _identity(function),
            function.entry_definitions[0],
        )
        assert structure is not None
        assert tuple(field.offset for field in structure.fields) == (4, 8, 12)
    assert result.converged is True
    assert result.iterations >= 2


def test_conflicting_field_widths_do_not_merge_unsafely() -> None:
    callee_address = BASE + 0x100
    caller = _function(
        component="arm9",
        address=BASE,
        name="caller",
        field_offset=4,
    )
    callee = _function(
        component="arm9",
        address=callee_address,
        name="callee",
        field_offset=4,
    )

    # Replace callee access with a 2-byte access at the same offset.
    callee = SSAFunction(
        component=callee.component,
        address=callee.address,
        instruction_set=callee.instruction_set,
        name=callee.name,
        parameters=callee.parameters,
        locals=callee.locals,
        blocks=(
            SSABlock(
                callee.address,
                callee.instruction_set,
                (),
                (
                    SSAReturnStatement(
                        _memory_read(
                            callee.entry_definitions[0],
                            4,
                            2,
                            callee.address + 4,
                        ),
                        _source(callee.address + 4),
                    ),
                ),
                (),
            ),
        ),
        entry_definitions=callee.entry_definitions,
    )
    call_source = _source(BASE + 8)
    caller = SSAFunction(
        component=caller.component,
        address=caller.address,
        instruction_set=caller.instruction_set,
        name=caller.name,
        parameters=caller.parameters,
        locals=caller.locals,
        blocks=(
            SSABlock(
                caller.address,
                caller.instruction_set,
                (),
                (
                    SSACallStatement(
                        SSACallExpression(
                            "callee",
                            callee.address,
                            callee.instruction_set,
                            callee.component,
                            (
                                _ref(
                                    caller.entry_definitions[0],
                                    BASE + 8,
                                ),
                            ),
                            call_source,
                        ),
                        call_source,
                    ),
                    *caller.blocks[0].statements,
                ),
                (),
            ),
        ),
        entry_definitions=caller.entry_definitions,
    )

    result = propagate_interprocedural_types(
        (caller, callee),
        (
            infer_local_types(caller),
            infer_local_types(callee),
        ),
    )

    structure = result.structure_for(
        _identity(caller),
        caller.entry_definitions[0],
    )
    assert structure is not None
    assert structure.conflicts
    assert structure.should_render is False


def test_ambiguous_componentless_overlay_call_does_not_propagate() -> None:
    shared = BASE + 0x100
    caller = _function(
        component="arm9",
        address=BASE,
        name="caller",
        field_offset=4,
    )
    overlay_a = _function(
        component="overlay_a",
        address=shared,
        name="overlay_a_func",
        field_offset=8,
    )
    overlay_b = _function(
        component="overlay_b",
        address=shared,
        name="overlay_b_func",
        field_offset=12,
    )
    source = _source(BASE + 8)
    caller = SSAFunction(
        component=caller.component,
        address=caller.address,
        instruction_set=caller.instruction_set,
        name=caller.name,
        parameters=caller.parameters,
        locals=caller.locals,
        blocks=(
            SSABlock(
                caller.address,
                caller.instruction_set,
                (),
                (
                    SSACallStatement(
                        SSACallExpression(
                            "ambiguous",
                            shared,
                            InstructionSet.ARM,
                            None,
                            (
                                _ref(
                                    caller.entry_definitions[0],
                                    BASE + 8,
                                ),
                            ),
                            source,
                        ),
                        source,
                    ),
                    *caller.blocks[0].statements,
                ),
                (),
            ),
        ),
        entry_definitions=caller.entry_definitions,
    )

    result = propagate_interprocedural_types(
        (caller, overlay_a, overlay_b),
        tuple(
            infer_local_types(function)
            for function in (caller, overlay_a, overlay_b)
        ),
    )

    caller_structure = result.structure_for(
        _identity(caller),
        caller.entry_definitions[0],
    )
    assert caller_structure is not None
    assert tuple(field.offset for field in caller_structure.fields) == (4,)
    assert caller_structure.interprocedural_support is False


def test_same_numeric_address_different_components_stay_separate() -> None:
    shared = BASE + 0x100
    caller = _function(
        component="arm9",
        address=BASE,
        name="caller",
        field_offset=4,
    )
    overlay_a = _function(
        component="overlay_a",
        address=shared,
        name="overlay_a_func",
        field_offset=8,
    )
    overlay_b = _function(
        component="overlay_b",
        address=shared,
        name="overlay_b_func",
        field_offset=12,
    )
    source = _source(BASE + 8)
    caller = SSAFunction(
        component=caller.component,
        address=caller.address,
        instruction_set=caller.instruction_set,
        name=caller.name,
        parameters=caller.parameters,
        locals=caller.locals,
        blocks=(
            SSABlock(
                caller.address,
                caller.instruction_set,
                (),
                (
                    SSACallStatement(
                        SSACallExpression(
                            "overlay_a_func",
                            shared,
                            InstructionSet.ARM,
                            "overlay_a",
                            (
                                _ref(
                                    caller.entry_definitions[0],
                                    BASE + 8,
                                ),
                            ),
                            source,
                        ),
                        source,
                    ),
                    *caller.blocks[0].statements,
                ),
                (),
            ),
        ),
        entry_definitions=caller.entry_definitions,
    )

    result = propagate_interprocedural_types(
        (caller, overlay_a, overlay_b),
        tuple(
            infer_local_types(function)
            for function in (caller, overlay_a, overlay_b)
        ),
    )

    caller_structure = result.structure_for(
        _identity(caller),
        caller.entry_definitions[0],
    )
    overlay_a_structure = result.structure_for(
        _identity(overlay_a),
        overlay_a.entry_definitions[0],
    )
    overlay_b_structure = result.structure_for(
        _identity(overlay_b),
        overlay_b.entry_definitions[0],
    )
    assert caller_structure is not None
    assert overlay_a_structure is not None
    assert overlay_b_structure is not None
    assert tuple(field.offset for field in caller_structure.fields) == (4, 8)
    assert tuple(field.offset for field in overlay_a_structure.fields) == (4, 8)
    assert tuple(field.offset for field in overlay_b_structure.fields) == (12,)


def test_iteration_cap_reports_deterministic_nonconvergence() -> None:
    a = _function(
        component="arm9",
        address=BASE,
        name="a",
        field_offset=4,
    )
    b = _function(
        component="arm9",
        address=BASE + 0x100,
        name="b",
        field_offset=8,
    )
    c = _function(
        component="arm9",
        address=BASE + 0x200,
        name="c",
        field_offset=12,
    )

    def add_call(function: SSAFunction, target: SSAFunction) -> SSAFunction:
        source = _source(function.address + 8)
        return SSAFunction(
            component=function.component,
            address=function.address,
            instruction_set=function.instruction_set,
            name=function.name,
            parameters=function.parameters,
            locals=function.locals,
            blocks=(
                SSABlock(
                    function.address,
                    function.instruction_set,
                    (),
                    (
                        SSACallStatement(
                            SSACallExpression(
                                target.name,
                                target.address,
                                target.instruction_set,
                                target.component,
                                (
                                    _ref(
                                        function.entry_definitions[0],
                                        function.address + 8,
                                    ),
                                ),
                                source,
                            ),
                            source,
                        ),
                        *function.blocks[0].statements,
                    ),
                    (),
                ),
            ),
            entry_definitions=function.entry_definitions,
        )

    a = add_call(a, b)
    b = add_call(b, c)
    environments = tuple(
        infer_local_types(function)
        for function in (a, b, c)
    )

    first = propagate_interprocedural_types(
        (a, b, c),
        environments,
        iteration_cap=1,
    )
    second = propagate_interprocedural_types(
        (a, b, c),
        environments,
        iteration_cap=1,
    )

    assert first == second
    assert first.converged is False
    assert first.iterations == 1
    assert first.warnings == (
        "interprocedural type propagation reached iteration cap 1",
    )
