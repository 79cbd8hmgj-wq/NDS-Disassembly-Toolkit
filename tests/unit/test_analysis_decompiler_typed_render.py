from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.lower import lower_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.model import (
    BinaryOperator,
    ConstantExpression,
    DecompilerVariable,
    DecompilerVariableKind,
    FieldAddressExpression,
    MemoryReadExpression,
    ReturnStatement,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.render import render_pseudo_c
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSABinaryExpression,
    SSABlock,
    SSAFunction,
    SSAMemoryReadExpression,
    SSAMemoryWriteStatement,
    SSAReferenceExpression,
    SSAReturnStatement,
    SSAStorage,
    SSAStorageKind,
    SSAValue,
)
from nds_disassembly_toolkit.analysis.decompiler.structure import structure_function
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    build_render_type_context,
    infer_local_types,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x02004000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _arg_value() -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=Register.R0),
        0,
        _source(BASE),
    )


def _temp(name: str, address: int) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.TEMPORARY, temporary_name=name),
        0,
        _source(address),
    )


def _ref(value: SSAValue, address: int):
    return SSAReferenceExpression(value.storage, value, _source(address))


def _address(root: SSAValue, offset: int, address: int):
    if offset == 0:
        return _ref(root, address)
    source = _source(address)
    return SSABinaryExpression(
        BinaryOperator.ADD,
        _ref(root, address),
        ConstantExpression(offset, source),
        source,
    )


def _argument() -> DecompilerVariable:
    return DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )


def _function(statements: tuple[object, ...]) -> SSAFunction:
    arg0 = _arg_value()
    return SSAFunction(
        component="arm9",
        address=BASE,
        instruction_set=InstructionSet.ARM,
        name="typed_entry",
        parameters=(_argument(),),
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
        entry_definitions=(arg0,),
    )


def _read_statement(
    root: SSAValue,
    offset: int,
    width: int,
    address: int,
    name: str,
):
    source = _source(address)
    return (
        _temp(name, address),
        SSAMemoryReadExpression(
            _address(root, offset, address),
            width,
            source,
        ),
        source,
    )


def _typed_pipeline(function: SSAFunction):
    environment = infer_local_types(function)
    lowered = lower_ssa_function(
        function,
        type_environment=environment,
    )
    structured = structure_function(lowered)
    context = build_render_type_context(function, environment)
    return (
        environment,
        lowered,
        render_pseudo_c(structured, type_context=context),
    )


def test_single_field_does_not_force_structure_rendering() -> None:
    arg0 = _arg_value()
    target, read, source = _read_statement(
        arg0,
        0x18,
        4,
        BASE + 4,
        "loaded",
    )
    function = _function(
        (
            # Keep one single-site field below the structure emission threshold.
            __import__(
                "nds_disassembly_toolkit.analysis.decompiler.ssa",
                fromlist=["SSAAssignmentStatement"],
            ).SSAAssignmentStatement(target, read, source),
            SSAReturnStatement(_ref(target, BASE + 8), _source(BASE + 8)),
        )
    )

    environment, lowered, pseudo_c = _typed_pipeline(function)

    candidate = environment.structures.candidates[0]
    assert candidate.should_render is False
    returned = lowered.blocks[0].statements[-1]
    assert isinstance(returned, ReturnStatement)
    assert isinstance(
        lowered.blocks[0].statements[0].value,  # type: ignore[union-attr]
        MemoryReadExpression,
    )
    address = lowered.blocks[0].statements[0].value.address  # type: ignore[union-attr]
    assert not isinstance(address, FieldAddressExpression)
    assert "struct struct_typed_entry_arg0" not in pseudo_c
    assert "*(uint32_t *)(arg0 + 0x18)" in pseudo_c


def test_two_fields_emit_struct_and_arrow_syntax() -> None:
    from nds_disassembly_toolkit.analysis.decompiler.ssa import (
        SSAAssignmentStatement,
    )

    arg0 = _arg_value()
    first, first_read, first_source = _read_statement(
        arg0,
        4,
        4,
        BASE + 4,
        "first",
    )
    second, second_read, second_source = _read_statement(
        arg0,
        0x18,
        2,
        BASE + 8,
        "second",
    )
    function = _function(
        (
            SSAAssignmentStatement(first, first_read, first_source),
            SSAAssignmentStatement(second, second_read, second_source),
            SSAReturnStatement(_ref(first, BASE + 12), _source(BASE + 12)),
        )
    )

    environment, lowered, pseudo_c = _typed_pipeline(function)

    candidate = environment.structures.candidates[0]
    assert candidate.should_render is True
    first_assignment = lowered.blocks[0].statements[0]
    second_assignment = lowered.blocks[0].statements[1]
    assert isinstance(first_assignment.value, MemoryReadExpression)  # type: ignore[union-attr]
    assert isinstance(first_assignment.value.address, FieldAddressExpression)  # type: ignore[union-attr]
    assert isinstance(second_assignment.value, MemoryReadExpression)  # type: ignore[union-attr]
    assert isinstance(second_assignment.value.address, FieldAddressExpression)  # type: ignore[union-attr]

    assert "struct struct_typed_entry_arg0 {" in pseudo_c
    assert "uint32_t field_04;" in pseudo_c
    assert "uint16_t field_18;" in pseudo_c
    assert (
        "uint32_t typed_entry(struct struct_typed_entry_arg0 *arg0)"
        in pseudo_c
    )
    assert "arg0->field_04" in pseudo_c
    assert "arg0->field_18" in pseudo_c
    assert ".0" not in pseudo_c


def test_field_write_renders_as_arrow_assignment() -> None:
    from nds_disassembly_toolkit.analysis.decompiler.ssa import (
        SSAAssignmentStatement,
    )

    arg0 = _arg_value()
    target, read, read_source = _read_statement(
        arg0,
        4,
        4,
        BASE + 4,
        "loaded",
    )
    write_source = _source(BASE + 8)
    function = _function(
        (
            SSAAssignmentStatement(target, read, read_source),
            SSAMemoryWriteStatement(
                _address(arg0, 8, BASE + 8),
                ConstantExpression(7, write_source),
                4,
                write_source,
            ),
            SSAReturnStatement(None, _source(BASE + 12)),
        )
    )

    _, lowered, pseudo_c = _typed_pipeline(function)

    write = lowered.blocks[0].statements[1]
    assert isinstance(write.address, FieldAddressExpression)  # type: ignore[union-attr]
    assert "arg0->field_08 = 7;" in pseudo_c


def test_old_renderer_without_type_context_remains_untyped() -> None:
    from nds_disassembly_toolkit.analysis.decompiler.ssa import (
        SSAAssignmentStatement,
    )

    arg0 = _arg_value()
    first, first_read, first_source = _read_statement(
        arg0,
        4,
        4,
        BASE + 4,
        "first",
    )
    second, second_read, second_source = _read_statement(
        arg0,
        8,
        4,
        BASE + 8,
        "second",
    )
    function = _function(
        (
            SSAAssignmentStatement(first, first_read, first_source),
            SSAAssignmentStatement(second, second_read, second_source),
            SSAReturnStatement(_ref(first, BASE + 12), _source(BASE + 12)),
        )
    )

    lowered = lower_ssa_function(function)
    pseudo_c = render_pseudo_c(structure_function(lowered))

    assert "struct " not in pseudo_c
    assert "uint32_t typed_entry(uint32_t arg0)" in pseudo_c
    assert "->field_" not in pseudo_c
    assert "*(uint32_t *)(arg0 + 4)" in pseudo_c
