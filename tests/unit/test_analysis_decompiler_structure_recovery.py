from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    DecompilerVariable,
    DecompilerVariableKind,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    PhiInput,
    PhiNode,
    SSAAssignmentStatement,
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
from nds_disassembly_toolkit.analysis.decompiler.structure_recovery import (
    recover_local_structures,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x02002000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _reg(register: Register, version: int, address: int = BASE) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.REGISTER, register=register),
        version,
        _source(address),
    )


def _temp(name: str, version: int, address: int = BASE) -> SSAValue:
    return SSAValue(
        SSAStorage(SSAStorageKind.TEMPORARY, temporary_name=name),
        version,
        _source(address),
    )


def _ref(value: SSAValue, address: int) -> SSAReferenceExpression:
    return SSAReferenceExpression(value.storage, value, _source(address))


def _address(
    root: SSAValue,
    offset: int,
    address: int,
):
    from nds_disassembly_toolkit.analysis.decompiler.model import (
        BinaryOperator,
        ConstantExpression,
    )
    from nds_disassembly_toolkit.analysis.decompiler.ssa import (
        SSABinaryExpression,
    )

    if offset == 0:
        return _ref(root, address)
    return SSABinaryExpression(
        BinaryOperator.ADD,
        _ref(root, address),
        ConstantExpression(offset, _source(address)),
        _source(address),
    )


def _read(
    root: SSAValue,
    offset: int,
    width: int,
    address: int,
    target_name: str,
) -> SSAAssignmentStatement:
    target = _temp(target_name, 0, address)
    return SSAAssignmentStatement(
        target,
        SSAMemoryReadExpression(
            _address(root, offset, address),
            width,
            _source(address),
        ),
        _source(address),
    )


def _write(
    root: SSAValue,
    offset: int,
    width: int,
    address: int,
) -> SSAMemoryWriteStatement:
    from nds_disassembly_toolkit.analysis.decompiler.model import ConstantExpression

    return SSAMemoryWriteStatement(
        _address(root, offset, address),
        ConstantExpression(1, _source(address)),
        width,
        _source(address),
    )


def _function(
    parameters: tuple[DecompilerVariable, ...],
    entry_definitions: tuple[SSAValue, ...],
    blocks: tuple[SSABlock, ...],
) -> SSAFunction:
    return SSAFunction(
        component="arm9",
        address=BASE,
        instruction_set=InstructionSet.ARM,
        name="entry",
        parameters=parameters,
        locals=(),
        blocks=blocks,
        entry_definitions=entry_definitions,
    )


def _single_block_function(
    parameters: tuple[DecompilerVariable, ...],
    entry_definitions: tuple[SSAValue, ...],
    statements: tuple[object, ...],
) -> SSAFunction:
    return _function(
        parameters,
        entry_definitions,
        (
            SSABlock(
                BASE,
                InstructionSet.ARM,
                (),
                statements,  # type: ignore[arg-type]
                (),
            ),
        ),
    )


def _arg(name: str, register: Register) -> DecompilerVariable:
    return DecompilerVariable(
        name,
        DecompilerVariableKind.ARGUMENT,
        register=register,
    )


def test_two_fields_on_one_argument_produce_one_renderable_candidate() -> None:
    arg0 = _reg(Register.R0, 0)
    function = _single_block_function(
        (_arg("arg0", Register.R0),),
        (arg0,),
        (
            _read(arg0, 4, 2, BASE + 4, "a"),
            _read(arg0, 0x18, 4, BASE + 8, "b"),
        ),
    )

    result = recover_local_structures(function)

    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.root == arg0
    assert candidate.name == "struct_entry_arg0"
    assert tuple(field.offset for field in candidate.fields) == (4, 0x18)
    assert tuple(field.name for field in candidate.fields) == (
        "field_04",
        "field_18",
    )
    assert candidate.conflicts == ()
    assert candidate.should_render is True
    assert candidate.to_struct_type() is not None


def test_repeated_same_field_at_two_sites_is_renderable() -> None:
    arg0 = _reg(Register.R0, 0)
    function = _single_block_function(
        (_arg("arg0", Register.R0),),
        (arg0,),
        (
            _read(arg0, 0x10, 4, BASE + 4, "a"),
            _read(arg0, 0x10, 4, BASE + 8, "b"),
        ),
    )

    candidate = recover_local_structures(function).candidates[0]

    assert len(candidate.fields) == 1
    assert candidate.should_render is True
    assert len(candidate.accesses) == 2


def test_compatible_read_and_write_merge_field_evidence() -> None:
    arg0 = _reg(Register.R0, 0)
    function = _single_block_function(
        (_arg("arg0", Register.R0),),
        (arg0,),
        (
            _read(arg0, 8, 4, BASE + 4, "a"),
            _write(arg0, 8, 4, BASE + 8),
        ),
    )

    candidate = recover_local_structures(function).candidates[0]
    field = candidate.fields[0]

    assert field.offset == 8
    assert field.width_bytes == 4
    assert tuple(item.address for item in field.source) == (
        BASE + 4,
        BASE + 8,
    )


def test_conflicting_same_offset_widths_block_rendering() -> None:
    arg0 = _reg(Register.R0, 0)
    function = _single_block_function(
        (_arg("arg0", Register.R0),),
        (arg0,),
        (
            _read(arg0, 4, 4, BASE + 4, "a"),
            _read(arg0, 4, 2, BASE + 8, "b"),
        ),
    )

    candidate = recover_local_structures(function).candidates[0]

    assert candidate.conflicts
    assert candidate.should_render is False
    assert candidate.to_struct_type() is None


def test_overlapping_distinct_fields_block_rendering() -> None:
    arg0 = _reg(Register.R0, 0)
    function = _single_block_function(
        (_arg("arg0", Register.R0),),
        (arg0,),
        (
            _read(arg0, 4, 4, BASE + 4, "a"),
            _read(arg0, 6, 2, BASE + 8, "b"),
        ),
    )

    candidate = recover_local_structures(function).candidates[0]

    assert any("overlap" in item for item in candidate.conflicts)
    assert candidate.should_render is False


def test_exact_copy_uses_original_argument_as_canonical_root() -> None:
    arg0 = _reg(Register.R0, 0)
    copied = _reg(Register.R1, 0, BASE + 4)
    source = _source(BASE + 4)
    function = _single_block_function(
        (_arg("arg0", Register.R0),),
        (arg0,),
        (
            SSAAssignmentStatement(
                copied,
                SSAReferenceExpression(arg0.storage, arg0, source),
                source,
            ),
            _read(copied, 4, 4, BASE + 8, "a"),
            _read(copied, 8, 4, BASE + 12, "b"),
        ),
    )

    candidate = recover_local_structures(function).candidates[0]

    assert candidate.root == arg0
    assert candidate.name == "struct_entry_arg0"


def test_phi_with_one_unique_canonical_root_collapses_for_structure_identity() -> None:
    arg0 = _reg(Register.R0, 0)
    left = _reg(Register.R1, 0, BASE + 4)
    right = _reg(Register.R1, 1, BASE + 8)
    joined = _reg(Register.R1, 2, BASE + 12)
    entry_source = _source(BASE)
    left_source = _source(BASE + 4)
    right_source = _source(BASE + 8)

    block = SSABlock(
        BASE,
        InstructionSet.ARM,
        (
            PhiNode(
                joined,
                (
                    PhiInput(BASE + 4, left),
                    PhiInput(BASE + 8, right),
                ),
            ),
        ),
        (
            SSAAssignmentStatement(
                left,
                SSAReferenceExpression(arg0.storage, arg0, left_source),
                left_source,
            ),
            SSAAssignmentStatement(
                right,
                SSAReferenceExpression(arg0.storage, arg0, right_source),
                right_source,
            ),
            _read(joined, 4, 4, BASE + 16, "a"),
            _read(joined, 8, 4, BASE + 20, "b"),
        ),
        (),
    )
    function = _function(
        (_arg("arg0", Register.R0),),
        (arg0,),
        (block,),
    )

    candidate = recover_local_structures(function).candidates[0]

    assert candidate.root == arg0


def test_phi_with_conflicting_roots_does_not_unify_arguments() -> None:
    arg0 = _reg(Register.R0, 0)
    arg1 = _reg(Register.R1, 0)
    left = _reg(Register.R2, 0, BASE + 4)
    right = _reg(Register.R2, 1, BASE + 8)
    joined = _reg(Register.R2, 2, BASE + 12)
    left_source = _source(BASE + 4)
    right_source = _source(BASE + 8)

    block = SSABlock(
        BASE,
        InstructionSet.ARM,
        (
            PhiNode(
                joined,
                (
                    PhiInput(BASE + 4, left),
                    PhiInput(BASE + 8, right),
                ),
            ),
        ),
        (
            SSAAssignmentStatement(
                left,
                SSAReferenceExpression(arg0.storage, arg0, left_source),
                left_source,
            ),
            SSAAssignmentStatement(
                right,
                SSAReferenceExpression(arg1.storage, arg1, right_source),
                right_source,
            ),
            _read(joined, 4, 4, BASE + 16, "a"),
            _read(joined, 8, 4, BASE + 20, "b"),
        ),
        (),
    )
    function = _function(
        (
            _arg("arg0", Register.R0),
            _arg("arg1", Register.R1),
        ),
        (arg0, arg1),
        (block,),
    )

    candidate = recover_local_structures(function).candidates[0]

    assert candidate.root == joined
    assert candidate.root not in {arg0, arg1}


def test_different_parameters_with_same_offsets_remain_separate() -> None:
    arg0 = _reg(Register.R0, 0)
    arg1 = _reg(Register.R1, 0)
    function = _single_block_function(
        (
            _arg("arg0", Register.R0),
            _arg("arg1", Register.R1),
        ),
        (arg0, arg1),
        (
            _read(arg0, 4, 4, BASE + 4, "a"),
            _read(arg0, 8, 4, BASE + 8, "b"),
            _read(arg1, 4, 4, BASE + 12, "c"),
            _read(arg1, 8, 4, BASE + 16, "d"),
        ),
    )

    result = recover_local_structures(function)

    assert len(result.candidates) == 2
    assert tuple(candidate.root for candidate in result.candidates) == (
        arg0,
        arg1,
    )
    assert tuple(candidate.name for candidate in result.candidates) == (
        "struct_entry_arg0",
        "struct_entry_arg1",
    )


def test_one_single_site_field_is_not_rendered_yet() -> None:
    arg0 = _reg(Register.R0, 0)
    function = _single_block_function(
        (_arg("arg0", Register.R0),),
        (arg0,),
        (_read(arg0, 4, 4, BASE + 4, "a"),),
    )

    candidate = recover_local_structures(function).candidates[0]

    assert candidate.should_render is False
    assert candidate.conflicts == ()


def test_indexed_access_does_not_create_direct_structure_field() -> None:
    from nds_disassembly_toolkit.analysis.decompiler.model import (
        BinaryOperator,
        ConstantExpression,
    )
    from nds_disassembly_toolkit.analysis.decompiler.ssa import SSABinaryExpression

    arg0 = _reg(Register.R0, 0)
    index = _reg(Register.R1, 0)
    source = _source(BASE + 4)
    address = SSABinaryExpression(
        BinaryOperator.ADD,
        _ref(arg0, BASE + 4),
        SSABinaryExpression(
            BinaryOperator.MULTIPLY,
            _ref(index, BASE + 4),
            ConstantExpression(4, source),
            source,
        ),
        source,
    )
    function = _single_block_function(
        (
            _arg("arg0", Register.R0),
            _arg("arg1", Register.R1),
        ),
        (arg0, index),
        (
            SSAReturnStatement(
                SSAMemoryReadExpression(address, 4, source),
                source,
            ),
        ),
    )

    result = recover_local_structures(function)

    assert result.candidates == ()
    assert len(result.indexed_accesses) == 1
