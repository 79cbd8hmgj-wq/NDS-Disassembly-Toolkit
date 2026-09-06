from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    DecompilerVariable,
    DecompilerVariableKind,
    MemoryReadExpression,
    MemoryWriteStatement,
    RegisterExpression,
    ReturnStatement,
    SourceRef,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAAssignmentStatement,
    SSAReferenceExpression,
    SSAStorage,
    SSAStorageKind,
    build_def_use_index,
    build_ssa_function,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x02001000


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _function(
    statements: tuple[object, ...],
    *,
    parameters: tuple[DecompilerVariable, ...] = (),
    locals_: tuple[DecompilerVariable, ...] = (),
) -> DecompiledFunction:
    block = DecompiledBlock(
        BASE,
        InstructionSet.ARM,
        statements,  # type: ignore[arg-type]
        (),
    )
    return DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "func",
        parameters,
        locals_,
        (block,),
    )


def test_exact_stack_local_is_promoted_to_stack_ssa_storage() -> None:
    local = DecompilerVariable("local_08", DecompilerVariableKind.LOCAL, stack_offset=-8)
    source = _source()
    function = _function(
        (
            AssignmentStatement(
                VariableExpression(local, source),
                ConstantExpression(7, source),
                source,
            ),
            ReturnStatement(VariableExpression(local, source), source),
        ),
        locals_=(local,),
    )

    result = build_ssa_function(function)
    assigned = result.blocks[0].statements[0]
    returned = result.blocks[0].statements[1]

    assert isinstance(assigned, SSAAssignmentStatement)
    assert assigned.target.storage.kind is SSAStorageKind.STACK
    assert assigned.target.storage.stack_offset == -8
    assert isinstance(returned.value, SSAReferenceExpression)
    assert returned.value.value == assigned.target


def test_deterministic_temporary_is_promoted_without_fake_stack_metadata() -> None:
    temporary = DecompilerVariable("tmp_3", DecompilerVariableKind.TEMPORARY)
    source = _source()
    result = build_ssa_function(
        _function(
            (
                AssignmentStatement(
                    VariableExpression(temporary, source),
                    ConstantExpression(3, source),
                    source,
                ),
                ReturnStatement(VariableExpression(temporary, source), source),
            )
        )
    )

    assigned = result.blocks[0].statements[0]
    assert isinstance(assigned, SSAAssignmentStatement)
    assert assigned.target.storage.kind is SSAStorageKind.TEMPORARY
    assert assigned.target.storage.temporary_name == "tmp_3"


def test_register_argument_is_an_explicit_entry_definition() -> None:
    argument = DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )
    source = _source()
    result = build_ssa_function(
        _function(
            (ReturnStatement(RegisterExpression(Register.R0, source), source),),
            parameters=(argument,),
        )
    )

    assert len(result.entry_definitions) == 1
    entry = result.entry_definitions[0]
    assert entry.storage.register is Register.R0
    assert entry.version == 0
    returned = result.blocks[0].statements[0]
    assert isinstance(returned.value, SSAReferenceExpression)
    assert returned.value.value == entry


def test_stack_argument_is_an_explicit_entry_definition() -> None:
    argument = DecompilerVariable(
        "stack_arg0",
        DecompilerVariableKind.ARGUMENT,
        stack_offset=4,
    )
    source = _source()
    result = build_ssa_function(
        _function(
            (ReturnStatement(VariableExpression(argument, source), source),),
            parameters=(argument,),
        )
    )

    entry = result.entry_definitions[0]
    assert entry.storage.kind is SSAStorageKind.STACK
    assert entry.storage.stack_offset == 4


def test_arbitrary_memory_is_not_promoted_as_ssa_storage() -> None:
    source = _source()
    address = RegisterExpression(Register.R1, source)
    read = MemoryReadExpression(address, 4, source)
    result = build_ssa_function(
        _function(
            (
                AssignmentStatement(RegisterExpression(Register.R0, source), read, source),
                MemoryWriteStatement(
                    address,
                    RegisterExpression(Register.R0, source),
                    4,
                    source,
                ),
            )
        )
    )

    storages = {
        definition.value.storage
        for definition in build_def_use_index(result).definitions
    }
    assert storages == {SSAStorage(SSAStorageKind.REGISTER, register=Register.R0)}


def test_def_use_index_links_assignment_and_return_use() -> None:
    source = _source()
    result = build_ssa_function(
        _function(
            (
                AssignmentStatement(
                    RegisterExpression(Register.R0, source),
                    ConstantExpression(11, source),
                    source,
                ),
                ReturnStatement(RegisterExpression(Register.R0, source), source),
            )
        )
    )
    index = build_def_use_index(result)
    assigned = result.blocks[0].statements[0]
    assert isinstance(assigned, SSAAssignmentStatement)

    definition = index.definition(assigned.target)
    uses = index.uses(assigned.target)

    assert definition is not None
    assert definition.block_address == BASE
    assert definition.statement_index == 0
    assert len(uses) == 1
    assert uses[0].block_address == BASE
    assert uses[0].statement_index == 1


def test_def_use_index_exposes_phi_by_storage_and_block() -> None:
    from nds_disassembly_toolkit.analysis.decompiler.model import BranchStatement
    from nds_disassembly_toolkit.analysis.model import CFGEdge, CFGEdgeKind

    then_address = BASE + 4
    else_address = BASE + 8
    join = BASE + 12
    source = _source()
    edge_then = CFGEdge(BASE, BASE, then_address, InstructionSet.ARM, CFGEdgeKind.BRANCH)
    edge_else = CFGEdge(BASE, BASE, else_address, InstructionSet.ARM, CFGEdgeKind.FALLTHROUGH)
    entry = DecompiledBlock(
        BASE,
        InstructionSet.ARM,
        (
            BranchStatement(
                RegisterExpression(Register.R1, source),
                then_address,
                InstructionSet.ARM,
                source,
            ),
        ),
        (edge_then, edge_else),
    )

    def branch_block(address: int, value: int) -> DecompiledBlock:
        local_source = _source(address)
        return DecompiledBlock(
            address,
            InstructionSet.ARM,
            (
                AssignmentStatement(
                    RegisterExpression(Register.R0, local_source),
                    ConstantExpression(value, local_source),
                    local_source,
                ),
            ),
            (
                CFGEdge(
                    address,
                    address,
                    join,
                    InstructionSet.ARM,
                    CFGEdgeKind.FALLTHROUGH,
                ),
            ),
        )

    joined = DecompiledBlock(
        join,
        InstructionSet.ARM,
        (ReturnStatement(RegisterExpression(Register.R0, _source(join)), _source(join)),),
        (),
    )
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "diamond",
        (),
        (),
        (entry, branch_block(then_address, 1), branch_block(else_address, 2), joined),
    )
    result = build_ssa_function(function)
    index = build_def_use_index(result)
    storage = SSAStorage(SSAStorageKind.REGISTER, register=Register.R0)
    phi = index.phi_for(storage, join)

    assert phi is not None
    assert phi.output.storage == storage
    assert len(index.uses(phi.output)) == 1
