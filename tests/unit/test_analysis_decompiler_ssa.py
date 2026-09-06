from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    BinaryExpression,
    BinaryOperator,
    BranchStatement,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    RegisterExpression,
    ReturnStatement,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAAssignmentStatement,
    SSABinaryExpression,
    SSAReferenceExpression,
    SSAReturnStatement,
    SSAStorageKind,
    build_ssa_function,
)
from nds_disassembly_toolkit.analysis.model import (
    CFGEdge,
    CFGEdgeKind,
    InstructionSet,
    Register,
)

BASE = 0x02000000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _edge(source: int, target: int, kind: CFGEdgeKind = CFGEdgeKind.FALLTHROUGH) -> CFGEdge:
    return CFGEdge(source, source, target, InstructionSet.ARM, kind)


def _assign(address: int, register: Register, value: object) -> AssignmentStatement:
    source = _source(address)
    assert isinstance(
        value,
        (ConstantExpression, RegisterExpression, BinaryExpression),
    )
    return AssignmentStatement(RegisterExpression(register, source), value, source)


def _return_register(address: int, register: Register) -> ReturnStatement:
    source = _source(address)
    return ReturnStatement(RegisterExpression(register, source), source)


def _block(address: int, statements: tuple[object, ...], *edges: CFGEdge) -> DecompiledBlock:
    return DecompiledBlock(address, InstructionSet.ARM, statements, tuple(edges))  # type: ignore[arg-type]


def _function(*blocks: DecompiledBlock) -> DecompiledFunction:
    return DecompiledFunction("arm9", BASE, InstructionSet.ARM, "entry", (), (), tuple(blocks))


def test_straight_line_register_redefinitions_get_distinct_versions() -> None:
    block = _block(
        BASE,
        (
            _assign(BASE, Register.R0, ConstantExpression(1, _source(BASE))),
            _assign(BASE + 4, Register.R0, ConstantExpression(2, _source(BASE + 4))),
            _return_register(BASE + 8, Register.R0),
        ),
    )

    result = build_ssa_function(_function(block))
    statements = result.blocks[0].statements

    first = statements[0]
    second = statements[1]
    returned = statements[2]
    assert isinstance(first, SSAAssignmentStatement)
    assert isinstance(second, SSAAssignmentStatement)
    assert isinstance(returned, SSAReturnStatement)
    assert first.target.storage.kind is SSAStorageKind.REGISTER
    assert first.target.storage.register is Register.R0
    assert (first.target.version, second.target.version) == (0, 1)
    assert isinstance(returned.value, SSAReferenceExpression)
    assert returned.value.value == second.target


def test_diamond_places_phi_and_join_uses_phi_output() -> None:
    join = BASE + 12
    entry = _block(
        BASE,
        (),
        _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
        _edge(BASE, BASE + 8),
    )
    then = _block(
        BASE + 4,
        (_assign(BASE + 4, Register.R0, ConstantExpression(1, _source(BASE + 4))),),
        _edge(BASE + 4, join),
    )
    otherwise = _block(
        BASE + 8,
        (_assign(BASE + 8, Register.R0, ConstantExpression(2, _source(BASE + 8))),),
        _edge(BASE + 8, join),
    )
    joined = _block(join, (_return_register(join, Register.R0),))

    result = build_ssa_function(_function(entry, then, otherwise, joined))
    by_address = {block.address: block for block in result.blocks}
    phi = by_address[join].phis[0]

    assert phi.output.storage.register is Register.R0
    assert tuple(item.predecessor_address for item in phi.inputs) == (BASE + 4, BASE + 8)
    assert all(item.value is not None for item in phi.inputs)
    returned = by_address[join].statements[0]
    assert isinstance(returned, SSAReturnStatement)
    assert isinstance(returned.value, SSAReferenceExpression)
    assert returned.value.value == phi.output


def test_loop_header_phi_carries_preheader_and_backedge_values() -> None:
    header = BASE + 4
    body = BASE + 8
    exit_address = BASE + 12
    initial = _assign(BASE, Register.R0, ConstantExpression(0, _source(BASE)))
    preheader = _block(BASE, (initial,), _edge(BASE, header))
    condition_source = _source(header)
    loop_header = _block(
        header,
        (
            BranchStatement(
                RegisterExpression(Register.R1, condition_source),
                body,
                InstructionSet.ARM,
                condition_source,
            ),
        ),
        _edge(header, body, CFGEdgeKind.BRANCH),
        _edge(header, exit_address),
    )
    body_source = _source(body)
    increment = BinaryExpression(
        BinaryOperator.ADD,
        RegisterExpression(Register.R0, body_source),
        ConstantExpression(1, body_source),
        body_source,
    )
    loop_body = _block(
        body,
        (_assign(body, Register.R0, increment),),
        _edge(body, header, CFGEdgeKind.BRANCH),
    )
    exit_block = _block(exit_address, (_return_register(exit_address, Register.R0),))

    result = build_ssa_function(_function(preheader, loop_header, loop_body, exit_block))
    by_address = {block.address: block for block in result.blocks}
    phi = by_address[header].phis[0]
    body_assignment = by_address[body].statements[0]

    assert tuple(item.predecessor_address for item in phi.inputs) == (BASE, body)
    assert isinstance(body_assignment, SSAAssignmentStatement)
    assert isinstance(body_assignment.value, SSABinaryExpression)
    assert isinstance(body_assignment.value.left, SSAReferenceExpression)
    assert body_assignment.value.left.value == phi.output
    assert phi.inputs[0].value is not None
    assert phi.inputs[1].value == body_assignment.target


def test_independent_registers_receive_independent_phis() -> None:
    join = BASE + 12
    entry = _block(BASE, (), _edge(BASE, BASE + 4), _edge(BASE, BASE + 8, CFGEdgeKind.BRANCH))
    then = _block(
        BASE + 4,
        (
            _assign(BASE + 4, Register.R0, ConstantExpression(1, _source(BASE + 4))),
            _assign(BASE + 4, Register.R1, ConstantExpression(10, _source(BASE + 4))),
        ),
        _edge(BASE + 4, join),
    )
    otherwise = _block(
        BASE + 8,
        (
            _assign(BASE + 8, Register.R0, ConstantExpression(2, _source(BASE + 8))),
            _assign(BASE + 8, Register.R1, ConstantExpression(20, _source(BASE + 8))),
        ),
        _edge(BASE + 8, join),
    )
    joined = _block(join, (_return_register(join, Register.R0),))

    result = build_ssa_function(_function(entry, then, otherwise, joined))
    phis = {phi.output.storage.register: phi for phi in result.block(join).phis}

    assert set(phis) == {Register.R0, Register.R1}
    assert phis[Register.R0].output.storage != phis[Register.R1].output.storage


def test_missing_definition_on_one_predecessor_stays_explicit() -> None:
    join = BASE + 12
    entry = _block(BASE, (), _edge(BASE, BASE + 4), _edge(BASE, BASE + 8, CFGEdgeKind.BRANCH))
    defined = _block(
        BASE + 4,
        (_assign(BASE + 4, Register.R0, ConstantExpression(1, _source(BASE + 4))),),
        _edge(BASE + 4, join),
    )
    undefined = _block(BASE + 8, (), _edge(BASE + 8, join))
    joined = _block(join, (_return_register(join, Register.R0),))

    result = build_ssa_function(_function(entry, defined, undefined, joined))
    phi = result.block(join).phis[0]

    assert tuple(item.value is None for item in phi.inputs) == (False, True)


def test_unreachable_definition_does_not_force_reachable_phi() -> None:
    exit_address = BASE + 4
    unreachable = BASE + 0x100
    entry = _block(BASE, (), _edge(BASE, exit_address))
    exit_block = _block(exit_address, (_return_register(exit_address, Register.R0),))
    dead = _block(
        unreachable,
        (_assign(unreachable, Register.R0, ConstantExpression(9, _source(unreachable))),),
        _edge(unreachable, exit_address, CFGEdgeKind.BRANCH),
    )

    result = build_ssa_function(_function(entry, exit_block, dead))

    assert result.block(exit_address).phis == ()
