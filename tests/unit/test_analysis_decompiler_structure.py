from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    BranchStatement,
    CompareExpression,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    GotoNode,
    IfNode,
    LoopNode,
    ReturnStatement,
    SourceRef,
    StatementNode,
    UnknownStatement,
)
from nds_disassembly_toolkit.analysis.decompiler.structure import structure_function
from nds_disassembly_toolkit.analysis.model import (
    CFGEdge,
    CFGEdgeKind,
    ConditionCode,
    InstructionSet,
)

BASE = 0x02000000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _condition(address: int) -> CompareExpression:
    source = _source(address)
    return CompareExpression(
        ConditionCode.EQ,
        ConstantExpression(1, source),
        ConstantExpression(1, source),
        source,
    )


def _effect(address: int, description: str) -> UnknownStatement:
    return UnknownStatement(description, _source(address))


def _return(address: int) -> ReturnStatement:
    return ReturnStatement(None, _source(address))


def _edge(source: int, target: int, kind: CFGEdgeKind) -> CFGEdge:
    return CFGEdge(source, source, target, InstructionSet.ARM, kind)


def _block(
    address: int,
    statements: tuple[UnknownStatement | ReturnStatement | BranchStatement, ...],
    edges: tuple[CFGEdge, ...] = (),
) -> DecompiledBlock:
    return DecompiledBlock(address, InstructionSet.ARM, statements, edges)


def _function(*blocks: DecompiledBlock) -> DecompiledFunction:
    return DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "entry",
        (),
        (),
        tuple(blocks),
    )


def test_straight_line_blocks_are_folded_without_fallback() -> None:
    first = _block(
        BASE,
        (_effect(BASE, "first"),),
        (_edge(BASE, BASE + 4, CFGEdgeKind.FALLTHROUGH),),
    )
    second = _block(BASE + 4, (_effect(BASE + 4, "second"), _return(BASE + 4)))

    structured = structure_function(_function(first, second))

    assert structured.fallback_used is False
    assert [
        node.statement.description
        for node in structured.body
        if isinstance(node, StatementNode)
        and isinstance(node.statement, UnknownStatement)
    ] == ["first", "second"]


def test_conditional_diamond_without_else_becomes_if() -> None:
    condition = _condition(BASE)
    entry = _block(
        BASE,
        (BranchStatement(condition, BASE + 4, InstructionSet.ARM, _source(BASE)),),
        (
            _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
            _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        ),
    )
    then = _block(
        BASE + 4,
        (_effect(BASE + 4, "then"),),
        (_edge(BASE + 4, BASE + 8, CFGEdgeKind.FALLTHROUGH),),
    )
    join = _block(BASE + 8, (_return(BASE + 8),))

    structured = structure_function(_function(entry, then, join))

    node = next(item for item in structured.body if isinstance(item, IfNode))
    assert node.condition == condition
    assert node.then_body
    assert node.else_body == ()
    assert structured.fallback_used is False


def test_diamond_becomes_if_else() -> None:
    condition = _condition(BASE)
    entry = _block(
        BASE,
        (BranchStatement(condition, BASE + 4, InstructionSet.ARM, _source(BASE)),),
        (
            _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
            _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        ),
    )
    then = _block(
        BASE + 4,
        (_effect(BASE + 4, "then"),),
        (_edge(BASE + 4, BASE + 12, CFGEdgeKind.FALLTHROUGH),),
    )
    otherwise = _block(
        BASE + 8,
        (_effect(BASE + 8, "else"),),
        (_edge(BASE + 8, BASE + 12, CFGEdgeKind.FALLTHROUGH),),
    )
    join = _block(BASE + 12, (_return(BASE + 12),))

    structured = structure_function(_function(entry, then, otherwise, join))

    node = next(item for item in structured.body if isinstance(item, IfNode))
    assert node.condition == condition
    assert node.then_body
    assert node.else_body
    assert structured.fallback_used is False


def test_early_return_branch_becomes_if() -> None:
    condition = _condition(BASE)
    entry = _block(
        BASE,
        (BranchStatement(condition, BASE + 4, InstructionSet.ARM, _source(BASE)),),
        (
            _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
            _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        ),
    )
    early = _block(BASE + 4, (_return(BASE + 4),))
    continuation = _block(BASE + 8, (_effect(BASE + 8, "continue"), _return(BASE + 8)))

    structured = structure_function(_function(entry, early, continuation))

    node = next(item for item in structured.body if isinstance(item, IfNode))
    assert any(
        isinstance(child, StatementNode) and isinstance(child.statement, ReturnStatement)
        for child in node.then_body
    )
    assert node.else_body == ()
    assert structured.fallback_used is False


def test_unstructured_multi_entry_region_uses_labels_and_gotos() -> None:
    entry = _block(
        BASE,
        (_effect(BASE, "entry"),),
        (_edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),),
    )
    extra = _block(
        BASE + 4,
        (_effect(BASE + 4, "extra"),),
        (_edge(BASE + 4, BASE + 8, CFGEdgeKind.BRANCH),),
    )
    shared = _block(BASE + 8, (_return(BASE + 8),))

    structured = structure_function(_function(entry, extra, shared))

    assert structured.fallback_used is True
    assert any(isinstance(item, GotoNode) for item in structured.body)


def test_simple_pretest_loop_structures() -> None:
    condition = _condition(BASE)
    header = _block(
        BASE,
        (BranchStatement(condition, BASE + 4, InstructionSet.ARM, _source(BASE)),),
        (
            _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
            _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        ),
    )
    body = _block(
        BASE + 4,
        (
            _effect(BASE + 4, "body"),
            BranchStatement(None, BASE, InstructionSet.ARM, _source(BASE + 4)),
        ),
        (_edge(BASE + 4, BASE, CFGEdgeKind.BRANCH),),
    )
    exit_block = _block(BASE + 8, (_return(BASE + 8),))

    structured = structure_function(_function(header, body, exit_block))

    loop = next(item for item in structured.body if isinstance(item, LoopNode))
    assert loop.condition == condition
    assert loop.post_test is False
    assert loop.body
    assert structured.fallback_used is False


def test_simple_posttest_loop_structures() -> None:
    condition = _condition(BASE + 4)
    header = _block(
        BASE,
        (_effect(BASE, "body"),),
        (_edge(BASE, BASE + 4, CFGEdgeKind.FALLTHROUGH),),
    )
    latch = _block(
        BASE + 4,
        (
            _effect(BASE + 4, "latch"),
            BranchStatement(condition, BASE, InstructionSet.ARM, _source(BASE + 4)),
        ),
        (
            _edge(BASE + 4, BASE, CFGEdgeKind.BRANCH),
            _edge(BASE + 4, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        ),
    )
    exit_block = _block(BASE + 8, (_return(BASE + 8),))

    structured = structure_function(_function(header, latch, exit_block))

    loop = next(item for item in structured.body if isinstance(item, LoopNode))
    assert loop.condition == condition
    assert loop.post_test is True
    assert loop.body
    assert structured.fallback_used is False


def test_irreducible_back_edges_fall_back() -> None:
    entry_condition = _condition(BASE)
    latch_condition = _condition(BASE + 8)
    entry = _block(
        BASE,
        (
            BranchStatement(
                entry_condition,
                BASE + 4,
                InstructionSet.ARM,
                _source(BASE),
            ),
        ),
        (
            _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
            _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        ),
    )
    header = _block(
        BASE + 4,
        (_effect(BASE + 4, "header"),),
        (_edge(BASE + 4, BASE + 8, CFGEdgeKind.FALLTHROUGH),),
    )
    latch = _block(
        BASE + 8,
        (
            BranchStatement(
                latch_condition,
                BASE + 4,
                InstructionSet.ARM,
                _source(BASE + 8),
            ),
        ),
        (
            _edge(BASE + 8, BASE + 4, CFGEdgeKind.BRANCH),
            _edge(BASE + 8, BASE + 12, CFGEdgeKind.FALLTHROUGH),
        ),
    )
    exit_block = _block(BASE + 12, (_return(BASE + 12),))

    structured = structure_function(_function(entry, header, latch, exit_block))

    assert structured.fallback_used is True
    assert any(isinstance(item, GotoNode) for item in structured.body)
