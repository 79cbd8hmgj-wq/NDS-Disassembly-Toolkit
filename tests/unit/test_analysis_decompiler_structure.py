from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    BranchStatement,
    CompareExpression,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    GotoNode,
    IfNode,
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
