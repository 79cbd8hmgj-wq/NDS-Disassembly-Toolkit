from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    DecompiledBlock,
    DecompiledFunction,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import compute_dominator_info
from nds_disassembly_toolkit.analysis.model import CFGEdge, CFGEdgeKind, InstructionSet

BASE = 0x02000000


def _edge(source: int, target: int, kind: CFGEdgeKind = CFGEdgeKind.FALLTHROUGH) -> CFGEdge:
    return CFGEdge(source, source, target, InstructionSet.ARM, kind)


def _block(address: int, *edges: CFGEdge) -> DecompiledBlock:
    return DecompiledBlock(address, InstructionSet.ARM, (), tuple(edges))


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


def test_straight_line_dominators_are_exact() -> None:
    function = _function(
        _block(BASE, _edge(BASE, BASE + 4)),
        _block(BASE + 4, _edge(BASE + 4, BASE + 8)),
        _block(BASE + 8),
    )

    info = compute_dominator_info(function)

    assert info.reachable_blocks == (BASE, BASE + 4, BASE + 8)
    assert info.idom(BASE) is None
    assert info.idom(BASE + 4) == BASE
    assert info.idom(BASE + 8) == BASE + 4
    assert info.frontier(BASE) == ()
    assert info.frontier(BASE + 4) == ()
    assert info.frontier(BASE + 8) == ()


def test_diamond_places_join_in_both_branch_frontiers() -> None:
    join = BASE + 12
    function = _function(
        _block(
            BASE,
            _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
            _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        ),
        _block(BASE + 4, _edge(BASE + 4, join)),
        _block(BASE + 8, _edge(BASE + 8, join)),
        _block(join),
    )

    info = compute_dominator_info(function)

    assert info.idom(BASE + 4) == BASE
    assert info.idom(BASE + 8) == BASE
    assert info.idom(join) == BASE
    assert info.frontier(BASE + 4) == (join,)
    assert info.frontier(BASE + 8) == (join,)


def test_loop_backedge_adds_header_to_body_frontier() -> None:
    function = _function(
        _block(
            BASE,
            _edge(BASE, BASE + 4, CFGEdgeKind.BRANCH),
            _edge(BASE, BASE + 8, CFGEdgeKind.FALLTHROUGH),
        ),
        _block(BASE + 4, _edge(BASE + 4, BASE, CFGEdgeKind.BRANCH)),
        _block(BASE + 8),
    )

    info = compute_dominator_info(function)

    assert info.idom(BASE) is None
    assert info.idom(BASE + 4) == BASE
    assert info.idom(BASE + 8) == BASE
    assert info.frontier(BASE + 4) == (BASE,)


def test_unreachable_blocks_do_not_change_reachable_dominators() -> None:
    unreachable = BASE + 0x100
    function = _function(
        _block(BASE, _edge(BASE, BASE + 4)),
        _block(BASE + 4),
        _block(unreachable, _edge(unreachable, BASE + 4, CFGEdgeKind.BRANCH)),
    )

    info = compute_dominator_info(function)

    assert info.reachable_blocks == (BASE, BASE + 4)
    assert info.idom(BASE + 4) == BASE
    assert info.idom(unreachable) is None
    assert info.frontier(unreachable) == ()
