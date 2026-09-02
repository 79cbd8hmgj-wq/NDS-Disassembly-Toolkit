from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    BranchStatement,
    DecompiledBlock,
    DecompiledFunction,
    GotoNode,
    IfNode,
    LabelNode,
    LoopNode,
    ReturnStatement,
    StatementNode,
    StructuredFunction,
    StructuredNode,
)
from nds_disassembly_toolkit.analysis.model import CFGEdge, CFGEdgeKind

_LOCAL_EDGE_KINDS = frozenset({CFGEdgeKind.BRANCH, CFGEdgeKind.FALLTHROUGH})


def _block_map(function: DecompiledFunction) -> dict[int, DecompiledBlock]:
    return {block.address: block for block in function.blocks}


def _local_edges(
    block: DecompiledBlock,
    blocks: dict[int, DecompiledBlock],
) -> tuple[CFGEdge, ...]:
    return tuple(
        sorted(
            (
                edge
                for edge in block.edges
                if edge.kind in _LOCAL_EDGE_KINDS and edge.target_address in blocks
            ),
            key=lambda edge: (
                edge.kind.value,
                edge.target_address,
                edge.target_instruction_set.value,
                edge.source_instruction_address,
            ),
        )
    )


def _predecessors(function: DecompiledFunction) -> dict[int, frozenset[int]]:
    blocks = _block_map(function)
    values: dict[int, set[int]] = {address: set() for address in blocks}
    for block in function.blocks:
        for edge in _local_edges(block, blocks):
            values[edge.target_address].add(block.address)
    return {
        address: frozenset(sorted(predecessors))
        for address, predecessors in values.items()
    }


def _incoming_counts(function: DecompiledFunction) -> dict[int, int]:
    return {
        address: len(predecessors)
        for address, predecessors in _predecessors(function).items()
    }


def _dominators(function: DecompiledFunction) -> dict[int, frozenset[int]]:
    blocks = _block_map(function)
    if not blocks or function.address not in blocks:
        return {}
    predecessors = _predecessors(function)
    all_blocks = frozenset(blocks)
    dominators = {
        address: (
            frozenset({address}) if address == function.address else all_blocks
        )
        for address in blocks
    }

    changed = True
    while changed:
        changed = False
        for address in sorted(blocks):
            if address == function.address:
                continue
            parents = tuple(sorted(predecessors[address]))
            if not parents:
                updated = frozenset({address})
            else:
                shared = set(dominators[parents[0]])
                for parent in parents[1:]:
                    shared.intersection_update(dominators[parent])
                shared.add(address)
                updated = frozenset(shared)
            if updated != dominators[address]:
                dominators[address] = updated
                changed = True
    return dominators


def _back_edges(function: DecompiledFunction) -> tuple[CFGEdge, ...]:
    blocks = _block_map(function)
    dominators = _dominators(function)
    return tuple(
        sorted(
            (
                edge
                for block in function.blocks
                for edge in _local_edges(block, blocks)
                if edge.target_address in dominators.get(block.address, frozenset())
            ),
            key=lambda edge: (
                edge.target_address,
                edge.source_address,
                edge.kind.value,
                edge.source_instruction_address,
            ),
        )
    )


def _branch_statement(block: DecompiledBlock) -> BranchStatement | None:
    for statement in reversed(block.statements):
        if isinstance(statement, BranchStatement):
            return statement
    return None


def _statement_nodes(block: DecompiledBlock) -> tuple[StructuredNode, ...]:
    return tuple(
        StatementNode(statement)
        for statement in block.statements
        if not isinstance(statement, BranchStatement)
    )


def _terminates_in_return(block: DecompiledBlock) -> bool:
    return bool(block.statements) and isinstance(block.statements[-1], ReturnStatement)


def _edge_of_kind(edges: tuple[CFGEdge, ...], kind: CFGEdgeKind) -> CFGEdge | None:
    matches = tuple(edge for edge in edges if edge.kind is kind)
    return matches[0] if len(matches) == 1 else None


def _fallback_function(function: DecompiledFunction) -> StructuredFunction:
    blocks = _block_map(function)
    body: list[StructuredNode] = []
    for block in sorted(function.blocks, key=lambda item: item.address):
        body.append(LabelNode(block.address))
        body.extend(_statement_nodes(block))
        for edge in sorted(
            _local_edges(block, blocks),
            key=lambda item: (item.target_address, item.kind.value),
        ):
            body.append(GotoNode(edge.target_address))
    return StructuredFunction(function, tuple(body), True)


def _linear_region_to_header(
    start: int,
    header: int,
    blocks: dict[int, DecompiledBlock],
) -> tuple[int, ...] | None:
    region: list[int] = []
    seen: set[int] = set()
    current = start
    while current != header:
        if current in seen or current not in blocks:
            return None
        seen.add(current)
        region.append(current)
        edges = _local_edges(blocks[current], blocks)
        if len(edges) != 1:
            return None
        current = edges[0].target_address
    return tuple(region)


def _linear_region_to_latch(
    header: int,
    latch: int,
    blocks: dict[int, DecompiledBlock],
) -> tuple[int, ...] | None:
    region: list[int] = []
    seen: set[int] = set()
    current = header
    while True:
        if current in seen or current not in blocks:
            return None
        seen.add(current)
        region.append(current)
        if current == latch:
            return tuple(region)
        edges = _local_edges(blocks[current], blocks)
        if len(edges) != 1:
            return None
        current = edges[0].target_address


def _region_is_single_entry(
    region: frozenset[int],
    header: int,
    predecessors: dict[int, frozenset[int]],
) -> bool:
    for address in region:
        outside = predecessors[address] - region
        if address == header:
            if outside:
                return False
            continue
        if outside:
            return False
    return True


def _try_pretest_loop(
    block: DecompiledBlock,
    blocks: dict[int, DecompiledBlock],
    predecessors: dict[int, frozenset[int]],
    back_edges: tuple[CFGEdge, ...],
) -> tuple[LoopNode, int, frozenset[int]] | None:
    branch = _branch_statement(block)
    if branch is None or branch.condition is None or _statement_nodes(block):
        return None
    candidates = tuple(
        edge for edge in back_edges if edge.target_address == block.address
    )
    if len(candidates) != 1:
        return None
    back_edge = candidates[0]
    edges = _local_edges(block, blocks)
    if len(edges) != 2:
        return None
    taken = _edge_of_kind(edges, CFGEdgeKind.BRANCH)
    fallthrough = _edge_of_kind(edges, CFGEdgeKind.FALLTHROUGH)
    if taken is None or fallthrough is None:
        return None
    if taken.target_address == fallthrough.target_address:
        return None

    path = _linear_region_to_header(taken.target_address, block.address, blocks)
    if not path or path[-1] != back_edge.source_address:
        return None
    region = frozenset({block.address, *path})
    if not _region_is_single_entry(region, block.address, predecessors):
        return None
    if fallthrough.target_address in region:
        return None

    body: list[StructuredNode] = []
    for address in path:
        body.extend(_statement_nodes(blocks[address]))
    return (
        LoopNode(branch.condition, tuple(body), post_test=False),
        fallthrough.target_address,
        region,
    )


def _try_posttest_loop(
    block: DecompiledBlock,
    blocks: dict[int, DecompiledBlock],
    predecessors: dict[int, frozenset[int]],
    back_edges: tuple[CFGEdge, ...],
) -> tuple[LoopNode, int, frozenset[int]] | None:
    candidates = tuple(
        edge for edge in back_edges if edge.target_address == block.address
    )
    if len(candidates) != 1:
        return None
    back_edge = candidates[0]
    latch = blocks[back_edge.source_address]
    branch = _branch_statement(latch)
    if branch is None or branch.condition is None:
        return None
    latch_edges = _local_edges(latch, blocks)
    if len(latch_edges) != 2:
        return None
    taken = _edge_of_kind(latch_edges, CFGEdgeKind.BRANCH)
    fallthrough = _edge_of_kind(latch_edges, CFGEdgeKind.FALLTHROUGH)
    if taken is None or fallthrough is None:
        return None
    if taken.target_address != block.address:
        return None

    path = _linear_region_to_latch(block.address, latch.address, blocks)
    if path is None:
        return None
    region = frozenset(path)
    if not _region_is_single_entry(region, block.address, predecessors):
        return None
    if fallthrough.target_address in region:
        return None

    body: list[StructuredNode] = []
    for address in path:
        body.extend(_statement_nodes(blocks[address]))
    return (
        LoopNode(branch.condition, tuple(body), post_test=True),
        fallthrough.target_address,
        region,
    )


def _try_early_return(
    block: DecompiledBlock,
    blocks: dict[int, DecompiledBlock],
    incoming: dict[int, int],
) -> tuple[IfNode, int, frozenset[int]] | None:
    branch = _branch_statement(block)
    if branch is None or branch.condition is None:
        return None
    edges = _local_edges(block, blocks)
    if len(edges) != 2:
        return None
    taken = _edge_of_kind(edges, CFGEdgeKind.BRANCH)
    fallthrough = _edge_of_kind(edges, CFGEdgeKind.FALLTHROUGH)
    if taken is None or fallthrough is None:
        return None
    early = blocks[taken.target_address]
    if incoming[early.address] != 1:
        return None
    if _local_edges(early, blocks) or not _terminates_in_return(early):
        return None
    return (
        IfNode(branch.condition, _statement_nodes(early)),
        fallthrough.target_address,
        frozenset({block.address, early.address}),
    )


def _try_if_else(
    block: DecompiledBlock,
    blocks: dict[int, DecompiledBlock],
    incoming: dict[int, int],
) -> tuple[IfNode, int, frozenset[int]] | None:
    branch = _branch_statement(block)
    if branch is None or branch.condition is None:
        return None
    edges = _local_edges(block, blocks)
    if len(edges) != 2:
        return None
    taken = _edge_of_kind(edges, CFGEdgeKind.BRANCH)
    fallthrough = _edge_of_kind(edges, CFGEdgeKind.FALLTHROUGH)
    if taken is None or fallthrough is None:
        return None
    if taken.target_address == fallthrough.target_address:
        return None

    then_block = blocks[taken.target_address]
    else_block = blocks[fallthrough.target_address]
    if incoming[then_block.address] != 1 or incoming[else_block.address] != 1:
        return None
    then_edges = _local_edges(then_block, blocks)
    else_edges = _local_edges(else_block, blocks)
    if len(then_edges) != 1 or len(else_edges) != 1:
        return None
    join = then_edges[0].target_address
    if else_edges[0].target_address != join or join in {then_block.address, else_block.address}:
        return None
    if incoming[join] != 2:
        return None
    return (
        IfNode(
            branch.condition,
            _statement_nodes(then_block),
            _statement_nodes(else_block),
        ),
        join,
        frozenset({block.address, then_block.address, else_block.address}),
    )


def _try_if(
    block: DecompiledBlock,
    blocks: dict[int, DecompiledBlock],
    incoming: dict[int, int],
) -> tuple[IfNode, int, frozenset[int]] | None:
    branch = _branch_statement(block)
    if branch is None or branch.condition is None:
        return None
    edges = _local_edges(block, blocks)
    if len(edges) != 2:
        return None
    taken = _edge_of_kind(edges, CFGEdgeKind.BRANCH)
    fallthrough = _edge_of_kind(edges, CFGEdgeKind.FALLTHROUGH)
    if taken is None or fallthrough is None:
        return None
    then_block = blocks[taken.target_address]
    if incoming[then_block.address] != 1:
        return None
    then_edges = _local_edges(then_block, blocks)
    if len(then_edges) != 1 or then_edges[0].target_address != fallthrough.target_address:
        return None
    if incoming[fallthrough.target_address] != 2:
        return None
    return (
        IfNode(branch.condition, _statement_nodes(then_block)),
        fallthrough.target_address,
        frozenset({block.address, then_block.address}),
    )


def structure_function(function: DecompiledFunction) -> StructuredFunction:
    if not function.blocks:
        return StructuredFunction(function, (), False)

    blocks = _block_map(function)
    if len(blocks) != len(function.blocks) or function.address not in blocks:
        return _fallback_function(function)
    incoming = _incoming_counts(function)
    predecessors = _predecessors(function)
    back_edges = _back_edges(function)
    body: list[StructuredNode] = []
    consumed: set[int] = set()
    current = function.address

    while current in blocks and current not in consumed:
        block = blocks[current]
        prefix = _statement_nodes(block)
        branch = _branch_statement(block)
        edges = _local_edges(block, blocks)

        loop = _try_pretest_loop(block, blocks, predecessors, back_edges)
        if loop is None:
            loop = _try_posttest_loop(block, blocks, predecessors, back_edges)
        if loop is not None:
            loop_node, next_address, region = loop
            if consumed.intersection(region):
                return _fallback_function(function)
            body.append(loop_node)
            consumed.update(region)
            current = next_address
            continue

        if branch is not None and branch.condition is not None:
            structured = (
                _try_early_return(block, blocks, incoming)
                or _try_if_else(block, blocks, incoming)
                or _try_if(block, blocks, incoming)
            )
            if structured is None:
                return _fallback_function(function)
            if_node, next_address, region = structured
            if consumed.intersection(region):
                return _fallback_function(function)
            body.extend(prefix)
            body.append(if_node)
            consumed.update(region)
            current = next_address
            continue

        if not edges:
            body.extend(prefix)
            if branch is not None:
                body.append(StatementNode(branch))
            consumed.add(block.address)
            break

        fallthrough = _edge_of_kind(edges, CFGEdgeKind.FALLTHROUGH)
        if (
            len(edges) == 1
            and fallthrough is not None
            and incoming[fallthrough.target_address] == 1
        ):
            body.extend(prefix)
            consumed.add(block.address)
            current = fallthrough.target_address
            continue

        return _fallback_function(function)

    if len(consumed) != len(blocks):
        return _fallback_function(function)
    return StructuredFunction(function, tuple(body), False)
