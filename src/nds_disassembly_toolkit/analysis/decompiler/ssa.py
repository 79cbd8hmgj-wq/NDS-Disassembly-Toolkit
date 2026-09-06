from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from nds_disassembly_toolkit.analysis.decompiler.model import (
    DecompiledFunction,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.model import CFGEdgeKind, Register

_U32_MAX = 0xFFFFFFFF


def _validate_u32(value: int, *, name: str) -> None:
    if not 0 <= value <= _U32_MAX:
        raise ValueError(f"{name} must be an unsigned 32-bit value")


class SSAStorageKind(StrEnum):
    REGISTER = "register"
    STACK = "stack"
    TEMPORARY = "temporary"


@dataclass(frozen=True, slots=True)
class SSAStorage:
    kind: SSAStorageKind
    register: Register | None = None
    stack_offset: int | None = None
    temporary_name: str | None = None

    def __post_init__(self) -> None:
        if self.kind is SSAStorageKind.REGISTER:
            if (
                self.register is None
                or self.stack_offset is not None
                or self.temporary_name is not None
            ):
                raise ValueError("register SSA storage requires exactly one register")
            return
        if self.kind is SSAStorageKind.STACK:
            if (
                self.stack_offset is None
                or self.register is not None
                or self.temporary_name is not None
            ):
                raise ValueError("stack SSA storage requires exactly one stack offset")
            return
        if (
            not self.temporary_name
            or self.register is not None
            or self.stack_offset is not None
        ):
            raise ValueError("temporary SSA storage requires exactly one temporary name")


@dataclass(frozen=True, slots=True)
class SSAValue:
    storage: SSAStorage
    version: int
    source: tuple[SourceRef, ...] = ()

    def __post_init__(self) -> None:
        if self.version < 0:
            raise ValueError("SSA value version must be non-negative")


@dataclass(frozen=True, slots=True)
class PhiInput:
    predecessor_address: int
    value: SSAValue | None

    def __post_init__(self) -> None:
        _validate_u32(self.predecessor_address, name="PHI predecessor address")


@dataclass(frozen=True, slots=True)
class PhiNode:
    output: SSAValue
    inputs: tuple[PhiInput, ...]

    def __post_init__(self) -> None:
        normalized = tuple(sorted(self.inputs, key=lambda item: item.predecessor_address))
        addresses = tuple(item.predecessor_address for item in normalized)
        if len(addresses) != len(set(addresses)):
            raise ValueError("PHI predecessor addresses must be unique")
        for item in normalized:
            if item.value is not None and item.value.storage != self.output.storage:
                raise ValueError("PHI input storage must match PHI output storage")
        object.__setattr__(self, "inputs", normalized)


@dataclass(frozen=True, slots=True)
class DominatorInfo:
    entry_address: int
    reachable_blocks: tuple[int, ...]
    immediate_dominators: tuple[tuple[int, int | None], ...]
    dominance_frontiers: tuple[tuple[int, tuple[int, ...]], ...]

    def idom(self, address: int) -> int | None:
        for block_address, immediate in self.immediate_dominators:
            if block_address == address:
                return immediate
        return None

    def frontier(self, address: int) -> tuple[int, ...]:
        for block_address, frontier in self.dominance_frontiers:
            if block_address == address:
                return frontier
        return ()


def _reachable_successors(function: DecompiledFunction) -> dict[int, tuple[int, ...]]:
    block_addresses = {block.address for block in function.blocks}
    successors: dict[int, tuple[int, ...]] = {}
    for block in function.blocks:
        targets = {
            edge.target_address
            for edge in block.edges
            if edge.kind is not CFGEdgeKind.CALL and edge.target_address in block_addresses
        }
        successors[block.address] = tuple(sorted(targets))
    return successors


def _find_reachable(
    entry_address: int,
    successors: dict[int, tuple[int, ...]],
) -> tuple[int, ...]:
    if entry_address not in successors:
        raise ValueError("decompiled function entry block is missing")
    seen: set[int] = set()
    pending = [entry_address]
    while pending:
        address = pending.pop()
        if address in seen:
            continue
        seen.add(address)
        pending.extend(reversed(successors[address]))
    return tuple(sorted(seen))


def _predecessors(
    reachable: tuple[int, ...],
    successors: dict[int, tuple[int, ...]],
) -> dict[int, tuple[int, ...]]:
    reachable_set = set(reachable)
    incoming: dict[int, set[int]] = {address: set() for address in reachable}
    for source in reachable:
        for target in successors[source]:
            if target in reachable_set:
                incoming[target].add(source)
    return {
        address: tuple(sorted(predecessors))
        for address, predecessors in incoming.items()
    }


def _dominator_sets(
    entry_address: int,
    reachable: tuple[int, ...],
    predecessors: dict[int, tuple[int, ...]],
) -> dict[int, set[int]]:
    all_blocks = set(reachable)
    dominators: dict[int, set[int]] = {
        address: ({entry_address} if address == entry_address else set(all_blocks))
        for address in reachable
    }

    changed = True
    while changed:
        changed = False
        for address in reachable:
            if address == entry_address:
                continue
            preds = predecessors[address]
            if not preds:
                new_set = {address}
            else:
                intersection = set(dominators[preds[0]])
                for predecessor in preds[1:]:
                    intersection.intersection_update(dominators[predecessor])
                new_set = {address, *intersection}
            if new_set != dominators[address]:
                dominators[address] = new_set
                changed = True
    return dominators


def _immediate_dominators(
    entry_address: int,
    reachable: tuple[int, ...],
    dominators: dict[int, set[int]],
) -> dict[int, int | None]:
    immediate: dict[int, int | None] = {entry_address: None}
    for address in reachable:
        if address == entry_address:
            continue
        strict = dominators[address] - {address}
        if not strict:
            immediate[address] = None
            continue
        immediate[address] = max(
            strict,
            key=lambda candidate: (len(dominators[candidate]), candidate),
        )
    return immediate


def _dominance_frontiers(
    reachable: tuple[int, ...],
    predecessors: dict[int, tuple[int, ...]],
    dominators: dict[int, set[int]],
) -> dict[int, tuple[int, ...]]:
    frontiers: dict[int, set[int]] = {address: set() for address in reachable}
    for candidate in reachable:
        for join in reachable:
            if not predecessors[join]:
                continue
            dominates_a_predecessor = any(
                candidate in dominators[predecessor]
                for predecessor in predecessors[join]
            )
            strictly_dominates_join = (
                candidate != join and candidate in dominators[join]
            )
            if dominates_a_predecessor and not strictly_dominates_join:
                frontiers[candidate].add(join)
    return {
        address: tuple(sorted(frontiers[address]))
        for address in reachable
    }


def compute_dominator_info(function: DecompiledFunction) -> DominatorInfo:
    if not function.blocks:
        raise ValueError("decompiled function has no blocks")
    addresses = [block.address for block in function.blocks]
    if len(addresses) != len(set(addresses)):
        raise ValueError("decompiled function contains duplicate block addresses")

    successors = _reachable_successors(function)
    reachable = _find_reachable(function.address, successors)
    predecessors = _predecessors(reachable, successors)
    dominators = _dominator_sets(function.address, reachable, predecessors)
    immediate = _immediate_dominators(function.address, reachable, dominators)
    frontiers = _dominance_frontiers(reachable, predecessors, dominators)

    return DominatorInfo(
        entry_address=function.address,
        reachable_blocks=reachable,
        immediate_dominators=tuple(
            (address, immediate[address])
            for address in reachable
        ),
        dominance_frontiers=tuple(
            (address, frontiers[address])
            for address in reachable
        ),
    )
