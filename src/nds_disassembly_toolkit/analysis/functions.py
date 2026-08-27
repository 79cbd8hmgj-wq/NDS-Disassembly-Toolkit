from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from nds_disassembly_toolkit.analysis.decoder import CapstoneArmDecoder, InstructionDecoder
from nds_disassembly_toolkit.analysis.model import (
    Component,
    ControlFlowKind,
    ExecutionMode,
    FunctionCandidate,
    FunctionDiscoveryResult,
    FunctionSeed,
)

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class _CandidateState:
    address: int
    mode: ExecutionMode
    confidence: str
    evidence: set[str] = field(default_factory=set)


def _stronger_confidence(current: str, incoming: str) -> str:
    current_key = (_CONFIDENCE_RANK.get(current, -1), current)
    incoming_key = (_CONFIDENCE_RANK.get(incoming, -1), incoming)
    return incoming if incoming_key > current_key else current


def _validate_seed(component: Component, seed: FunctionSeed) -> None:
    if not component.base_address <= seed.address < component.end_address:
        raise ValueError(
            f"function seed 0x{seed.address:X} is outside component {component.name}"
        )
    if seed.mode is ExecutionMode.ARM and seed.address % 4:
        raise ValueError(f"function seed 0x{seed.address:X} must be ARM aligned")
    if seed.mode is ExecutionMode.THUMB and seed.address % 2:
        raise ValueError(f"function seed 0x{seed.address:X} must be Thumb aligned")


def discover_functions(
    component: Component,
    seeds: Iterable[FunctionSeed],
    *,
    decoder: InstructionDecoder | None = None,
) -> FunctionDiscoveryResult:
    """Discover functions reachable from explicit seeds and direct calls."""

    active_decoder = decoder or CapstoneArmDecoder()
    candidates: dict[tuple[int, ExecutionMode], _CandidateState] = {}
    function_work: deque[tuple[int, ExecutionMode]] = deque()
    unresolved: set[int] = set()

    def add_candidate(seed: FunctionSeed) -> None:
        _validate_seed(component, seed)
        key = (seed.address, seed.mode)
        existing = candidates.get(key)
        if existing is None:
            candidates[key] = _CandidateState(
                address=seed.address,
                mode=seed.mode,
                confidence=seed.confidence,
                evidence={seed.evidence},
            )
            function_work.append(key)
            return
        existing.evidence.add(seed.evidence)
        existing.confidence = _stronger_confidence(existing.confidence, seed.confidence)

    for seed in seeds:
        add_candidate(seed)

    while function_work:
        function_address, function_mode = function_work.popleft()
        path_work: deque[tuple[int, ExecutionMode]] = deque(
            [(function_address, function_mode)]
        )
        visited: set[tuple[int, ExecutionMode]] = set()

        while path_work:
            address, mode = path_work.popleft()
            state = (address, mode)
            if state in visited:
                continue
            visited.add(state)
            if not component.base_address <= address < component.end_address:
                continue

            instruction = active_decoder.decode_one(component, address, mode)
            if instruction is None:
                continue

            fallthrough = (instruction.end_address, mode)

            if instruction.flow is ControlFlowKind.FALLTHROUGH:
                path_work.append(fallthrough)
                continue

            if instruction.flow is ControlFlowKind.CALL:
                if (
                    instruction.target is not None
                    and component.base_address <= instruction.target < component.end_address
                ):
                    add_candidate(
                        FunctionSeed(
                            instruction.target,
                            instruction.target_mode or mode,
                            "direct-call",
                            "high",
                        )
                    )
                path_work.append(fallthrough)
                continue

            if instruction.flow is ControlFlowKind.BRANCH:
                if (
                    instruction.target is not None
                    and component.base_address <= instruction.target < component.end_address
                ):
                    path_work.append((instruction.target, instruction.target_mode or mode))
                if instruction.conditional:
                    path_work.append(fallthrough)
                continue

            if instruction.flow is ControlFlowKind.INDIRECT_BRANCH:
                unresolved.add(instruction.address)
                if instruction.conditional:
                    path_work.append(fallthrough)
                continue

            if instruction.flow is ControlFlowKind.RETURN:
                continue

    functions = tuple(
        FunctionCandidate(
            component=component.name,
            address=state.address,
            offset=state.address - component.base_address,
            mode=state.mode,
            confidence=state.confidence,
            evidence=tuple(sorted(state.evidence)),
        )
        for _, state in sorted(
            candidates.items(), key=lambda item: (item[0][0], item[0][1].value)
        )
    )
    return FunctionDiscoveryResult(
        functions=functions,
        unresolved_indirect_transfers=tuple(sorted(unresolved)),
    )
