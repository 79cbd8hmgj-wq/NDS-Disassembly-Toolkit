from __future__ import annotations

from collections import deque
from collections.abc import Sequence

from nds_disassembly_toolkit.analysis.decoder import decode_instruction
from nds_disassembly_toolkit.analysis.model import (
    Component,
    ControlFlowKind,
    FunctionCandidate,
    FunctionDiscoveryResult,
    FunctionSeed,
    InstructionSet,
)

_FunctionKey = tuple[int, InstructionSet]


def _validate_seed(component: Component, seed: FunctionSeed) -> None:
    if not seed.source.strip():
        raise ValueError("function seed source must be nonempty")
    if not component.base_address <= seed.address < component.end_address:
        raise ValueError(f"function seed 0x{seed.address:X} is outside {component.name}")
    if seed.address % seed.instruction_set.alignment:
        raise ValueError(
            f"{seed.instruction_set.value} function seed must be "
            f"{seed.instruction_set.alignment}-byte aligned"
        )


def _local_target(
    component: Component,
    address: int,
    instruction_set: InstructionSet,
) -> bool:
    return (
        component.base_address <= address < component.end_address
        and address % instruction_set.alignment == 0
    )


def discover_functions(
    component: Component,
    *,
    seeds: Sequence[FunctionSeed],
) -> FunctionDiscoveryResult:
    evidence_by_key: dict[_FunctionKey, set[str]] = {}
    for seed in seeds:
        _validate_seed(component, seed)
        key = (seed.address, seed.instruction_set)
        evidence_by_key.setdefault(key, set()).add(seed.source)

    initial_keys = sorted(evidence_by_key, key=lambda item: (item[0], item[1].value))
    worklist = deque(initial_keys)
    queued = set(initial_keys)
    processed: set[_FunctionKey] = set()
    unresolved_calls: set[int] = set()
    decode_failures: set[int] = set()

    while worklist:
        key = worklist.popleft()
        queued.discard(key)
        if key in processed:
            continue
        processed.add(key)
        address, instruction_set = key
        cursor = address

        while cursor < component.end_address:
            offset = cursor - component.base_address
            decoded = decode_instruction(
                component.data[offset:],
                address=cursor,
                instruction_set=instruction_set,
            )
            if decoded is None:
                decode_failures.add(cursor)
                break

            if decoded.control_flow is ControlFlowKind.CALL and decoded.direct_target is not None:
                target_instruction_set = decoded.target_instruction_set or instruction_set
                call_evidence = f"direct call from 0x{decoded.address:08X}"
                if _local_target(component, decoded.direct_target, target_instruction_set):
                    target_key = (decoded.direct_target, target_instruction_set)
                    evidence_by_key.setdefault(target_key, set()).add(call_evidence)
                    if target_key not in processed and target_key not in queued:
                        worklist.append(target_key)
                        queued.add(target_key)
                else:
                    unresolved_calls.add(decoded.direct_target)

            if decoded.control_flow is ControlFlowKind.RETURN:
                break
            if decoded.control_flow is ControlFlowKind.BRANCH and not decoded.conditional:
                break

            cursor += decoded.size

    functions = tuple(
        FunctionCandidate(
            component=component.name,
            address=address,
            offset=address - component.base_address,
            instruction_set=instruction_set,
            confidence="high",
            evidence=tuple(sorted(evidence_by_key[(address, instruction_set)])),
        )
        for address, instruction_set in sorted(
            evidence_by_key,
            key=lambda item: (item[0], item[1].value),
        )
    )
    return FunctionDiscoveryResult(
        functions=functions,
        unresolved_calls=tuple(sorted(unresolved_calls)),
        decode_failures=tuple(sorted(decode_failures)),
    )
