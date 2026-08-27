from __future__ import annotations

import struct

from nds_disassembly_toolkit.analysis.model import Component, ExecutionMode, FunctionSeed


def arm_function_starts(component: Component) -> tuple[int, ...]:
    """Return aligned ARM functions beginning with STMDB SP!, {..., LR}."""
    starts: list[int] = []
    for offset in range(0, len(component.data) - 3, 4):
        word = struct.unpack_from("<I", component.data, offset)[0]
        is_stmdb_sp = word & 0xFFFF0000 == 0xE92D0000
        saves_lr = bool(word & (1 << 14))
        if is_stmdb_sp and saves_lr:
            starts.append(offset)
    return tuple(starts)


def arm_prologue_seeds(component: Component) -> tuple[FunctionSeed, ...]:
    """Convert legacy ARM prologue matches into discovery evidence."""
    return tuple(
        FunctionSeed(
            address=component.base_address + offset,
            mode=ExecutionMode.ARM,
            evidence="arm-prologue",
            confidence="medium",
        )
        for offset in arm_function_starts(component)
    )


def nearest_function_start(
    component: Component,
    offset: int,
    *,
    max_distance: int = 0x2000,
) -> int | None:
    if not 0 <= offset < len(component.data):
        raise ValueError("offset is outside component")
    if max_distance < 0:
        raise ValueError("max_distance must be non-negative")
    floor = max(0, offset - max_distance)
    for candidate in range(offset & ~3, floor - 1, -4):
        word = struct.unpack_from("<I", component.data, candidate)[0]
        if word & 0xFFFF0000 == 0xE92D0000 and word & (1 << 14):
            return candidate
    return None


def function_address_for_reference(component: Component, reference_offset: int) -> int | None:
    start = nearest_function_start(component, reference_offset)
    return None if start is None else component.base_address + start
