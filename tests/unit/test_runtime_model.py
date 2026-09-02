from __future__ import annotations

import pytest

from nds_disassembly_toolkit.analysis import InstructionSet
from nds_disassembly_toolkit.analysis.runtime import (
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)


def test_runtime_cpu_default_ports() -> None:
    assert RuntimeCpu.ARM9.default_port == 3333
    assert RuntimeCpu.ARM7.default_port == 3334


def test_register_snapshot_uses_canonical_order_then_extra_names() -> None:
    snapshot = RegisterSnapshot.from_mapping(
        {
            "cpsr": 0x20,
            "pc": 0x02000100,
            "r2": 2,
            "r0": 0,
            "banked_spsr": 0x13,
            "sp": 0x023FFF00,
        }
    )

    assert snapshot.values == (
        ("r0", 0),
        ("r2", 2),
        ("sp", 0x023FFF00),
        ("pc", 0x02000100),
        ("cpsr", 0x20),
        ("banked_spsr", 0x13),
    )
    assert snapshot.value("pc") == 0x02000100
    assert snapshot.value("missing") is None


def test_register_snapshot_rejects_negative_values() -> None:
    with pytest.raises(ValueError, match="register values must be non-negative"):
        RegisterSnapshot.from_mapping({"pc": -1})


def test_runtime_snapshot_derives_thumb_from_cpsr() -> None:
    registers = RegisterSnapshot.from_mapping({"pc": 0x02000100, "cpsr": 1 << 5})
    snapshot = RuntimeSnapshot(
        cpu=RuntimeCpu.ARM9,
        registers=registers,
        stop=RuntimeStop(StopReasonKind.STEP),
    )

    assert snapshot.pc == 0x02000100
    assert snapshot.instruction_set is InstructionSet.THUMB


def test_runtime_snapshot_derives_arm_without_thumb_bit() -> None:
    registers = RegisterSnapshot.from_mapping({"pc": 0x02000100, "cpsr": 0x13})
    snapshot = RuntimeSnapshot(
        cpu=RuntimeCpu.ARM7,
        registers=registers,
        stop=RuntimeStop(StopReasonKind.BREAKPOINT),
    )

    assert snapshot.instruction_set is InstructionSet.ARM


def test_runtime_snapshot_requires_pc_and_cpsr() -> None:
    with pytest.raises(ValueError, match="runtime snapshot requires pc and cpsr"):
        RuntimeSnapshot(
            cpu=RuntimeCpu.ARM9,
            registers=RegisterSnapshot.from_mapping({"pc": 0x02000000}),
            stop=RuntimeStop(StopReasonKind.UNKNOWN),
        )
