from __future__ import annotations

import pytest

from nds_disassembly_toolkit.analysis.decompiler.model import SourceRef
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    PhiInput,
    PhiNode,
    SSAStorage,
    SSAStorageKind,
    SSAValue,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register


def test_ssa_storage_distinguishes_register_stack_and_temporary() -> None:
    register = SSAStorage(SSAStorageKind.REGISTER, register=Register.R0)
    stack = SSAStorage(SSAStorageKind.STACK, stack_offset=-8)
    temporary = SSAStorage(SSAStorageKind.TEMPORARY, temporary_name="tmp_0")

    assert register != stack
    assert stack != temporary
    assert temporary != register


def test_ssa_storage_requires_exact_kind_metadata() -> None:
    with pytest.raises(ValueError, match="register"):
        SSAStorage(SSAStorageKind.REGISTER)
    with pytest.raises(ValueError, match="stack"):
        SSAStorage(SSAStorageKind.STACK)
    with pytest.raises(ValueError, match="temporary"):
        SSAStorage(SSAStorageKind.TEMPORARY)


def test_same_storage_can_have_distinct_deterministic_versions() -> None:
    storage = SSAStorage(SSAStorageKind.REGISTER, register=Register.R0)
    source = (SourceRef(0x02000000, InstructionSet.ARM),)

    first = SSAValue(storage, 0, source)
    second = SSAValue(storage, 1, source)

    assert first.storage == second.storage
    assert first.version == 0
    assert second.version == 1
    assert first != second


def test_ssa_value_rejects_negative_version() -> None:
    storage = SSAStorage(SSAStorageKind.REGISTER, register=Register.R0)

    with pytest.raises(ValueError, match="version"):
        SSAValue(storage, -1)


def test_phi_inputs_are_canonicalized_by_predecessor_address() -> None:
    storage = SSAStorage(SSAStorageKind.REGISTER, register=Register.R0)
    output = SSAValue(storage, 2)
    low = SSAValue(storage, 0)
    high = SSAValue(storage, 1)

    phi = PhiNode(
        output,
        (
            PhiInput(0x02000020, high),
            PhiInput(0x02000010, low),
        ),
    )

    assert tuple(item.predecessor_address for item in phi.inputs) == (
        0x02000010,
        0x02000020,
    )
    assert tuple(item.value for item in phi.inputs) == (low, high)


def test_phi_rejects_duplicate_predecessor_identity() -> None:
    storage = SSAStorage(SSAStorageKind.REGISTER, register=Register.R0)
    output = SSAValue(storage, 2)

    with pytest.raises(ValueError, match="predecessor"):
        PhiNode(
            output,
            (
                PhiInput(0x02000010, SSAValue(storage, 0)),
                PhiInput(0x02000010, SSAValue(storage, 1)),
            ),
        )
