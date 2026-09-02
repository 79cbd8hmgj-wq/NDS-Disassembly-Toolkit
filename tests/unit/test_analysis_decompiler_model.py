from dataclasses import FrozenInstanceError

import pytest

from nds_disassembly_toolkit.analysis import InstructionSet, Register
from nds_disassembly_toolkit.analysis.decompiler.model import (
    ConstantExpression,
    DecompilerVariable,
    DecompilerVariableKind,
    MemoryReadExpression,
    ReturnStatement,
    SourceRef,
    UnknownExpression,
)
from nds_disassembly_toolkit.errors import DecompilerError, NdsToolkitError


def test_source_ref_and_ir_nodes_are_immutable() -> None:
    source = SourceRef(0x02000000, InstructionSet.ARM)
    value = ConstantExpression(7, (source,))
    statement = ReturnStatement(value, (source,))

    assert statement.value == value
    assert statement.source == (source,)
    with pytest.raises(FrozenInstanceError):
        source.address = 0x02000004  # type: ignore[misc]


def test_source_ref_rejects_non_u32_address() -> None:
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        SourceRef(-1, InstructionSet.ARM)


def test_variable_kind_requires_matching_location_metadata() -> None:
    with pytest.raises(ValueError, match="argument"):
        DecompilerVariable("arg0", DecompilerVariableKind.ARGUMENT)
    with pytest.raises(ValueError, match="local"):
        DecompilerVariable("local_04", DecompilerVariableKind.LOCAL)
    with pytest.raises(ValueError, match="temporary"):
        DecompilerVariable(
            "tmp_0",
            DecompilerVariableKind.TEMPORARY,
            register=Register.R0,
        )


def test_memory_read_width_is_conservative() -> None:
    address = ConstantExpression(0x02001000)
    with pytest.raises(ValueError, match="width"):
        MemoryReadExpression(address, 8)


def test_unknown_expression_requires_description() -> None:
    with pytest.raises(ValueError, match="description"):
        UnknownExpression("")


def test_decompiler_error_uses_toolkit_boundary() -> None:
    assert issubclass(DecompilerError, NdsToolkitError)
