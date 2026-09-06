from __future__ import annotations

from typing import Any

import pytest

from nds_disassembly_toolkit.analysis.decompiler import service
from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    BinaryExpression,
    BinaryOperator,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    DecompilerVariable,
    DecompilerVariableKind,
    RegisterExpression,
    ReturnStatement,
    SourceRef,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register

BASE = 0x02006000


class _ProjectStub:
    def function(self, component: str, address: int, instruction_set: InstructionSet) -> object:
        return object()

    def cfg(self, component: str, address: int, instruction_set: InstructionSet) -> object:
        return object()

    def data_flow(
        self,
        component: str,
        address: int,
        instruction_set: InstructionSet,
    ) -> object:
        return object()


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _redundant_ir() -> DecompiledFunction:
    arg0 = DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )
    first_source = _source(BASE)
    second_source = _source(BASE + 4)
    return_source = _source(BASE + 8)
    masked = BinaryExpression(
        BinaryOperator.BITWISE_AND,
        VariableExpression(arg0, first_source),
        ConstantExpression(0, first_source),
        first_source,
    )
    added = BinaryExpression(
        BinaryOperator.ADD,
        RegisterExpression(Register.R1, second_source),
        ConstantExpression(12, second_source),
        second_source,
    )
    return DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "service_ssa",
        (arg0,),
        (),
        (
            DecompiledBlock(
                BASE,
                InstructionSet.ARM,
                (
                    AssignmentStatement(
                        RegisterExpression(Register.R1, first_source),
                        masked,
                        first_source,
                    ),
                    AssignmentStatement(
                        RegisterExpression(Register.R2, second_source),
                        added,
                        second_source,
                    ),
                    ReturnStatement(
                        RegisterExpression(Register.R2, return_source),
                        return_source,
                    ),
                ),
                (),
            ),
        ),
    )


def test_service_runs_ssa_value_facts_and_simplification_before_render(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ir = _redundant_ir()
    monkeypatch.setattr(service, "build_name_context", lambda *args: object())
    monkeypatch.setattr(service, "lift_function", lambda *args: ir)

    result = service.decompile_function(  # type: ignore[arg-type]
        _ProjectStub(),
        "arm9",
        BASE,
        InstructionSet.ARM,
    )

    assert len(result.ir.blocks[0].statements) == 1
    returned = result.ir.blocks[0].statements[0]
    assert isinstance(returned, ReturnStatement)
    assert isinstance(returned.value, ConstantExpression)
    assert returned.value.value == 12
    assert result.structured.function is result.ir
    assert result.pseudo_c == (
        "uint32_t service_ssa(uint32_t arg0) {\n"
        "    return 0xc;\n"
        "}\n"
    )


def test_service_pipeline_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ir = _redundant_ir()
    monkeypatch.setattr(service, "build_name_context", lambda *args: object())
    monkeypatch.setattr(service, "lift_function", lambda *args: ir)

    first = service.decompile_function(  # type: ignore[arg-type]
        _ProjectStub(),
        "arm9",
        BASE,
        InstructionSet.ARM,
    )
    second = service.decompile_function(  # type: ignore[arg-type]
        _ProjectStub(),
        "arm9",
        BASE,
        InstructionSet.ARM,
    )

    assert first == second
