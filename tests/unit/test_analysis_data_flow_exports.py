from __future__ import annotations

import nds_disassembly_toolkit.analysis as analysis
from nds_disassembly_toolkit.analysis.data_flow import analyze_data_flow
from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    AbstractValueKind,
    BlockFlowState,
    ConditionCode,
    FunctionDataFlow,
    InstructionFlowState,
    InstructionOperand,
    InstructionSemantics,
    MemoryOperand,
    OperandAccess,
    OperandKind,
    OperandShift,
    Register,
    RegisterState,
    ShiftKind,
)


def test_data_flow_api_is_exported() -> None:
    assert analysis.Register is Register
    assert analysis.ConditionCode is ConditionCode
    assert analysis.OperandKind is OperandKind
    assert analysis.OperandAccess is OperandAccess
    assert analysis.ShiftKind is ShiftKind
    assert analysis.OperandShift is OperandShift
    assert analysis.MemoryOperand is MemoryOperand
    assert analysis.InstructionOperand is InstructionOperand
    assert analysis.InstructionSemantics is InstructionSemantics
    assert analysis.AbstractValueKind is AbstractValueKind
    assert analysis.AbstractValue is AbstractValue
    assert analysis.RegisterState is RegisterState
    assert analysis.InstructionFlowState is InstructionFlowState
    assert analysis.BlockFlowState is BlockFlowState
    assert analysis.FunctionDataFlow is FunctionDataFlow
    assert analysis.analyze_data_flow is analyze_data_flow


def test_decompiler_api_is_exported() -> None:
    for name in (
        "DecompilationResult",
        "DecompilerError",
        "DecompiledFunction",
        "StructuredFunction",
    ):
        assert hasattr(analysis, name), name
