import nds_disassembly_toolkit.analysis as analysis
from nds_disassembly_toolkit.analysis.model import (
    ArgumentEvidence,
    ArgumentLocationKind,
    FunctionSummary,
    ReturnEvidence,
    StackAccess,
    StackAccessKind,
    StackAnalysis,
    StackFrame,
    StackSlot,
    StackSlotKind,
    StackState,
)


def test_stack_summary_api_is_exported() -> None:
    assert analysis.StackAccessKind is StackAccessKind
    assert analysis.StackSlotKind is StackSlotKind
    assert analysis.StackAccess is StackAccess
    assert analysis.StackSlot is StackSlot
    assert analysis.StackFrame is StackFrame
    assert analysis.StackState is StackState
    assert analysis.StackAnalysis is StackAnalysis
    assert analysis.ArgumentLocationKind is ArgumentLocationKind
    assert analysis.ArgumentEvidence is ArgumentEvidence
    assert analysis.ReturnEvidence is ReturnEvidence
    assert analysis.FunctionSummary is FunctionSummary
