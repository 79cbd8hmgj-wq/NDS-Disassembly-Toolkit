from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
    PointerReference,
)
from nds_disassembly_toolkit.analysis.xrefs import build_code_xrefs, build_data_xrefs

BASE = 0x02000000


def _function(address: int = BASE) -> FunctionCandidate:
    return FunctionCandidate(
        component="arm9",
        address=address,
        offset=address - BASE,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )


def _cfg() -> FunctionControlFlowGraph:
    arm_block = BasicBlock(
        component="arm9",
        address=BASE,
        offset=0,
        instruction_set=InstructionSet.ARM,
        instructions=(),
    )
    return FunctionControlFlowGraph(
        function=_function(),
        blocks=(arm_block,),
        edges=(
            CFGEdge(
                source_address=BASE,
                source_instruction_address=BASE + 4,
                target_address=BASE + 0x100,
                target_instruction_set=InstructionSet.THUMB,
                kind=CFGEdgeKind.CALL,
            ),
            CFGEdge(
                source_address=BASE,
                source_instruction_address=BASE + 8,
                target_address=BASE + 0x20,
                target_instruction_set=InstructionSet.ARM,
                kind=CFGEdgeKind.BRANCH,
            ),
            CFGEdge(
                source_address=BASE,
                source_instruction_address=BASE + 12,
                target_address=BASE + 0x10,
                target_instruction_set=InstructionSet.ARM,
                kind=CFGEdgeKind.FALLTHROUGH,
            ),
        ),
        unresolved_transfers=(),
        decode_failures=(),
    )


def test_code_xrefs_include_calls_and_branches_but_not_fallthrough() -> None:
    references = build_code_xrefs((_cfg(),))

    assert [reference.kind.value for reference in references] == ["call", "branch"]
    call, branch = references
    assert call.source_component == "arm9"
    assert call.source_function_address == BASE
    assert call.source_address == BASE + 4
    assert call.source_instruction_set is InstructionSet.ARM
    assert call.target_address == BASE + 0x100
    assert call.target_instruction_set is InstructionSet.THUMB
    assert branch.source_address == BASE + 8
    assert branch.target_address == BASE + 0x20


def test_code_xrefs_deduplicate_duplicate_cfg_inputs() -> None:
    assert build_code_xrefs((_cfg(), _cfg())) == build_code_xrefs((_cfg(),))


def test_pointer_reference_becomes_data_xref_without_invented_code_metadata() -> None:
    pointer = PointerReference(
        component="arm9",
        offset=0x40,
        address=BASE + 0x40,
        target_address=BASE + 0x800,
    )

    references = build_data_xrefs((pointer, pointer))

    assert len(references) == 1
    reference = references[0]
    assert reference.kind.value == "data_pointer"
    assert reference.source_component == "arm9"
    assert reference.source_address == BASE + 0x40
    assert reference.source_function_address is None
    assert reference.source_instruction_set is None
    assert reference.target_address == BASE + 0x800
    assert reference.target_instruction_set is None
