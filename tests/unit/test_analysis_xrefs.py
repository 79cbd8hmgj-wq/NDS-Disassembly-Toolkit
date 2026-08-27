from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    CrossReferenceKind,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
    PointerReference,
)
from nds_disassembly_toolkit.analysis.xrefs import (
    build_call_graph,
    build_code_xrefs,
    build_data_xrefs,
    build_xref_index,
)

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


def _pointer() -> PointerReference:
    return PointerReference(
        component="arm9",
        offset=0x40,
        address=BASE + 0x40,
        target_address=BASE + 0x800,
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
    references = build_data_xrefs((_pointer(), _pointer()))

    assert len(references) == 1
    reference = references[0]
    assert reference.kind.value == "data_pointer"
    assert reference.source_component == "arm9"
    assert reference.source_address == BASE + 0x40
    assert reference.source_function_address is None
    assert reference.source_instruction_set is None
    assert reference.target_address == BASE + 0x800
    assert reference.target_instruction_set is None


def test_xref_index_queries_sources_and_targets_deterministically() -> None:
    index = build_xref_index((_cfg(), _cfg()), pointer_references=(_pointer(), _pointer()))

    assert len(index.references) == 3
    assert index.from_address(BASE + 4) == (index.references[0],)
    assert index.to_address(BASE + 0x100) == (index.references[0],)
    assert index.to_address(BASE + 0x100, kind=CrossReferenceKind.BRANCH) == ()
    assert index.to_address(BASE + 0x100, kind=CrossReferenceKind.CALL) == (
        index.references[0],
    )
    assert index.from_address(BASE + 0xDEAD) == ()


def test_call_graph_is_derived_only_from_direct_call_xrefs() -> None:
    index = build_xref_index((_cfg(),), pointer_references=(_pointer(),))

    edges = build_call_graph(index)

    assert len(edges) == 1
    edge = edges[0]
    assert edge.caller_component == "arm9"
    assert edge.caller_function_address == BASE
    assert edge.callsite_address == BASE + 4
    assert edge.target_address == BASE + 0x100
    assert edge.target_instruction_set is InstructionSet.THUMB


def test_xref_api_is_exported_from_analysis_package() -> None:
    import nds_disassembly_toolkit.analysis as analysis
    from nds_disassembly_toolkit.analysis.model import (
        CallGraphEdge,
        CrossReference,
        CrossReferenceIndex,
    )

    assert analysis.CallGraphEdge is CallGraphEdge
    assert analysis.CrossReference is CrossReference
    assert analysis.CrossReferenceIndex is CrossReferenceIndex
    assert analysis.CrossReferenceKind is CrossReferenceKind
    assert analysis.build_call_graph is build_call_graph
    assert analysis.build_code_xrefs is build_code_xrefs
    assert analysis.build_data_xrefs is build_data_xrefs
    assert analysis.build_xref_index is build_xref_index
