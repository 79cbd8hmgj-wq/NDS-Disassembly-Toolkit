from pathlib import Path

from nds_disassembly_toolkit.analysis.model import (
    BasicBlock,
    CFGEdge,
    CFGEdgeKind,
    Component,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
    StringRecord,
    SymbolCandidate,
    SymbolKind,
)
from nds_disassembly_toolkit.analysis.symbols import build_symbol_table

BASE = 0x02200000


def _component(name: str, base: int = BASE, size: int = 0x100) -> Component:
    return Component(name, Path(f"{name}.bin"), base, bytes(size))


def _function(
    component: str,
    address: int = BASE,
    *,
    offset: int = 0,
    instruction_set: InstructionSet = InstructionSet.ARM,
    confidence: str = "high",
    evidence: tuple[str, ...] = ("explicit entry seed",),
) -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=address,
        offset=offset,
        instruction_set=instruction_set,
        confidence=confidence,
        evidence=evidence,
    )


def _cfg_with_branch(
    component: str = "arm9",
    *,
    target: int = BASE + 0x10,
    include_target_block: bool = True,
) -> FunctionControlFlowGraph:
    function = _function(component)
    blocks = [
        BasicBlock(
            component=component,
            address=BASE,
            offset=0,
            instruction_set=InstructionSet.ARM,
            instructions=(),
        )
    ]
    if include_target_block:
        blocks.append(
            BasicBlock(
                component=component,
                address=target,
                offset=target - BASE,
                instruction_set=InstructionSet.ARM,
                instructions=(),
            )
        )
    return FunctionControlFlowGraph(
        function=function,
        blocks=tuple(blocks),
        edges=(
            CFGEdge(
                source_address=BASE,
                source_instruction_address=BASE + 4,
                target_address=target,
                target_instruction_set=InstructionSet.ARM,
                kind=CFGEdgeKind.BRANCH,
            ),
        ),
        unresolved_transfers=(),
        decode_failures=(),
    )


def test_function_candidate_becomes_component_aware_function_symbol() -> None:
    table = build_symbol_table(functions=(_function("overlay_1"),))

    assert len(table.symbols) == 1
    symbol = table.symbols[0]
    assert symbol.component == "overlay_1"
    assert symbol.address == BASE
    assert symbol.offset == 0
    assert symbol.name == "func_02200000"
    assert symbol.kind is SymbolKind.FUNCTION
    assert symbol.instruction_set is InstructionSet.ARM
    assert symbol.confidence == "high"
    assert symbol.evidence == ("explicit entry seed",)
    assert table.at_address(BASE, component="overlay_1") == (symbol,)
    assert table.for_component("overlay_1") == (symbol,)
    assert table.by_name("func_02200000") == (symbol,)


def test_string_record_becomes_string_symbol() -> None:
    record = StringRecord(
        component="arm9",
        offset=0x20,
        address=0x02000020,
        text="battle",
    )

    table = build_symbol_table(strings=(record,))

    symbol = table.symbols[0]
    assert symbol.component == "arm9"
    assert symbol.address == 0x02000020
    assert symbol.offset == 0x20
    assert symbol.name == "str_02000020"
    assert symbol.kind is SymbolKind.STRING
    assert symbol.instruction_set is None
    assert symbol.confidence == "high"
    assert symbol.evidence == ("string 'battle'",)


def test_same_runtime_address_in_two_overlays_remains_two_symbols() -> None:
    table = build_symbol_table(
        functions=(
            _function("overlay_1"),
            _function("overlay_2"),
        ),
        components=(
            _component("overlay_1"),
            _component("overlay_2"),
        ),
    )

    assert [(item.component, item.address) for item in table.symbols] == [
        ("overlay_1", BASE),
        ("overlay_2", BASE),
    ]
    assert len(table.at_address(BASE)) == 2
    assert len(table.by_name("func_02200000")) == 2
    assert table.at_address(BASE, component="overlay_1")[0].component == "overlay_1"


def test_local_cfg_branch_target_becomes_label_symbol() -> None:
    table = build_symbol_table(cfgs=(_cfg_with_branch(),))

    symbol = table.at_address(BASE + 0x10, component="arm9")[0]
    assert symbol.offset == 0x10
    assert symbol.name == "loc_02200010"
    assert symbol.kind is SymbolKind.LABEL
    assert symbol.instruction_set is InstructionSet.ARM
    assert symbol.confidence == "high"
    assert symbol.evidence == ("local branch target from 0x02200004",)


def test_external_cfg_branch_target_is_not_auto_symbolized() -> None:
    target = BASE + 0x200
    table = build_symbol_table(
        cfgs=(_cfg_with_branch(target=target, include_target_block=False),)
    )

    assert table.at_address(target) == ()


def test_explicit_name_overrides_generated_function_name_without_losing_function_role() -> None:
    candidate = SymbolCandidate(
        component="arm9",
        address=BASE,
        offset=0,
        name="BattleStart",
        confidence="medium",
        evidence="manual symbol",
    )

    table = build_symbol_table(
        functions=(_function("arm9"),),
        candidates=(candidate,),
    )

    symbol = table.at_address(BASE, component="arm9")[0]
    assert symbol.name == "BattleStart"
    assert symbol.kind is SymbolKind.FUNCTION
    assert symbol.instruction_set is InstructionSet.ARM
    assert symbol.confidence == "high"
    assert symbol.evidence == ("explicit entry seed", "manual symbol")


def test_explicit_only_candidate_becomes_named_symbol() -> None:
    candidate = SymbolCandidate(
        component="arm9",
        address=BASE + 0x24,
        offset=0x24,
        name="gBattleState",
        confidence="medium",
        evidence="user map",
    )

    table = build_symbol_table(candidates=(candidate,))

    symbol = table.at_address(BASE + 0x24, component="arm9")[0]
    assert symbol.name == "gBattleState"
    assert symbol.kind is SymbolKind.NAMED
    assert symbol.instruction_set is None
    assert symbol.confidence == "medium"
    assert symbol.evidence == ("user map",)


def test_symbol_merge_keeps_strongest_confidence_and_sorted_unique_evidence() -> None:
    candidate = SymbolCandidate(
        component="arm9",
        address=BASE,
        offset=0,
        name="EntryPoint",
        confidence="medium",
        evidence="alpha",
    )
    function = _function(
        "arm9",
        confidence="low",
        evidence=("zeta", "alpha"),
    )

    table = build_symbol_table(functions=(function,), candidates=(candidate,))

    symbol = table.at_address(BASE, component="arm9")[0]
    assert symbol.confidence == "medium"
    assert symbol.evidence == ("alpha", "zeta")
