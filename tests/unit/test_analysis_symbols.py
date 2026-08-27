from pathlib import Path

from nds_disassembly_toolkit.analysis.model import (
    Component,
    FunctionCandidate,
    InstructionSet,
    StringRecord,
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
) -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=address,
        offset=offset,
        instruction_set=instruction_set,
        confidence="high",
        evidence=("explicit entry seed",),
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
