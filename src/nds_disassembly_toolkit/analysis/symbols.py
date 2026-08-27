from __future__ import annotations

from collections.abc import Sequence

from nds_disassembly_toolkit.analysis.model import (
    Component,
    FunctionCandidate,
    FunctionControlFlowGraph,
    StringRecord,
    Symbol,
    SymbolCandidate,
    SymbolKind,
    SymbolTable,
)

_SymbolKey = tuple[str, int]


def _symbol_sort_key(symbol: Symbol) -> tuple[str, int, str, str]:
    return (symbol.component, symbol.address, symbol.name, symbol.kind.value)


def build_symbol_table(
    *,
    functions: Sequence[FunctionCandidate] = (),
    strings: Sequence[StringRecord] = (),
    cfgs: Sequence[FunctionControlFlowGraph] = (),
    candidates: Sequence[SymbolCandidate] = (),
    components: Sequence[Component] = (),
) -> SymbolTable:
    symbols: dict[_SymbolKey, Symbol] = {}

    for function in functions:
        key = (function.component, function.address)
        symbols[key] = Symbol(
            component=function.component,
            address=function.address,
            offset=function.offset,
            name=f"func_{function.address:08X}",
            kind=SymbolKind.FUNCTION,
            instruction_set=function.instruction_set,
            confidence=function.confidence,
            evidence=tuple(sorted(set(function.evidence))),
        )

    for record in strings:
        key = (record.component, record.address)
        if key in symbols:
            continue
        symbols[key] = Symbol(
            component=record.component,
            address=record.address,
            offset=record.offset,
            name=f"str_{record.address:08X}",
            kind=SymbolKind.STRING,
            instruction_set=None,
            confidence="high",
            evidence=(f"string {record.text!r}",),
        )

    return SymbolTable(tuple(sorted(symbols.values(), key=_symbol_sort_key)))
