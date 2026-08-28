from __future__ import annotations

from collections.abc import Sequence

from nds_disassembly_toolkit.analysis.model import (
    CFGEdgeKind,
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
_CONFIDENCE_RANK = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}
_KIND_RANK = {
    SymbolKind.NAMED: 0,
    SymbolKind.LABEL: 1,
    SymbolKind.STRING: 2,
    SymbolKind.FUNCTION: 3,
}


def _symbol_sort_key(symbol: Symbol) -> tuple[str, int, str, str]:
    return (symbol.component, symbol.address, symbol.name, symbol.kind.value)


def _stronger_confidence(left: str, right: str) -> str:
    left_rank = _CONFIDENCE_RANK.get(left, _CONFIDENCE_RANK["unknown"])
    right_rank = _CONFIDENCE_RANK.get(right, _CONFIDENCE_RANK["unknown"])
    if right_rank > left_rank:
        return right
    return left


def _generated_name(kind: SymbolKind, address: int) -> str:
    if kind is SymbolKind.FUNCTION:
        return f"func_{address:08X}"
    if kind is SymbolKind.STRING:
        return f"str_{address:08X}"
    if kind is SymbolKind.LABEL:
        return f"loc_{address:08X}"
    raise ValueError(f"cannot generate a structural name for {kind.value}")


def _component_map(components: Sequence[Component]) -> dict[str, Component]:
    result: dict[str, Component] = {}
    for component in components:
        if component.name in result:
            raise ValueError(f"duplicate component name {component.name!r}")
        result[component.name] = component
    return result


def _validate_location(
    components: dict[str, Component],
    *,
    record_kind: str,
    component_name: str,
    address: int,
    offset: int,
) -> None:
    component = components.get(component_name)
    if component is None:
        raise ValueError(
            f"{record_kind} references unknown component {component_name!r}"
        )
    expected_offset = component.offset_for_address(address)
    if offset != expected_offset:
        raise ValueError(
            f"{record_kind} offset 0x{offset:X} does not match "
            f"{component_name} address 0x{address:X} (expected 0x{expected_offset:X})"
        )


def _validate_inputs(
    *,
    functions: Sequence[FunctionCandidate],
    strings: Sequence[StringRecord],
    cfgs: Sequence[FunctionControlFlowGraph],
    candidates: Sequence[SymbolCandidate],
    components: Sequence[Component],
) -> None:
    components_by_name = _component_map(components)

    for candidate in candidates:
        if not candidate.name.strip():
            raise ValueError("explicit symbol candidate name cannot be empty")

    if not components_by_name:
        return

    for function in functions:
        _validate_location(
            components_by_name,
            record_kind="function candidate",
            component_name=function.component,
            address=function.address,
            offset=function.offset,
        )

    for record in strings:
        _validate_location(
            components_by_name,
            record_kind="string record",
            component_name=record.component,
            address=record.address,
            offset=record.offset,
        )

    for candidate in candidates:
        _validate_location(
            components_by_name,
            record_kind="symbol candidate",
            component_name=candidate.component,
            address=candidate.address,
            offset=candidate.offset,
        )

    for cfg in cfgs:
        _validate_location(
            components_by_name,
            record_kind="CFG function",
            component_name=cfg.function.component,
            address=cfg.function.address,
            offset=cfg.function.offset,
        )
        for block in cfg.blocks:
            if block.component != cfg.function.component:
                raise ValueError(
                    f"CFG block component {block.component!r} does not match "
                    f"function component {cfg.function.component!r}"
                )
            _validate_location(
                components_by_name,
                record_kind="CFG block",
                component_name=block.component,
                address=block.address,
                offset=block.offset,
            )


def _merge_symbol(
    existing: Symbol | None,
    incoming: Symbol,
    *,
    explicit_name: str | None = None,
) -> Symbol:
    selected = (
        incoming
        if existing is None or _KIND_RANK[incoming.kind] > _KIND_RANK[existing.kind]
        else existing
    )

    confidence = incoming.confidence
    evidence = set(incoming.evidence)
    if existing is not None:
        confidence = _stronger_confidence(existing.confidence, incoming.confidence)
        evidence.update(existing.evidence)

    name = explicit_name
    if name is None:
        if existing is not None and not existing.name.startswith(("func_", "str_", "loc_")):
            name = existing.name
        elif incoming.kind is SymbolKind.NAMED:
            name = incoming.name
        else:
            name = _generated_name(selected.kind, selected.address)

    return Symbol(
        component=selected.component,
        address=selected.address,
        offset=selected.offset,
        name=name,
        kind=selected.kind,
        instruction_set=selected.instruction_set,
        confidence=confidence,
        evidence=tuple(sorted(evidence)),
    )


def build_symbol_table(
    *,
    functions: Sequence[FunctionCandidate] = (),
    strings: Sequence[StringRecord] = (),
    cfgs: Sequence[FunctionControlFlowGraph] = (),
    candidates: Sequence[SymbolCandidate] = (),
    components: Sequence[Component] = (),
) -> SymbolTable:
    _validate_inputs(
        functions=functions,
        strings=strings,
        cfgs=cfgs,
        candidates=candidates,
        components=components,
    )

    symbols: dict[_SymbolKey, Symbol] = {}

    for function in sorted(
        functions,
        key=lambda item: (
            item.component,
            item.address,
            item.offset,
            item.instruction_set.value,
            item.confidence,
            item.evidence,
        ),
    ):
        key = (function.component, function.address)
        incoming = Symbol(
            component=function.component,
            address=function.address,
            offset=function.offset,
            name=f"func_{function.address:08X}",
            kind=SymbolKind.FUNCTION,
            instruction_set=function.instruction_set,
            confidence=function.confidence,
            evidence=tuple(sorted(set(function.evidence))),
        )
        symbols[key] = _merge_symbol(symbols.get(key), incoming)

    for record in sorted(
        strings,
        key=lambda item: (item.component, item.address, item.offset, item.text),
    ):
        key = (record.component, record.address)
        incoming = Symbol(
            component=record.component,
            address=record.address,
            offset=record.offset,
            name=f"str_{record.address:08X}",
            kind=SymbolKind.STRING,
            instruction_set=None,
            confidence="high",
            evidence=(f"string {record.text!r}",),
        )
        symbols[key] = _merge_symbol(symbols.get(key), incoming)

    for cfg in sorted(
        cfgs,
        key=lambda item: (item.function.component, item.function.address),
    ):
        component = cfg.function.component
        blocks_by_address = {
            block.address: block for block in cfg.blocks if block.component == component
        }
        for edge in sorted(
            cfg.edges,
            key=lambda item: (
                item.target_address,
                item.source_instruction_address,
                item.source_address,
                item.kind.value,
            ),
        ):
            if edge.kind is not CFGEdgeKind.BRANCH:
                continue
            block = blocks_by_address.get(edge.target_address)
            if block is None:
                continue
            key = (component, edge.target_address)
            incoming = Symbol(
                component=component,
                address=edge.target_address,
                offset=block.offset,
                name=f"loc_{edge.target_address:08X}",
                kind=SymbolKind.LABEL,
                instruction_set=block.instruction_set,
                confidence="high",
                evidence=(
                    f"local branch target from 0x{edge.source_instruction_address:08X}",
                ),
            )
            symbols[key] = _merge_symbol(symbols.get(key), incoming)

    for candidate in sorted(
        candidates,
        key=lambda item: (
            item.component,
            item.address,
            item.name,
            item.offset,
            item.confidence,
            item.evidence,
        ),
    ):
        key = (candidate.component, candidate.address)
        incoming = Symbol(
            component=candidate.component,
            address=candidate.address,
            offset=candidate.offset,
            name=candidate.name,
            kind=SymbolKind.NAMED,
            instruction_set=None,
            confidence=candidate.confidence,
            evidence=(candidate.evidence,),
        )
        symbols[key] = _merge_symbol(
            symbols.get(key),
            incoming,
            explicit_name=candidate.name,
        )

    return SymbolTable(tuple(sorted(symbols.values(), key=_symbol_sort_key)))
