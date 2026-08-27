# Phase 7D Symbol Recovery Design

## Status

Approved continuation of the Phase 7 analysis roadmap on 2026-08-27.

## Goal

Add a deterministic, component-aware symbol layer that turns already-proven function, CFG/xref, string, and explicit candidate evidence into stable names without conflating overlapping Nintendo DS overlay address spaces.

## Scope

Phase 7D includes:

- immutable symbol kinds and symbol records;
- a component-aware `SymbolTable` with address/name queries;
- automatic function symbols from Phase 7A `FunctionCandidate` records;
- automatic local branch-label symbols from Phase 7B CFGs;
- automatic string symbols from existing `StringRecord` records;
- promotion of existing `SymbolCandidate` names as explicit/high-priority evidence;
- deterministic evidence merging and naming precedence;
- safe handling of overlapping overlay runtime ranges;
- public API exports and documentation.

Phase 7D does not include:

- struct/type inference;
- function signature recovery;
- global-variable type inference;
- jump-table recovery;
- indirect-target guessing;
- persistent on-disk analysis databases;
- user annotation editing workflows;
- CLI symbol-query commands.

Those remain later Phase 7 work.

## Symbol identity

Nintendo DS overlays may share runtime ranges, so runtime address alone is not a safe symbol identity. A symbol is keyed by `(component, address)`.

`component` is always a concrete component name for symbols emitted in Phase 7D. Targets whose component cannot be proven are not auto-symbolized. This is deliberately conservative: an external call target at `0x02201000` is not assigned to one overlay merely because several overlays cover that address.

## Models

Extend `analysis/model.py` with:

- `SymbolKind`: `FUNCTION`, `LABEL`, `STRING`, `DATA`, `NAMED`;
- `Symbol` with component, runtime address, component-relative offset when known, name, kind, optional instruction set, confidence, and stable evidence tuple;
- `SymbolTable` with immutable sorted symbols plus `at_address()`, `by_name()`, and `for_component()` queries.

`DATA` is reserved for later exact data evidence and may be supported by the model without being automatically emitted in the first Phase 7D implementation.

## Generated names

Generated names are structural rather than semantic:

- function: `func_XXXXXXXX`;
- branch label: `loc_XXXXXXXX`;
- string: `str_XXXXXXXX`.

Names intentionally use the runtime address only for readability. Because overlays can overlap, `SymbolTable.by_name()` returns a tuple rather than assuming names are globally unique.

## Evidence and precedence

Evidence at the same `(component, address)` merges into one symbol using the following precedence:

1. explicit `SymbolCandidate` name;
2. discovered function;
3. discovered string;
4. local branch target.

The selected symbol kind follows the strongest structural role: a known/discovered function remains `FUNCTION` even when an explicit name replaces `func_XXXXXXXX`; otherwise an explicit-only candidate is `NAMED`.

Evidence strings are de-duplicated and sorted. Confidence uses a stable ordering of `high > medium > low > unknown` and keeps the strongest available value.

## Function symbols

Every Phase 7A `FunctionCandidate` becomes a function symbol in its own component. Its instruction set, confidence, and discovery evidence are preserved.

## Branch-label symbols

Phase 7D consumes Phase 7B CFGs directly rather than re-decoding. A `BRANCH` edge yields a `LABEL` symbol only when its target is the start address of a block in the same CFG/component and the address is not already represented by a stronger function/string/explicit symbol role.

External direct branch targets are not auto-labeled because their component is unproven.

## String symbols

Every supplied `StringRecord` becomes a `STRING` symbol keyed by its recorded component/address. The string contents are evidence only; they are not transformed into semantic identifier names in Phase 7D.

## Explicit candidates

Existing `SymbolCandidate` records are accepted as trusted caller-provided naming evidence. Their component/address/name/confidence/evidence are preserved. An empty name is rejected. Their stored `offset` is validated against a supplied matching component when components are provided; otherwise Phase 7D preserves the candidate as supplied.

## Component validation

`build_symbol_table()` optionally receives `Component` records. When supplied, function/string/candidate records naming a known component must fall within that component's runtime range and use the expected component-relative offset where applicable.

Overlapping components remain independent because validation is by component name, never by globally searching an address range.

## Determinism

Symbols are sorted by `(component, address, name, kind)`. Evidence is sorted and de-duplicated. Queries retain canonical table order.

## Testing

Required cases:

1. function candidates become `func_XXXXXXXX` function symbols with mode/evidence;
2. local CFG branch targets become `loc_XXXXXXXX` labels;
3. external branch targets do not acquire guessed component symbols;
4. strings become `str_XXXXXXXX` symbols;
5. explicit `SymbolCandidate` names override generated names while preserving stronger function kind;
6. evidence/confidence merge deterministically;
7. two components with the same runtime address remain distinct symbols and `by_name()` can return both;
8. component/address/offset validation rejects inconsistent records;
9. public exports are available from `nds_disassembly_toolkit.analysis`.

## Compatibility

Phase 7D does not alter Phase 7A function discovery, Phase 7B CFG construction, or Phase 7C xref semantics. Later data-flow/type recovery and persistence phases should annotate or serialize this symbol table rather than creating another naming model.
