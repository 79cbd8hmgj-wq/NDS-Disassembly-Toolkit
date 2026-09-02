# Investigation and function prioritization

Phase 7J turns the evidence already stored in a persistent `.ndsre` project, plus optional Phase 7H `.ndstrace` differentials, into a deterministic ranked list of functions to inspect next.

The investigation engine is read-only. It does not modify the project database, persist ranking results, connect to melonDS, re-decode instructions, or run a second control-flow/data-flow analysis.

## Basic usage

Rank functions that contain an exact typed constant:

```bash
nds-toolkit project investigate game.ndsre \
  --constant 500
```

Combine a text clue, constant, and referenced address:

```bash
nds-toolkit project investigate game.ndsre \
  --text power \
  --constant 500 \
  --address 0x04000208 \
  --top 25
```

Fuse static evidence with an offline runtime behavioral differential:

```bash
nds-toolkit project investigate game.ndsre \
  --baseline idle.ndstrace \
  --target action.ndstrace \
  --top 20
```

Render conservative Phase 7I pseudo-C for only the candidates that survive ranking and truncation:

```bash
nds-toolkit project investigate game.ndsre \
  --text battle \
  --baseline idle.ndstrace \
  --target battle.ndstrace \
  --decompile \
  --top 10
```

Use `--json` for deterministic machine-readable output and `--output PATH` for atomic file replacement.

## Selectors

At least one investigation selector is required.

- `--text TEXT` performs a case-insensitive substring match against persisted strings and user annotation names/comments/tags. A matching string contributes only to functions that actually reference the string through persisted xrefs. Because persisted xrefs contain a numeric target rather than a target component, string-derived xref evidence is suppressed when multiple persisted strings from overlapping components share that runtime address.
- `--constant VALUE` is repeatable. Constants are matched only against persisted typed `IMMEDIATE` instruction operands. Human-readable assembly operand strings are never parsed for scoring.
- `--address ADDRESS` is repeatable. The engine uses persisted cross-references targeting that exact address and credits only references with a known source-function identity.
- `--component NAME` restricts static candidate functions/evidence to one persisted component.
- `--baseline TRACE --target TRACE` must be supplied as a pair. The engine delegates runtime comparison to the existing Phase 7H2 trace-differential implementation.
- `--top N` defaults to 25 and accepts 1 through 250.
- `--decompile` adds pseudo-C context after ranking. Pseudo-C does not influence the score.

Integer selectors accept normal Python-style integer syntax such as decimal and `0x` hexadecimal. Constants may be signed; addresses must be unsigned.

## Transparent scoring

Phase 7J uses fixed weights rather than a hidden or learned model:

| Evidence | Maximum contribution |
| --- | ---: |
| runtime differential | 0.35 |
| matching text/string/annotation | 0.25 |
| matching typed constant | 0.20 |
| requested-address xref | 0.15 |
| one-hop call neighbor | 0.05 |

Static selector features are binary per candidate after evidence deduplication. A runtime differential reuses the existing normalized Phase 7H2 function score and defensively clamps it into `[0, 1]` before multiplying by 0.35.

Every result exposes the individual evidence kind, value, weight, contribution, supporting addresses, and deterministic reason strings. Equal total scores are sorted by component, runtime address, and ARM/Thumb mode.

## Call-neighbor expansion

After direct evidence is collected, the engine performs exactly one call-graph expansion using persisted `CALL` xrefs:

- a function directly calling an evidence-bearing function can receive the 0.05 neighbor contribution;
- a function directly called by an evidence-bearing function can receive the same contribution;
- a neighbor-only function never recursively propagates that evidence another hop.

A numerical call target is resolved only when exactly one persisted function has the target `(runtime address, instruction set)` identity. This is important for Nintendo DS overlays: if two overlays legitimately share the same runtime address and mode, the engine refuses to guess which overlay a component-less call target means.

## Component-aware identity

Ranked functions retain the established Phase 7D identity:

```text
(component, runtime_address, instruction_set)
```

Therefore these remain independent candidates:

```text
overlay_3:0x02200000 arm
overlay_7:0x02200000 arm
```

Runtime-address equality never merges overlay functions. The same conservative rule applies to text evidence: a numeric xref is not assigned to one matching overlay string when another persisted overlay string occupies the same runtime address.

## Names and pseudo-C

Result display names use this deterministic precedence:

1. user annotation `name_override` at the exact function entry;
2. generated `FUNCTION`/`NAMED` symbol at that entry;
3. structural fallback `sub_XXXXXXXX`.

When `--decompile` is present, the existing Phase 7I `decompile_function()` service runs only after score sorting and `--top` truncation. A decompiler failure for one candidate is reported as `pseudo_c_error`; it does not remove the candidate or abort the investigation.

This keeps pseudo-C as contextual evidence rather than a hidden ranking input.

## Offline and persistence boundaries

`project investigate` opens `.ndsre` with `read_only=True`. Runtime trace files are read offline by the existing `.ndstrace` subsystem. No debugger connection is created by this command.

Phase 7J introduces:

- no `.ndsre` schema migration;
- no `.ndstrace` schema migration;
- no runtime dependency;
- no direct SQLite access from the investigation package;
- no Capstone access outside the existing decoder;
- no second runtime-differential implementation;
- no game-specific ranking rule.

The engine is intentionally a fusion/query layer over evidence already produced by Phases 7A through 7I.
