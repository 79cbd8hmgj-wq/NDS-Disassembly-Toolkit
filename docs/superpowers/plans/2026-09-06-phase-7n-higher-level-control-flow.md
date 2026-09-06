# Phase 7N Higher-Level Control-Flow Implementation Plan

**Base:** `4b08df5a3a070fffafa10d4064f58e89d0c525d1`

**Branch:** `phase-7n-higher-level-control-flow`

## Task 1 — Structured switch IR and renderer

RED:

- immutable `SwitchCase` / `SwitchNode`;
- deterministic case ordering;
- multiple values sharing one body;
- default body;
- nested rendering;
- no change to old nodes.

GREEN: model + renderer only.

## Task 2 — Compare-chain switch recovery

RED:

- two-case equality chain + default;
- three cases;
- reversed constant/subject comparison;
- case with return;
- common join;
- repeated values rejected;
- different subjects rejected;
- external predecessor rejected;
- non-equality comparison rejected;
- ambiguous join falls back.

GREEN: conservative structurer recognizer.

## Task 3 — Loop break/continue

RED:

- conditional break to loop exit;
- conditional continue to header;
- post-test loop continue;
- external/goto edges remain fallback.

GREEN: loop-region-aware `BreakNode` / `ContinueNode`.

## Task 4 — Short-circuit booleans

RED:

- canonical AND;
- canonical OR;
- nested chain;
- side-effecting intermediate blocks reject;
- external predecessor rejects.

GREEN: expression composition over already-proven CFG shape.

## Task 5 — Simple ternary values

RED:

- one-destination if/else assignment;
- side-effect-free arms;
- different destinations reject;
- calls/memory writes reject;
- type/presentation compatibility.

GREEN: optional expression/statement lowering refinement.

## Task 6 — Conditional indirect control-flow correctness

RED decoder tests for conditional indirect branch/call semantics where Capstone exposes a
non-AL condition code.

GREEN: generic condition-code-based `DecodedInstruction.conditional` rule.

## Task 7 — ARM word jump-table recovery

RED CFG tests with raw component bytes:

- valid bounded `ldr pc, [pc, index, lsl #2]` table;
- deterministic recovered branch edges;
- default/fallthrough when condition permits;
- out-of-range target rejects;
- misaligned target rejects;
- unproven bound rejects;
- partial table rejects completely;
- unresolved transfer retained on rejection.

GREEN: small CFG-local recovery helper; existing branch-edge persistence only.

## Task 8 — Switch recovery from jump-table CFG

RED:

- recovered multi-target branch is converted to `SwitchNode`;
- numeric case labels match table indexes;
- default preserved;
- shared targets coalesce case values;
- ambiguous/non-table multi-target branch stays fallback.

If persisted branch edges alone cannot preserve the case-index mapping without ambiguity, stop and
introduce a versioned derived decompiler hint rather than guessing. Do not silently infer labels
from target sort order.

## Task 9 — Docs/provenance/release

Update README, disassembly docs, provenance boundary, and design limitations.

Scope audit:

- no schema migration unless Task 8 demonstrates an unavoidable blocker and a separate approved
  design is created;
- no runtime/orchestration changes;
- no game-specific logic;
- no second decoder;
- no third-party source incorporation.

Release:

```text
pytest
ruff check
strict mypy
stock melonDS smoke
managed DeSmuME smoke
```

Then expected-head squash merge and fresh main CI.
