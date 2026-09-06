# Phase 7N — Higher-Level Control-Flow Recovery

## Goal

Phase 7N extends the conservative Phase 7I/7K structurer beyond simple if/else and loops so
automatic decompilation can recover common Nintendo DS compiler control-flow shapes:

- switch/case;
- break and continue;
- short-circuit boolean conditions;
- simple ternary expressions where both arms are side-effect free;
- jump-table-backed switches when static table targets are provable.

The phase remains semantics-first. Unsupported or ambiguous shapes retain the existing label/goto
fallback rather than being forced into incorrect C.

## Architectural position

```text
persisted CFG + typed SSA
        ↓
Phase 7K simplification
        ↓
Phase 7L/7M types and prototypes
        ↓
Phase 7N control-flow recognition
├── compare-chain switch recognition
├── loop exit/continue recognition
├── boolean-chain folding
├── simple value-merge ternaries
└── recovered jump-table edges
        ↓
existing structured IR renderer
```

## Structured IR additions

Add immutable structured nodes:

```text
SwitchNode
├── expression
├── cases[]
└── default_body

SwitchCase
├── values[]
└── body

BreakNode
ContinueNode
```

A switch case may carry multiple integer values only when they provably share one body.

The renderer emits deterministic numeric case labels. Original enum names are not guessed in 7N.

## Compare-chain switches

The first switch recognizer operates entirely on the existing decompiler CFG.

Supported initial shape:

```text
cmp subject, C0
beq case0
cmp subject, C1
beq case1
...
default
```

Requirements:

- every comparison is equality against a constant;
- every comparison uses the same structurally equal subject expression;
- each case region is single-entry;
- every case/default region either terminates or reaches the same join;
- no case body has an external predecessor;
- no comparison node is reused from outside the chain.

If any condition, subject, or join is ambiguous, retain current fallback.

Case values are sorted numerically for rendering while case body ordering remains deterministic.

## Break and continue

Inside an already proven loop region:

- an edge to the loop exit may render as `break`;
- an edge to the loop header/latch may render as `continue`.

Only edges wholly classified by the proven natural-loop region may be rewritten. Arbitrary gotos
outside a loop remain gotos.

## Short-circuit boolean recovery

Recognize canonical CFG chains only:

```text
if (a) {
    if (b) body;
}
```

may become `if (a && b) body;` when the intermediate block has no side effects and no external
predecessor.

Equivalent false-path chains may become `||`.

No boolean algebra rewriting is performed beyond CFG-proven short circuiting.

## Ternary recovery

A simple if/else may become a ternary assignment only when:

- both arms assign exactly one compatible destination;
- both assigned expressions are side-effect free;
- both arms reach the same join;
- there are no other statements in either arm.

This is a presentation refinement and must not change SSA semantics.

## Jump-table recovery

The CFG builder currently records indirect branches as `UnresolvedTransfer`. 7N may recover a
small set of statically provable jump-table patterns while the raw `Component.data` is still
available during CFG construction.

Recovered targets use the existing `CFGEdge(kind=BRANCH)` model. Therefore no persistence schema
change is required.

Initial pattern target:

```text
ldr<cond> pc, [pc, index, lsl #2]
```

or an equivalent decoder-semantic form where:

- destination is PC;
- table base is the architectural PC value plus a constant displacement;
- index scale is exactly four bytes;
- a preceding proven bound limits the number of entries;
- every table word resolves to an aligned executable address in the same component;
- target instruction-set mode is unambiguous.

The table is rejected if any entry is out of range, misaligned, overlaps decoded code in an
incompatible way, or the bound is not statically proven.

ARM/Thumb PC semantics must use existing toolkit rules; no display-string parsing is allowed.

Additional Thumb-1 compiler patterns are deferred until individually specified and tested.

## Conditional indirect transfers

If Capstone classifies an instruction as control flow and its architectural condition code is
neither AL nor INVALID, `DecodedInstruction.conditional` must reflect that even when the mnemonic
is not a `b*` mnemonic. Any decoder adjustment must be generic and covered by regression tests.

## Persistence

No schema migration.

A recovered jump table is represented by ordinary persisted branch edges. The original unresolved
transfer is removed only when the pattern is fully recovered. Partial recovery keeps the unresolved
transfer and does not emit speculative edges.

## Determinism

Stable ordering:

- function/component/mode identity;
- block addresses;
- switch case numeric values;
- jump-table entry index;
- branch target address/mode.

No set or dictionary iteration may affect output.

## Explicitly deferred

- computed gotos that are not switches;
- indirect function-pointer calls;
- speculative table bounds;
- enum-name recovery;
- Duff's-device-like overlapping cases;
- irreducible CFG restructuring;
- general C AST optimization;
- unrestricted symbolic execution.

## Completion criteria

Phase 7N is complete when:

1. switch/break/continue structured IR exists and renders deterministically;
2. canonical equality compare chains recover to switch/case;
3. ambiguous compare chains fall back unchanged;
4. proven loop exits/backs can render break/continue;
5. canonical short-circuit boolean chains recover without side-effect reordering;
6. simple safe ternary assignments recover;
7. at least one statically proven ARM jump-table form emits persisted branch edges;
8. partial/ambiguous jump tables remain unresolved;
9. overlay/component/mode identity remains safe;
10. no schema migration or second decoder is introduced;
11. public decompile result and CLI formats remain compatible;
12. exact-head pytest, Ruff, strict mypy, melonDS, and DeSmuME pass;
13. fresh post-merge main CI passes.
