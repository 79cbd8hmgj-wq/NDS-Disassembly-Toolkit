# Phase 7M Interprocedural Prototype and Return Recovery Implementation Plan

**Base:** `1bf14d74ae33db5f4117ca6f7497b3f0fb17e806`

**Branch:** `phase-7m-interprocedural-recovery`

**Design:** `docs/superpowers/specs/2026-09-06-phase-7m-interprocedural-recovery-design.md`

Execution remains RED -> minimal GREEN -> focused regression -> full gate.

## Global constraints

- preserve the existing decoder boundary;
- no `.ndsre` schema migration;
- no new runtime dependency;
- no second decompiler/type system;
- reuse Phase 7L `RecoveredType` models;
- preserve call side effects;
- create SSA call-result identity only for ABI `r0`;
- keep r1/r2/r3/r12/lr unknown after calls;
- no ambiguous overlay propagation;
- no guessed variadic/stack parameter ordering;
- no game-specific semantics;
- deterministic ordering and iteration caps;
- final gate includes pytest, Ruff, strict mypy, melonDS, and DeSmuME.

## Task 1 — SSA call-result heritage

### RED

Add focused SSA tests proving:

- a `CallStatement` creates a fresh SSA value for register r0;
- the returned `SSACallStatement` exposes that result value;
- a subsequent r0 reference resolves to the call-result value;
- r1/r2/r3/r12/lr remain undefined after the call;
- def-use index records the call result as a definition;
- an unused call result does not require changed source-like output;
- PHI placement can include r0 definitions from calls where control flow joins.

### GREEN

Extend the existing SSA call statement minimally, e.g. with an explicit `result: SSAValue`.
Introduce a call-result definition kind if useful for diagnostics.

Do not yet infer prototypes.

## Task 2 — Local prototype model and seeds

### RED

Create prototype-model tests for:

- stable function identity;
- ordered parameters preserving ABI location;
- UNKNOWN local parameter type;
- pointer/integer local parameter type from 7L environment;
- VOID return;
- integer return;
- pointer return;
- unknown return;
- compatible return-site merge;
- signedness widening;
- incompatible return-site conflict.

### GREEN

Create `prototype.py` with immutable models and local seed analysis.

Reuse `RecoveredType`.

## Task 3 — Call graph constraints

### RED

Test:

- caller argument -> callee parameter;
- callee parameter -> caller argument;
- callee return -> caller call-result;
- caller call-result use -> callee return;
- multiple call sites;
- transitive A->B->C;
- recursion/SCC;
- incompatible widths;
- pointer/integer conflict;
- component-less overlay ambiguity;
- component-qualified overlay call;
- iteration cap.

### GREEN

Implement deterministic prototype propagation over unique direct call identities.

Reuse/coordinate with Phase 7L structure propagation instead of duplicating its layout merge.

## Task 4 — Used call-result source lowering

### RED

Test:

- unused result renders `foo();`;
- used result receives stable source temporary or target;
- call result can feed a return;
- call result can feed field dereference;
- no SSA suffixes;
- existing call ordering preserved;
- unknown calls remain conservative.

### GREEN

Extend lowering/rendering minimally to expose a call result only when required by downstream use.

## Task 5 — Project-level prototype service

### RED

Test read-only project orchestration:

- deterministic function enumeration;
- missing CFG/data-flow functions skipped/reported conservatively;
- unique direct call resolution;
- overlay-safe identity;
- no project write;
- stable diagnostics;
- single-function lookup from project-wide result.

### GREEN

Add a read-only service that builds local SSA/type environments and runs prototype fixed point.

## Task 6 — Decompiler context integration

### RED

End-to-end tests for:

- callee signature improved by callers;
- caller call-result type improved by callee;
- typed structure shared across function boundary;
- fallback unchanged for ambiguity/conflicts;
- current `decompile_function(...)` remains source compatible.

### GREEN

Add optional recovered prototype context to the existing decompiler path.

No persistence.

## Task 7 — Docs, provenance, release

Update README, `docs/disassembly-and-analysis.md`, and provenance.

Audit allowed changes only. No decoder/schema/runtime/dependency/game coupling.

Final exact-head gate:

```text
pytest
ruff check
strict mypy
stock melonDS live smoke
managed DeSmuME live smoke
```

Ready PR, expected-head squash merge, then require fresh successful `main` CI.
