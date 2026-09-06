# Phase 7K SSA and Decompiler IR v2 Implementation Plan

> **Execution mode:** implement task-by-task with RED → minimal GREEN → focused regression → commit. Keep the existing Phase 7I public decompiler contract stable throughout.

**Goal:** Insert a toolkit-owned SSA/value-fact/simplification layer between Phase 7I lifting and source-like rendering so ARM/Thumb decompilation can eliminate register churn, reason across CFG joins and loops, and prepare for later type/structure/interprocedural recovery.

**Base:** `phase-7k-ssa-ir-v2` from current `main` `34ab25b109ec63540dd87aa9a4d48f7f32d89705`.

**Spec:** `docs/superpowers/specs/2026-09-05-phase-7k-ssa-ir-v2-design.md`

## Global constraints

- No new decoder and no direct Capstone use outside `analysis/decoder.py`.
- No `.ndsre` schema/version migration.
- No new runtime dependency.
- No Ghidra/LLVM/RetDec/Miasm/angr runtime dependency.
- Miasm is GPL reference-only.
- Ghidra, RetDec, and LLVM remain architecture/algorithm references in 7K; do not copy implementation source.
- Preserve overlay-safe component identity.
- Promote only exact registers, exact recovered stack slots, and deterministic decompiler temporaries.
- Do not promote arbitrary memory; no general memory SSA in 7K.
- Preserve memory writes, calls, unknown operations, and other side effects through simplification.
- Keep `decompile_function()`, `DecompilationResult`, and `project decompile` compatible.
- Every algorithm must use deterministic ordering.
- Full release gate: pytest + Ruff + strict mypy + stock-melonDS CI + exact-head PR + post-merge `main`.

## Expected file map

Create:

```text
src/nds_disassembly_toolkit/analysis/decompiler/ssa.py
src/nds_disassembly_toolkit/analysis/decompiler/value_facts.py
src/nds_disassembly_toolkit/analysis/decompiler/simplify.py
src/nds_disassembly_toolkit/analysis/decompiler/lower.py

tests/unit/test_analysis_decompiler_ssa_model.py
tests/unit/test_analysis_decompiler_dominators.py
tests/unit/test_analysis_decompiler_ssa.py
tests/unit/test_analysis_decompiler_value_facts.py
tests/unit/test_analysis_decompiler_simplify.py
tests/unit/test_analysis_decompiler_ssa_integration.py
```

Modify as required:

```text
src/nds_disassembly_toolkit/analysis/decompiler/__init__.py
src/nds_disassembly_toolkit/analysis/decompiler/lift.py
src/nds_disassembly_toolkit/analysis/decompiler/service.py
src/nds_disassembly_toolkit/analysis/decompiler/model.py
tests/unit/test_analysis_decompiler_lift.py
tests/unit/test_analysis_decompiler_service.py
tests/unit/test_analysis_decompiler_render.py
docs/disassembly-and-analysis.md
docs/provenance-and-licenses.md
README.md
```

Do not modify without a demonstrated blocker:

```text
src/nds_disassembly_toolkit/analysis/decoder.py
src/nds_disassembly_toolkit/analysis/project/schema.py
src/nds_disassembly_toolkit/analysis/runtime/
src/nds_disassembly_toolkit/analysis/orchestration/
pyproject.toml
```

---

## Task 1 — SSA storage/value models and dominator foundation

### RED

Create `tests/unit/test_analysis_decompiler_ssa_model.py` and `test_analysis_decompiler_dominators.py`.

Contracts:

- register storage and stack storage are distinct;
- same storage can have deterministic versions `.0`, `.1`, ...;
- negative SSA versions are rejected;
- PHI inputs are ordered canonically by predecessor block identity;
- duplicate PHI predecessor inputs are rejected;
- dominator computation handles straight-line, diamond, loop, and unreachable blocks;
- immediate dominators and dominance frontiers are deterministic.

The RED gate should fail because `analysis.decompiler.ssa` does not exist.

### GREEN

Implement minimum immutable models and graph helpers in `ssa.py`.

Recommended initial public/internal vocabulary:

```python
class SSAStorageKind(StrEnum):
    REGISTER = "register"
    STACK = "stack"
    TEMPORARY = "temporary"

@dataclass(frozen=True, slots=True)
class SSAStorage:
    kind: SSAStorageKind
    register: Register | None = None
    stack_offset: int | None = None
    temporary_name: str | None = None

@dataclass(frozen=True, slots=True)
class SSAValue:
    storage: SSAStorage
    version: int
    source: tuple[SourceRef, ...] = ()

@dataclass(frozen=True, slots=True)
class PhiInput:
    predecessor_address: int
    value: SSAValue | None

@dataclass(frozen=True, slots=True)
class PhiNode:
    output: SSAValue
    inputs: tuple[PhiInput, ...]
```

Graph helpers may remain private unless later tasks need stable access.

Commit once focused tests + Ruff + mypy pass.

---

## Task 2 — PHI placement and deterministic SSA rename

### RED

Create `tests/unit/test_analysis_decompiler_ssa.py`.

Required fixtures:

1. straight-line:
   ```text
   r0 = 1
   r0 = 2
   return r0
   ```
   produces distinct `r0.0` / `r0.1` definitions and return uses the newest definition.

2. diamond:
   ```text
        entry
       /     \
    r0=1   r0=2
       \     /
        join
   ```
   places exactly one PHI for r0 at join.

3. loop:
   loop-carried r0 creates a header PHI with entry and back-edge inputs.

4. independent storages:
   r0 and r1 PHIs do not contaminate each other.

5. undefined incoming:
   one predecessor without a proven definition yields an explicit undefined/input PHI incoming, not a copied sibling value.

6. unreachable definitions do not force PHIs in reachable code.

### GREEN

Implement:

- definition-site collection;
- iterated dominance-frontier PHI placement;
- deterministic dominator-tree rename;
- per-storage version stacks;
- predecessor-edge PHI filling;
- explicit entry/input values.

Do not rewrite arbitrary memory accesses.

Focused gate, then full pytest/Ruff/mypy before commit.

---

## Task 3 — Stack/local/temp promotion and def-use index

### RED

Extend SSA tests for:

- recovered `VariableExpression` locals with exact stack offsets;
- deterministic temporary variables;
- register arguments as entry definitions;
- exact stack arguments when represented by recovered stack storage;
- memory reads/writes remaining side effects rather than becoming SSA storage.

Add def-use query tests:

```text
definition(value)
uses(value)
phi_for(storage, block)
```

### GREEN

Normalize Phase 7I assignment targets/uses into promotable `SSAStorage`.

Build a deterministic `DefUseIndex` from SSA statements and PHIs.

No SQL/persistence changes.

---

## Task 4 — ValueFacts lattice

### RED

Create `tests/unit/test_analysis_decompiler_value_facts.py`.

Required contracts:

- constant 0x12 knows all 32 bits exactly;
- `x & 0xff` proves upper 24 bits zero;
- `x | 0x80000000` proves sign bit one;
- XOR of exact operands produces exact known bits;
- left/right shifts with known amounts update known bits conservatively;
- PHI join intersects only facts true on every incoming path;
- conflicting constants lose exact-constant status but retain shared known bits;
- nonzero fact must be proven, never guessed;
- proven address facts preserve component ownership;
- same numeric address with ambiguous overlay ownership must not gain a component.

### GREEN

Implement `ValueFacts` and a small fixed-point facts engine over SSA values.

Suggested invariant helpers:

```text
known_zero_bits & known_one_bits == 0
0 <= masks <= 0xffffffff
range bounds remain valid
```

Keep initial transfer set intentionally small.

Do not port LLVM code.

---

## Task 5 — Fixed-point SSA simplifier

### RED

Create `tests/unit/test_analysis_decompiler_simplify.py`.

Required transformations:

- copy chain collapse;
- constant fold `(1 + 2)`;
- nested constant fold `(arg + 4) + 8 -> arg + 12` when width semantics remain exact;
- identical-input PHI collapse;
- single-use safe expression propagation;
- dead temporary definition removal.

Required non-transformations:

- never remove/reorder memory writes;
- never cross unresolved calls;
- never eliminate unknown statements as "dead";
- conflicting PHI remains;
- no pointer alias assumption;
- deterministic convergence.

### GREEN

Implement pass interface:

```text
simplify constants
propagate copies
propagate safe expressions
simplify PHIs
apply exact algebraic identities
remove dead temporaries
normalize exact booleans
repeat
```

Use explicit stable pass order and an iteration cap. Hitting the cap yields a warning.

---

## Task 6 — Lower SSA back to Phase 7I source-like IR

### RED

Create `tests/unit/test_analysis_decompiler_ssa_integration.py`.

Start from hand-built decompiler blocks so tests isolate the new layer.

Required examples:

- straight-line register churn lowers to fewer temporaries;
- PHI-driven diamond lowers without leaking SSA version suffixes;
- loop SSA lowers while preserving existing loop structuring;
- unsupported instruction remains visible;
- memory side effects remain in original order.

### GREEN

Implement `lower.py` and any compatibility adapters required.

The existing `model.py` source-like IR remains the renderer contract.

---

## Task 7 — Service/lifter integration and pseudo-C quality regression

### RED

Extend existing service/lift/render tests with a function whose current Phase 7I output contains redundant register temporaries.

Expected new output should be structurally simpler while retaining equivalent side effects and provenance.

Also test:

- ARM;
- Thumb;
- overlay ambiguity;
- read-only project behavior;
- deterministic text;
- deterministic JSON;
- no schema write.

### GREEN

Integrate pipeline:

```text
existing lift
→ SSA normalize
→ ValueFacts
→ simplify
→ lower
→ existing structure
→ existing render
```

Avoid a second machine-code semantic implementation.

If integration reveals a specific Phase 7I IR limitation, extend that IR minimally and with explicit tests.

---

## Task 8 — Documentation, provenance, release gate

Update:

- `docs/disassembly-and-analysis.md`;
- `README.md`;
- `docs/provenance-and-licenses.md`.

Provenance must record:

- Ghidra native decompiler: Apache-2.0, architecture/reference in 7K;
- Miasm supplied archive: GPLv2, reference-only;
- RetDec supplied archive: MIT plus third-party notices, reference-only in 7K;
- LLVM supplied `ValueTracking.cpp`: Apache-2.0 WITH LLVM-exception, value-fact concept reference;
- no implementation code from those sources incorporated in Phase 7K.

Audit:

- no dependency change;
- no schema change;
- no game/Bakugan coupling;
- no second decoder;
- no runtime/orchestration change unless test-only compatibility is unavoidable;
- no third-party source vendoring.

Final exact-head gate:

```text
pytest
ruff check
mypy --strict (existing project invocation)
stock-melonDS live interoperability workflow
```

Then:

1. update PR description with exact scope/gate;
2. mark ready only if head-stable and mergeable;
3. squash merge with expected-head protection;
4. verify exact squash commit on `main`;
5. require fresh post-merge CI.
