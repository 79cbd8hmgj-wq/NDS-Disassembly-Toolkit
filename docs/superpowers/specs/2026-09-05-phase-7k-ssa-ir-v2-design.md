# Phase 7K — SSA and Decompiler IR v2 Design

## Status

Approved-for-execution design drafted from current `main` at `34ab25b109ec63540dd87aa9a4d48f7f32d89705`.

Phase 7K follows the completed Phase 7I conservative pseudo-C decompiler and Phase 7J investigation engine. Its purpose is to improve decompiler reasoning quality without replacing the toolkit-owned decoder, CFG, data-flow, project, runtime, or renderer boundaries.

## Purpose

Phase 7I deliberately stops at conservative source-like lifting. It can express registers, arguments, locals, arithmetic, memory accesses, calls, branches, and simple structured control flow, but it still inherits machine-register churn and cannot globally reason about distinct definitions of the same storage location.

Phase 7K introduces a toolkit-owned Static Single Assignment (SSA) layer and a second-generation decompiler value model so later phases can perform:

- def-use and use-def reasoning;
- PHI-based join recovery;
- copy and expression propagation;
- constant folding;
- dead temporary elimination;
- condition simplification;
- richer partial-value facts;
- cleaner variable reconstruction;
- stronger inputs for later type/structure/interprocedural recovery.

The target is not LLVM IR, Ghidra p-code, RetDec BIR, Miasm IR, or VEX. The toolkit retains its own immutable NDS-aware representation.

## Source/reference findings

The implementation is independently authored, but the design was checked against multiple mature decompiler/compiler architectures.

### Ghidra native decompiler

Ghidra's `heritage.hh` describes SSA construction as two major operations: PHI/MULTIEQUAL placement and renaming. It also explicitly stages register data flow before stack locations and guards ambiguous LOAD/STORE aliasing rather than pretending arbitrary memory is freely promotable.

Ghidra's `varnode.hh` separates storage location from SSA definition identity: multiple SSA values can refer to the same underlying address/size while remaining distinct definitions.

Ghidra's rule engine repeatedly applies localized data-flow transforms until no further rule changes are possible. Its type system separately models unknown, integer, boolean, pointer, array, enum, struct, union, and code categories.

These are architectural references. Phase 7K does not port Ghidra classes or code.

### Miasm

The supplied Miasm tree has a graph SSA implementation with explicit PHI placement, renaming, PHI filling, and a simplifier that repeatedly performs expression propagation, dummy-PHI cleanup, dead removal, and block merging to fixed point.

Miasm also exposes a useful warning for our design: arbitrary memory expressions are not equivalent to ordinary SSA variables without alias reasoning.

Miasm is GPLv2 and is reference/validation material only.

### RetDec

The supplied RetDec tree contains def-use analysis, reaching definitions, expression signedness analysis, alias-analysis infrastructure, high-level IR optimization, and C type/composite-type models.

RetDec is permissively licensed, but Phase 7K still starts with independently authored toolkit code. Any deliberate source reuse would require a separate provenance entry and code-level audit.

### LLVM ValueTracking

The supplied LLVM `ValueTracking.cpp` demonstrates a stronger alternative to all-or-nothing constants: known-zero/known-one bits, ranges, nonzero facts, pointer/non-null facts, PHI/select reasoning, dominating-condition reasoning, recurrence reasoning, and conservative recursion limits.

Phase 7K adopts the concept of partial value facts, not LLVM implementation code.

## Architectural position

```text
.ndsre / AnalysisProject
        ↓
existing CFG + typed semantics + FunctionDataFlow
        ↓
Phase 7I low-level decompiler lifting
        ↓
7K promotable-storage normalization
        ↓
SSA construction
├── dominators
├── dominance frontiers
├── PHI placement
└── deterministic rename
        ↓
SSA Decompiler IR v2
        ↓
value-fact analysis
        ↓
fixed-point simplification
        ↓
existing source-like IR / structurer / renderer
        ↓
cleaner deterministic pseudo-C
```

Phase 7K is an internal analysis upgrade. The public `decompile_function(...)` workflow and `project decompile` CLI remain compatible unless a later task adds explicitly versioned diagnostics.

## Core design rule: storage identity is not value identity

The current decompiler can refer to a register or local as a storage location. SSA needs a separate definition identity.

Conceptually:

```text
storage: r0
definitions:
    r0.0
    r0.1
    r0.2
```

and:

```text
storage: stack[-0x08]
definitions:
    local_08.0
    local_08.1
```

A value identity therefore contains:

- promotable storage identity;
- deterministic version number;
- function/component context indirectly through its owning SSA function.

Version numbers are assigned by deterministic CFG traversal, never hash iteration order.

## Promotable storage

Phase 7K promotes only storage with exact identity.

Initially promotable:

- ARM registers represented by toolkit `Register`;
- exact recovered stack slots;
- recovered register arguments;
- exact stack arguments when represented as stable stack slots;
- deterministic decompiler temporaries produced by lifting.

Not initially promotable:

- arbitrary RAM loads/stores;
- unresolved pointer dereferences;
- overlapping/partially aliased memory regions;
- volatile/device memory;
- unknown indirect call side effects.

This is deliberate. We will not introduce unsound "memory SSA" before alias analysis exists.

Memory reads remain expressions with explicit addresses. Memory writes remain side-effecting statements. Calls conservatively invalidate facts according to the existing ABI/data-flow model unless a later interprocedural phase proves more.

## SSA model

Add a dedicated module, expected to be `analysis/decompiler/ssa.py`, with immutable records approximately equivalent to:

```text
SSAStorageKind
SSAStorage
SSAValue
SSAUse
SSADefinition
PhiInput
PhiNode
SSAStatement
SSABlock
SSAFunction
DefUseIndex
```

The exact final class names may differ during TDD, but the following contracts are mandatory.

### SSAStorage

Represents a stable promotable location, not a value instance.

Identity must distinguish at minimum:

- register storage;
- exact stack offset storage;
- lifted temporary storage.

Two stack slots at different offsets are different storage. A register and stack slot are always different even if current analysis believes they contain the same numeric value.

### SSAValue

Represents one definition of one `SSAStorage`.

It must have:

- storage;
- non-negative deterministic version;
- source provenance where definition is machine-code-derived.

Equality cannot depend on display name.

### PhiNode

A PHI is associated with one output `SSAValue` and ordered incoming values keyed by predecessor block identity.

Incoming ordering is canonical by the existing component-safe block identity/order, never database row order.

An undefined incoming value remains explicit. It must not be silently replaced by zero or by another predecessor's value.

## Dominators and PHI placement

The toolkit currently structures simple loops using local dominance reasoning but does not expose a reusable dominator subsystem.

Phase 7K adds one toolkit-owned CFG utility sufficient for SSA:

- reachable-block filtering from the function entry;
- immediate dominators;
- dominator-tree children;
- dominance frontiers.

PHI placement follows the conventional iterated-dominance-frontier approach over definition sites for each promotable storage.

Only reachable CFG blocks participate in SSA. Unreachable blocks may remain in conservative fallback rendering but cannot perturb reachable SSA versioning.

## Rename algorithm

Renaming uses a per-storage version stack while traversing the dominator tree.

Rules:

1. PHI outputs are definitions at block entry.
2. Statement uses resolve against the current top definition.
3. Statement writes create a new definition/version.
4. Successor PHI inputs capture the definition visible on that predecessor edge.
5. Definitions created in a block are popped when leaving its dominator-tree subtree.
6. Entry values for recovered arguments are explicit initial definitions.
7. Reads with no proven definition produce an explicit undefined/input value rather than guessing.

ARM and Thumb use identical SSA mechanics because instruction-set differences are already normalized by typed semantics before this phase.

## Value facts

Phase 7K introduces a conservative `ValueFacts` lattice associated with SSA values/expressions.

Initial facts:

```text
bit_width = 32 for ARM general integer/register values
known_zero_bits
known_one_bits
unsigned_min / unsigned_max
signed_min / signed_max
is_nonzero
is_address
component (only when address ownership is proven)
alignment
provenance
```

The implementation may internally derive some fields from others rather than storing all redundantly.

Required invariants:

- known-zero and known-one masks never overlap;
- facts only become more precise when justified;
- conflicting path facts merge conservatively;
- address ownership is never guessed from a naked numeric range when overlays overlap;
- timestamps/random identifiers never affect facts.

### Initial transfer coverage

At minimum:

- constants;
- copies;
- bitwise AND/OR/XOR;
- logical/arithmetic shifts with known amounts;
- ADD/SUB when constant/range reasoning is safe;
- PHI joins;
- compare-derived booleans where already represented in decompiler IR.

A future phase may add multiplication/division and richer path-sensitive assumptions. Phase 7K should not become a clone of LLVM ValueTracking.

## Def-use index

The SSA function exposes deterministic queries:

```text
definition(value)
uses(value)
value_at(storage, block/instruction position)
phi_for(storage, block)
```

Later phases must not have to rescan rendered strings to discover data flow.

The index is derived from SSA IR and is not persisted in `.ndsre` during 7K.

## Simplification pipeline

Phase 7K adds a deterministic fixed-point simplifier over SSA IR.

Initial passes, in this order:

1. constant folding;
2. copy propagation;
3. expression propagation for single-use/simple safe expressions;
4. PHI simplification;
5. algebraic identities with exact semantics;
6. dead temporary-definition removal;
7. boolean/compare normalization where evidence is exact.

The pass sequence repeats until no pass changes the function or a defensive iteration cap is reached.

The iteration cap is a safety guard and reaching it produces a warning, not nondeterministic behavior.

### Required conservative behavior

No simplifier may:

- remove a memory write;
- reorder potentially effectful calls;
- assume two pointer expressions do not alias;
- fold signed/unsigned behavior without enough evidence;
- invent source-level types;
- cross an unresolved call clobber barrier;
- erase an unsupported/unknown instruction solely to improve appearance.

## Lowering back to source-like IR

Phase 7K does not require replacing every Phase 7I model immediately.

After SSA simplification, a lowering step converts SSA values into the existing source-like expression/statement layer consumed by `structure.py` and `render.py`.

Expected visible improvements:

```c
tmp_0 = arg0;
tmp_1 = tmp_0 + 4;
tmp_2 = tmp_1 + 8;
return tmp_2;
```

can become:

```c
return arg0 + 12;
```

and join-heavy register churn can become a single recovered variable with an explicit PHI-derived source-level assignment pattern where structuring makes that safe.

SSA version suffixes are internal diagnostics. They are not intended to leak into ordinary pseudo-C unless diagnostic JSON explicitly requests them in a later task.

## Compatibility

Phase 7K must preserve:

- current `DecompilationResult` public behavior;
- `project decompile` text/json command shapes;
- component-aware overlay handling;
- existing unsupported-instruction visibility;
- existing read-only `.ndsre` behavior;
- Capstone confinement to the decoder;
- no runtime dependency on Ghidra, LLVM, RetDec, Miasm, or angr.

A temporary internal compatibility adapter is acceptable while the lifter is migrated.

## Persistence

No `.ndsre` schema change is required in Phase 7K.

SSA and simplified IR are derived on demand from already persisted static analysis.

Persistence can be reconsidered only after:

- the SSA model stabilizes;
- type/structure recovery needs durable inferred evidence;
- invalidation/freshness semantics are explicitly designed.

## Provenance boundary

Phase 7K implementation remains toolkit-authored.

Reference roles:

- Ghidra: SSA heritage architecture, varnode/value distinction, transform-pool concepts, type-system architecture;
- Miasm: independent SSA/simplification behavior and test comparison only; GPL source is not copied;
- RetDec: def-use/reaching-definition/HLL/type architecture reference; no code incorporation in 7K;
- LLVM: known-bits/range/value-fact concepts; no source copied;
- angr: future symbolic-analysis reference only.

The final Phase 7K PR must update `docs/provenance-and-licenses.md` with these supplied/reference sources and their observed licensing boundaries.

## Testing strategy

Phase 7K follows RED → GREEN TDD.

Required SSA fixtures:

- straight-line register redefinition;
- diamond CFG requiring a PHI;
- loop-header PHI;
- nested dominance;
- multiple variables requiring independent PHIs;
- recovered stack-local SSA;
- ARM and Thumb inputs;
- unreachable block isolation;
- undefined predecessor value;
- deterministic predecessor/input order;
- overlapping overlay addresses remaining separate by owning function/component.

Required simplification fixtures:

- copy chain collapse;
- constant-expression folding;
- known-bit AND-mask facts;
- shift-derived known bits/ranges;
- PHI with identical incoming values;
- PHI with conflicting values remaining PHI/unknown;
- dead temporary removal;
- side-effect preservation;
- call barrier preservation;
- deterministic fixed point.

Required integration fixtures:

- existing Phase 7I decompilation still succeeds;
- representative pseudo-C becomes strictly cleaner without losing provenance;
- no `.ndsre` write/schema mutation;
- exact text/json deterministic output;
- existing runtime/orchestration tests remain unaffected.

Repository gates remain:

```text
pytest
Ruff
strict mypy
stock-melonDS interoperability CI
```

## Staging

### 7K1 — SSA core

- storage/value models;
- dominators/dominance frontiers;
- PHI placement;
- rename;
- def-use index.

### 7K2 — Value facts

- known bits;
- basic ranges;
- nonzero/address/alignment facts;
- PHI joins;
- conservative transfer rules.

### 7K3 — Fixed-point simplification

- copies/constants/expressions;
- PHI cleanup;
- dead temporaries;
- deterministic convergence.

### 7K4 — Decompiler integration

- Phase 7I lifter → SSA normalization;
- simplified lowering;
- renderer compatibility;
- optional diagnostic JSON only if needed by tests.

## Explicitly deferred

Phase 7K does not implement:

- general memory SSA;
- full alias analysis;
- structure/field recovery;
- source-level type inference;
- interprocedural fixed-point propagation;
- jump-table/switch recovery;
- library signature matching;
- cross-ROM function similarity;
- targeted angr symbolic execution;
- recompilable-C guarantees.

Those remain the intended 7L+ path.

## Completion criteria

Phase 7K is complete when:

1. promotable register/stack/temporary storage is converted to deterministic SSA;
2. PHIs are correctly placed and renamed for diamonds and loops;
3. deterministic def-use queries are available;
4. partial known-bit/range facts work for the agreed initial operation set;
5. fixed-point simplification removes redundant register/temporary churn without crossing side-effect or alias boundaries;
6. Phase 7I public decompilation and CLI behavior remain compatible while representative pseudo-C becomes cleaner;
7. no `.ndsre` schema migration or new runtime dependency is introduced;
8. provenance documentation records Ghidra, RetDec, Miasm, and LLVM boundaries;
9. pytest, Ruff, strict mypy, and stock-melonDS CI pass on the exact PR head;
10. the exact squash commit on `main` receives a fresh successful post-merge gate.
