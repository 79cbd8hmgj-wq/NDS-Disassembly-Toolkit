# Phase 7L — Type, Pointer, and Structure Recovery Design

## Status

Approved-for-execution design drafted from current `main` at
`48ba7d420f15c4be606aabdc9b79f24a2c6059dd`.

Phase 7L follows Phase 7K's deterministic SSA/value-fact/simplification layer. Its purpose is
to recover source-level pointer and structure information from the decompiler's existing
SSA and memory-access evidence without introducing unsound alias assumptions or a second
decompiler stack.

## Goal

Move ordinary output from low-level forms such as:

```c
return *(uint32_t *)(arg0 + 0x18);
```

toward conservative source-like output such as:

```c
struct struct_arg0 {
    uint32_t field_18;
};

uint32_t func(struct struct_arg0 *arg0) {
    return arg0->field_18;
}
```

when the binary provides enough consistent evidence to support that interpretation.

Phase 7L must improve readability without claiming that recovered types are original source
types.

## Architectural position

```text
persisted .ndsre evidence
        ↓
Phase 7I source-like lift
        ↓
Phase 7K SSA
        ↓
Phase 7K ValueFacts + simplification
        ↓
7L access-path normalization
├── base pointer root
├── constant field offset
├── optional scaled index
├── access width
└── read/write provenance
        ↓
7L type evidence graph
├── pointer evidence
├── scalar width/sign evidence
├── call argument/return links
└── exact-value equivalence links
        ↓
7L structure candidates
├── stable candidate identity
├── non-overlapping fields
├── repeated access support
└── conservative conflict handling
        ↓
typed source-like IR annotations
        ↓
existing control-flow structurer
        ↓
typed pseudo-C renderer
```

The toolkit remains ARM/Thumb-aware only through the existing decoder/lifter semantics.
Type/structure recovery operates on toolkit-owned decompiler IR and SSA.

## Core rule: access evidence, not semantic guessing

A structure field may be recovered only from normalized memory-access evidence.

Initial supported access shapes:

```text
base
base + constant
base - constant
base + index * scale + constant
base - index * scale + constant
```

The first useful structure case is a non-negative constant byte offset from a proven pointer
root.

A base pointer root can initially be:

- an SSA entry argument;
- an exact recovered stack argument holding an address-like value;
- a copied/PHI-related SSA value whose root is uniquely recoverable;
- a call return value only when the call result is explicitly represented and its pointer
  nature is proven by downstream dereference use.

The toolkit must not invent a structure root from an arbitrary numeric constant merely because
it falls within RAM.

## Reference findings

The implementation remains independently authored.

### Ghidra

Ghidra is used as an architectural reference for:

- separating storage/value identity from datatype identity;
- propagating pointer/type information through decompiler data flow;
- representing structure components by byte offset and width;
- keeping user/source type knowledge conceptually separate from machine storage.

No Ghidra source is copied or translated.

### Retypd / binary type inference research

Retypd and related work are useful references for the idea that machine-code type recovery is
best expressed as constraints rather than one-shot guesses. Phase 7L does **not** implement or
port Retypd's polymorphic subtype solver.

The supplied/public implementations are GPL-family reference material only.

### Structure-recovery literature

Modern structure-recovery work repeatedly uses normalized base-plus-index-plus-offset memory
accesses as evidence for a structure base and field offset. Phase 7L uses that broad algorithmic
idea but implements its own intentionally smaller evidence model over Phase 7K SSA.

## Type model

Add a toolkit-owned immutable type vocabulary. The first version should remain small.

```text
RecoveredTypeKind
├── UNKNOWN
├── INTEGER
├── POINTER
└── STRUCT

IntegerType
├── width_bytes: 1 | 2 | 4
└── signedness: unknown | unsigned | signed

PointerType
├── pointee candidate
└── component ownership only when proven

StructType
├── deterministic synthetic name
├── optional size lower bound
└── ordered fields

StructField
├── offset
├── width
├── scalar/pointer type evidence
├── deterministic synthetic name
└── provenance
```

Phase 7L does not initially recover:

- floating point types;
- C unions;
- bitfields;
- packed-vs-natural alignment declarations;
- C++ class inheritance/vtables;
- enums;
- function pointer prototypes;
- exact typedef names.

## Type evidence

Evidence records are immutable and carry provenance.

Initial evidence kinds:

- MEMORY_READ;
- MEMORY_WRITE;
- POINTER_DEREFERENCE;
- POINTER_ARITHMETIC;
- INTEGER_ARITHMETIC;
- SIGNED_COMPARE;
- UNSIGNED_COMPARE;
- CALL_ARGUMENT;
- CALL_RETURN;
- PHI_JOIN;
- EXACT_ADDRESS.

Evidence is ranked by structural certainty, not by game semantics.

A recovered type may become more precise only when all required facts are compatible. Conflicts
must widen back to a conservative representation or preserve separate candidates.

## Access paths

Introduce a canonical `AccessPath` representation independent of rendered text.

Suggested shape:

```text
AccessPath
├── root: SSAValue | stable source variable identity
├── byte_offset: int
├── index: SSAValue | None
├── scale: int | None
└── source
```

Normalization must flatten exact ADD/SUB constant trees and one scaled index term. Unsupported
or ambiguous arithmetic stays as an ordinary raw memory access.

Examples:

```text
(arg0 + 0x18)               -> root=arg0, offset=0x18
((arg0 + 4) + 8)            -> root=arg0, offset=0x0c
(arg0 + (i * 4) + 0x10)     -> root=arg0, index=i, scale=4, offset=0x10
(arg0 + i + j)              -> unresolved
```

Negative final offsets do not become structure fields in 7L unless a later normalization proves
that the current root is an interior pointer into a larger object.

## Pointer-root equivalence

Exact SSA copies and PHIs with one uniquely recoverable root may share one type variable.

Do not merge roots merely because:

- numeric values match;
- addresses overlap at runtime;
- two overlays share a runtime address;
- two unrelated parameters happen to access the same offsets.

Component/function identity remains part of the root context.

## Structure candidate formation

A structure candidate is created when one root has at least one non-negative constant-offset
dereference.

Field rules:

1. one field starts at one byte offset;
2. access width provides a minimum field width;
3. identical offset+width accesses merge evidence;
4. a wider access covering an existing narrower field is a conflict unless exact decomposition
   is independently proven;
5. overlapping incompatible fields prevent a normal struct layout and retain raw memory access;
6. fields are ordered by offset;
7. synthetic field names use `field_XX` / `field_XXXX` based on byte offset;
8. synthetic structure names are deterministic from owning function/root identity unless
   interprocedural unification provides a stronger shared identity.

One access is enough to infer pointer-like use, but not necessarily enough to emit a structure
declaration by default. The renderer threshold should initially require either:

- two distinct compatible field offsets for the same root; or
- repeated accesses to the same field from at least two source sites; or
- a compatible interprocedural link to another recovered candidate.

This keeps one-off pointer arithmetic conservative.

## Scalar type evidence

Memory access width gives strong scalar-width evidence for the field.

Signedness is only inferred when an operation distinguishes it:

- signed comparison -> signed integer evidence;
- unsigned comparison -> unsigned integer evidence;
- logical shift / mask -> unsigned-compatible evidence;
- plain load/store alone -> signedness unknown.

The renderer may use fixed-width integer types while signedness is unknown:

- 1 byte -> `uint8_t`
- 2 bytes -> `uint16_t`
- 4 bytes -> `uint32_t`

A later phase can refine signedness globally.

## Field-address IR

Do not make the renderer re-parse `base + offset` strings.

Add an explicit source-like field-address expression, approximately:

```text
FieldAddressExpression
├── base
├── structure_name
├── field_name
├── offset
├── width
└── source
```

Existing `MemoryReadExpression` and `MemoryWriteStatement` remain the memory effect model.
When their address is a proven `FieldAddressExpression`, rendering becomes:

```c
base->field_18
base->field_18 = value;
```

instead of a typed pointer dereference.

This keeps read/write semantics intact and avoids introducing a second lvalue statement family.

## Function signatures and local declarations

A recovered argument root may receive a pointer-to-struct display type.

The underlying `DecompilerVariable` identity remains unchanged. Type annotations belong in a
separate type environment keyed by stable variable/root identity.

The renderer should emit synthetic structure declarations only for candidates actually used by
the rendered function.

Initial function signatures may therefore become:

```c
uint32_t func(struct struct_func_arg0 *arg0)
```

while unrelated scalar parameters remain `uint32_t`.

## Interprocedural propagation

Phase 7L should add a bounded project-level type propagation service after local recovery is
working.

Allowed links:

- direct call target with unique component/address/mode identity;
- caller argument expression whose unique SSA root is known;
- callee parameter with stable argument identity;
- direct returned value when both caller and callee evidence are explicit.

Ambiguous overlay targets are not unified.

The propagation graph uses deterministic fixed-point iteration and an explicit cap. Conflicting
candidate layouts do not get silently merged.

## Persistence

No `.ndsre` schema migration is required initially.

Type/structure recovery remains derived on demand until:

- the model stabilizes;
- annotation overrides are designed;
- invalidation semantics for inferred types are explicit.

User-supplied type annotations are deferred rather than being mixed into generated inference
without a persistence design.

## Public compatibility

Preserve:

- `decompile_function(...)`;
- `DecompilationResult`;
- `project decompile` text mode;
- current JSON shape unless a new optional type section is explicitly versioned;
- read-only project behavior;
- Phase 7K SSA internals;
- component-aware overlay safety.

Typed output may improve ordinary pseudo-C text, but unsupported/conflicting cases must continue
to render in existing conservative syntax.

## Determinism

All candidate and field ordering must use explicit stable keys.

Synthetic structure identity must not depend on:

- Python hash order;
- database row order;
- random UUIDs;
- timestamps.

Suggested deterministic key:

```text
(component, function_address, instruction_set, root_storage_kind, root_identity)
```

Interprocedurally unified candidates should choose the lexicographically smallest canonical key.

## Testing strategy

Required fixtures:

- argument pointer with one field;
- argument pointer with two fields;
- same field read at multiple sites;
- read/write of one field;
- widths 1/2/4;
- nested constant addition normalization;
- scaled-index array-like access with constant field offset;
- unresolved multi-index arithmetic remains raw;
- negative offset remains raw;
- exact SSA copies preserve one pointer root;
- PHI with identical pointer root preserves one root;
- conflicting PHI roots remain unresolved;
- overlapping field widths remain conservative;
- ARM and Thumb inputs;
- overlay-identical runtime addresses remain independent;
- call argument propagation with unique target;
- ambiguous overlay call target is not unified;
- deterministic struct/field names;
- renderer does not emit a struct for insufficient evidence;
- renderer emits a struct and `->field` syntax when threshold is satisfied;
- raw memory fallback remains byte-for-byte stable for unresolved accesses.

## Staging

### 7L1 — Type and access-path foundation

- recovered type models;
- type evidence models;
- access-path normalizer;
- field-access evidence collector.

### 7L2 — Local structure candidates

- pointer-root equivalence;
- field layout construction;
- conflicts/overlap handling;
- local type environment.

### 7L3 — Typed source-like IR

- field-address expression;
- annotate memory reads/writes;
- typed parameter/local rendering;
- synthetic structure declarations.

### 7L4 — Interprocedural propagation

- direct call argument links;
- direct return links;
- bounded fixed point;
- overlay-safe target identity.

### 7L5 — Service integration and diagnostics

- integrate after 7K simplification;
- deterministic typed pseudo-C;
- optional internal diagnostics;
- preserve public CLI/read-only behavior.

## Explicitly deferred

Phase 7L does not implement:

- general alias analysis;
- arbitrary memory SSA;
- union/bitfield recovery;
- class/vtable recovery;
- enum recovery;
- library signature database;
- function similarity matching;
- full Retypd-style polymorphic inference;
- symbolic execution;
- recompilable-C guarantees.

## Completion criteria

Phase 7L is complete when:

1. constant-offset memory accesses can be normalized to stable pointer roots;
2. local compatible field accesses form deterministic structure candidates;
3. incompatible/overlapping evidence falls back conservatively;
4. exact scalar field widths and limited signedness evidence are tracked;
5. typed field addresses lower into existing memory read/write semantics;
6. representative pseudo-C gains struct declarations and `->field` syntax;
7. direct unambiguous call edges propagate compatible type evidence;
8. overlay ambiguity never causes cross-component type unification;
9. no persistence migration or new runtime dependency is introduced;
10. exact-head pytest, Ruff, strict mypy, melonDS, and DeSmuME gates pass;
11. the exact squash commit on `main` receives fresh successful CI.
