# Phase 7M — Interprocedural Prototype and Return Recovery Design

## Status

Approved-for-execution design based on verified Phase 7L main commit
`1bf14d74ae33db5f4117ca6f7497b3f0fb17e806`.

## Goal

Recover conservative whole-function prototypes and propagate parameter/return type evidence across
the call graph so decompiled functions can increasingly agree on:

- which ABI locations are parameters;
- parameter source-level types;
- return type;
- call-result type;
- pointer/structure identity shared across callers and callees.

Phase 7M builds on Phase 7E2 ABI evidence, Phase 7K SSA/value facts, and Phase 7L local
type/structure recovery. It does not replace any of those layers.

## Critical prerequisite: explicit SSA call result

Phase 7K currently handles a call by pushing `None` for all caller-saved registers. That is safe
for local scalar propagation but erases the def-use identity of the ABI return register `r0`.

Phase 7M changes the SSA call model so a direct/represented call defines a fresh SSA value for
`r0` while the other caller-saved clobbers remain unknown.

Conceptually:

```text
before:
    call foo
    r0 -> undefined SSA lineage

after:
    call foo -> r0_v7
    r1/r2/r3/r12/lr -> unknown
```

This is a definition identity, not a claim that the call returns a meaningful C value. Whether
the result is typed or rendered as a value depends on subsequent evidence.

The call result must be present in the def-use index and may be referenced by subsequent
instructions. Existing call side-effect ordering remains intact.

## Architectural position

```text
7E2 persisted ABI summaries
        +
7K SSA/value facts
        +
7L local type environments
        ↓
7M local prototype seeds
├── parameter locations
├── local parameter types
├── local return evidence
└── call-result SSA definitions
        ↓
component-safe direct call graph
        ↓
prototype constraints
├── caller argument -> callee parameter
├── callee return -> caller call result
├── structure/type equivalence
└── width/signedness compatibility
        ↓
bounded fixed-point propagation
        ↓
RecoveredFunctionPrototype
        ↓
typed calls / signatures / return expressions
```

## Prototype identity

Function identity remains exactly:

```text
(component, runtime_address, instruction_set)
```

No propagation is permitted across an ambiguous component-less target when two or more overlays
contain the same numeric address/mode.

## Prototype model

Introduce immutable toolkit-owned models.

```text
RecoveredFunctionPrototype
├── identity
├── name
├── parameters
├── return_type
├── evidence
├── conflicts
└── confidence / precision metadata only where deterministic

RecoveredParameter
├── index when ABI index is proven
├── register or entry-SP offset
├── display name
├── recovered type
└── evidence

RecoveredReturn
├── recovered type
├── source return sites
└── evidence
```

Parameter location comes from the existing Phase 7E2 / decompiler parameter model. Phase 7M does
not infer a fifth register argument or invent stack argument ordering that Phase 7E2 has not
proven.

## Type compatibility

Reuse Phase 7L recovered types rather than creating a second type system.

Initial compatibility rules:

- UNKNOWN + T -> T;
- identical fixed-width integer types -> same type;
- same-width signed/unsigned conflict -> same width, unknown signedness;
- incompatible integer widths -> conflict;
- pointer + compatible pointer -> merged pointer evidence;
- pointer + integer -> conflict unless the integer is still UNKNOWN;
- compatible recovered struct pointers may unify through the Phase 7L structure merge rules;
- incompatible field layouts remain explicit conflicts.

No C implicit-conversion semantics are assumed merely because machine code permits them.

## Parameter seeds

For each SSA function:

1. use existing `function.parameters` and `entry_definitions`;
2. obtain local parameter type from the Phase 7L `LocalTypeEnvironment`;
3. if no local type exists, preserve UNKNOWN rather than defaulting the analysis model to
   `uint32_t`;
4. retain the original ABI location and deterministic name.

Rendering may still use `uint32_t` as a presentation fallback for UNKNOWN.

## Return seeds

A function return type is derived from all reachable SSA return statements.

Initial rules:

- all returns with no value -> VOID;
- exact address expression -> pointer/address evidence;
- returned SSA value with a Phase 7L type -> that type;
- fixed-width memory result -> its recovered integer type;
- exact numeric constant without pointer evidence -> integer;
- incompatible return-site types -> conflict / UNKNOWN;
- unresolved `r0` return -> UNKNOWN, not `uint32_t` as an analysis fact.

Phase 7E2 `ReturnEvidence` remains supporting evidence, especially for exact constants/addresses,
but does not override contradictory SSA use evidence.

## Call constraints

For one uniquely resolved direct call:

```text
caller argument 0 type  <-> callee parameter 0 type
caller argument 1 type  <-> callee parameter 1 type
...
callee return type      <-> caller call-result SSA value type
```

Constraints are bidirectional for compatible type precision. For example:

- callee dereferences arg0 -> caller value becomes pointer-like;
- caller passes a recovered struct pointer -> callee arg0 can inherit it;
- callee returns a recovered pointer -> caller call result can inherit it;
- caller immediately dereferences a call result -> callee return becomes pointer-like.

A call with fewer represented arguments constrains only represented arguments. No missing
argument is invented.

## Fixed-point behavior

Prototype propagation is deterministic and bounded.

The implementation should process function/call identities in stable sorted order and iterate
until no prototype changes. An explicit iteration cap is required.

SCC recursion is supported naturally by the fixed point. Hitting the cap returns the current
conservative result plus a deterministic warning; it must not silently claim convergence.

## Typed call rendering

Phase 7M may improve source-like rendering when return flow is proven.

Examples:

```c
struct Actor *actor = find_actor(id);
return actor->field_18;
```

or conservatively:

```c
r0 = find_actor(id);
return r0;
```

The renderer must not emit an assignment for a call result that is never subsequently used just
to expose SSA mechanics.

No SSA version suffix may leak into pseudo-C.

## Service boundaries

Add project-level prototype recovery as a read-only analysis service. The existing
`decompile_function(...)` API must remain usable without requiring whole-project analysis.

A later service integration may optionally supply a recovered prototype context to improve a
single function's call/signature rendering. It must not open/write a second project or persist
derived prototypes implicitly.

## Persistence

Phase 7M prototypes remain derived on demand.

No `.ndsre` schema migration is allowed in this phase. Persistence should be considered only
after prototype override/invalidation semantics are designed.

## External reference boundary

Implementation remains independently authored.

Architectural references may include:

- Ghidra decompiler function prototypes / parameter and return type propagation;
- RetDec interprocedural type and call analysis architecture;
- Retypd/binary type inference literature;
- angr calling-convention and function-prototype architecture.

No implementation source from incompatible projects is copied or translated. Phase 7M adds no
runtime dependency on these projects.

## Explicitly deferred

Phase 7M does not implement:

- variadic prototype recovery;
- full C calling-convention reconstruction beyond current NDS ARM ABI evidence;
- function-pointer target resolution;
- general alias analysis;
- general memory SSA;
- library/signature database matching;
- enum recovery;
- switch recovery;
- unrestricted symbolic execution;
- recompilable-C guarantees.

## Testing requirements

Required fixtures include:

- call produces a fresh SSA `r0` result definition;
- subsequent r0 use references that result;
- r1/r2/r3/r12/lr remain unknown after call;
- unused call result remains side-effect-only in source rendering;
- used call result has stable def-use identity;
- local parameter prototype seed from 7L pointer/integer evidence;
- local return seed for void/integer/pointer/unknown;
- multiple compatible return sites merge;
- incompatible return sites conflict conservatively;
- caller argument type propagates to callee parameter;
- callee parameter evidence propagates back to caller argument;
- callee return propagates to caller call result;
- caller call-result dereference refines callee return;
- transitive A -> B -> C propagation;
- recursive SCC convergence;
- iteration-cap warning;
- ambiguous overlay call does not propagate;
- same numeric address in different components remains independent;
- deterministic prototype/name/parameter ordering;
- no SSA suffixes in pseudo-C;
- existing untyped fallback remains stable.

## Staging

### 7M1 — SSA call-result heritage

- explicit `r0` call-result SSA definition;
- def-use indexing;
- conservative lowering compatibility;
- no prototype inference yet.

### 7M2 — Local function prototypes

- prototype model;
- parameter seeds;
- return seeds;
- local compatibility/conflicts.

### 7M3 — Interprocedural prototype constraints

- argument <-> parameter links;
- return <-> call-result links;
- deterministic fixed point;
- SCCs and cap behavior;
- overlay safety.

### 7M4 — Typed call-result lowering/rendering

- represent used call results source-like;
- typed call expression context;
- signature/return rendering;
- preserve unused call side effects.

### 7M5 — Project service and diagnostics

- read-only multi-function prototype service;
- optional single-function decompiler context;
- deterministic diagnostics;
- no persistence migration.

### 7M6 — Documentation and release

- docs/provenance;
- scope audit;
- exact-head pytest/Ruff/mypy;
- melonDS/DeSmuME;
- protected squash merge;
- fresh post-merge main CI.

## Completion criteria

Phase 7M is complete when:

1. calls have explicit SSA `r0` result heritage without weakening other call clobbers;
2. every analyzed function can produce a conservative prototype seed;
3. parameter and return type evidence propagates across unique direct calls;
4. recursive/transitive call graphs converge deterministically;
5. ambiguous overlay targets never unify prototypes;
6. used call results can carry recovered types into caller analysis/rendering;
7. unknown/conflicting evidence remains explicit and conservative;
8. no persistence schema, decoder, runtime, or dependency boundary changes;
9. exact-head tests/lint/type/emulator gates pass;
10. the squash commit on `main` receives fresh successful CI.
