# Phase 7E Data-Flow Analysis Design

## Status

Approved continuation of the Phase 7 analysis roadmap on 2026-08-28.

## Goal

Add a conservative, deterministic data-flow layer that operates on the existing toolkit-owned CFG and decoded-instruction models. Phase 7E will recover useful register values, constants, addresses, stack-frame facts, arguments, and return values without reparsing display text, re-decoding CFG instructions, leaking Capstone objects into public analysis APIs, or guessing through unsupported semantics.

Phase 7E is intentionally staged:

- **Phase 7E1:** typed instruction semantics plus intraprocedural register/constant/address propagation;
- **Phase 7E2:** stack-frame, argument, and return-value recovery built on the same 7E1 engine.

The two slices share one semantic model and one fixed-point data-flow implementation. 7E2 must extend 7E1 rather than introduce a second analysis engine.

## Architectural constraints

Phase 7E preserves the boundaries established by Phases 7A-7D:

- Capstone remains confined to the decoder adapter;
- public analysis records remain toolkit-owned immutable models;
- CFGs remain the source of intraprocedural topology;
- data-flow analysis consumes existing CFG instructions and edges rather than rebuilding control flow;
- human-readable `DecodedInstruction.operands` remains display data and is never parsed by the data-flow engine;
- component identity is explicit and must not be guessed from overlapping runtime ranges;
- unsupported instructions or ambiguous effects degrade conservatively to unknown state rather than speculative values;
- results, provenance, joins, and query ordering are deterministic;
- no Bakugan-specific addresses, policies, calling conventions, or gameplay facts enter the generic toolkit.

## Why typed instruction semantics belong in `DecodedInstruction`

The current decoder deliberately converts Capstone results into toolkit-owned immutable instruction records. Phase 7E extends that adapter so downstream analysis can use typed semantics without depending on Capstone or parsing operand strings.

A separate address-keyed semantic sidecar would create synchronization and lookup complexity between CFG instructions and semantic records. Re-exposing Capstone objects would violate the existing package boundary. Therefore `DecodedInstruction` will retain its current display fields and gain toolkit-owned semantic detail.

Existing consumers that only inspect address, mnemonic, operand text, mode, or control-flow metadata must remain compatible.

## Phase 7E1: typed instruction semantics

### Semantic models

Add toolkit-owned immutable models sufficient to describe ARM/Thumb operands and register effects. Exact field names may be refined during the implementation plan, but the public concepts are:

- `Register`: canonical ARM register identity, including aliases normalized to one representation;
- `ConditionCode`: decoded execution condition where relevant;
- `OperandKind`: register, immediate, memory, register-list, or other supported typed categories;
- `MemoryOperand`: base register plus optional index/displacement and access metadata when proven by the decoder;
- `InstructionOperand`: typed operand payload;
- `InstructionSemantics`: ordered operands, registers read, registers written, and condition metadata.

`DecodedInstruction` gains an optional/contained `semantics` field populated by the decoder. Human-readable `mnemonic` and `operands` remain unchanged for presentation and compatibility.

Capstone-specific constants, objects, register IDs, and operand classes must not escape `analysis/decoder.py`.

### Required semantic coverage

7E1 needs semantic coverage for the high-value instructions used by the initial propagation engine, including ARM and Thumb forms where applicable:

- register moves;
- immediate moves/constants;
- add/subtract;
- PC-relative address construction;
- literal-pool loads;
- direct calls/branches already represented by prior phases;
- instructions with decoder-proven register read/write effects even when their value semantics are otherwise unsupported.

The semantic adapter may expose additional operand kinds if Capstone provides them reliably, but the propagation engine must not claim support merely because an operand can be represented.

### Register aliases

Aliases such as `sp`, `lr`, and `pc` must normalize to the same canonical register identities as `r13`, `r14`, and `r15`. Data-flow joins and state queries must never treat an alias and its numbered register as distinct storage locations.

## Phase 7E1: abstract values

The initial lattice is deliberately small:

- `UNKNOWN`: no single value can be proven;
- `CONSTANT`: an exact integer value is proven, but no address role is yet proven;
- `ADDRESS`: an exact runtime address role is proven, with component provenance only when component ownership is established.

Known values carry deterministic provenance identifying the instruction addresses/evidence that established them. Provenance is metadata for explanation and later persistence; it must not change value equality or create non-converging fixed-point states.

An exact integer is not promoted to `ADDRESS` merely because its numeric value resembles a runtime pointer. Address role must be established by instruction semantics or by a proven use as an address. This avoids turning arbitrary constants into pointers.

### Address provenance

An `ADDRESS` may have no component owner when the address role is proven but component ownership is not. A concrete component is recorded only when that ownership follows from the current component context or another exact component-relative fact.

A numeric value that happens to fall inside one or more component runtime ranges does not gain component ownership by global range search. This is required for Nintendo DS overlays, where multiple components may legitimately occupy the same runtime addresses at different times.

## Phase 7E1: data-flow result model

Add an immutable function-level result, conceptually `FunctionDataFlow`, containing:

- the analyzed function/component identity;
- canonical block-entry register states;
- canonical block-exit register states;
- instruction-level before/after states or equivalent deterministic query data;
- stable provenance for known values;
- analysis warnings/unsupported-effect records only where they materially help explain precision loss.

The primary entry point is conceptually:

```python
analyze_data_flow(cfg, component)
```

The implementation must validate that the CFG and component identities agree.

## Phase 7E1: transfer behavior

The first implementation propagates exact values only when all required inputs are exact and the instruction operation is supported.

Minimum supported cases:

- register-to-register move copies the abstract value and extends provenance;
- immediate move produces `CONSTANT`;
- supported add/subtract with exact operands produces an exact constant or preserves an `ADDRESS` when adding/subtracting an exact displacement from a proven address;
- supported PC-relative construction produces a proven `ADDRESS` using architecture-correct PC semantics;
- an exact literal-pool load reads the literal from the supplied `Component` and initially produces an exact `CONSTANT`; if a later supported operation or memory operand proves that value is being used as an address, it may be promoted to `ADDRESS` without guessing component ownership;
- decoder-proven writes by unsupported instructions invalidate the written registers to `UNKNOWN`;
- a supported instruction with insufficiently known inputs writes `UNKNOWN` to affected destinations rather than retaining stale state.

Conditional execution must be conservative. A conditionally executed register write merges the written result with the incoming value because the instruction may not execute. It must not be treated as an unconditional replacement unless execution is proven.

## CFG fixed-point algorithm

Use the Phase 7B CFG as the only topology source.

A deterministic worklist computes block-entry and block-exit states until no state changes. Block input is the join of predecessor exit states.

Join rules are conservative:

- identical exact values on all reachable incoming paths retain that value;
- differing exact values become `UNKNOWN`;
- exact plus unknown becomes `UNKNOWN`;
- address role and component provenance must agree to survive a join;
- missing/unreachable predecessor state must not fabricate a value.

Loops are handled by iteration to a fixed point. The finite lattice and provenance normalization must guarantee convergence.

## Calls and ABI boundary

7E1 is intraprocedural. It does not infer callee summaries or propagate values into another function.

At a call site, apply the standard ARM procedure-call boundary conservatively:

- caller-clobbered general-purpose registers become `UNKNOWN` after the call;
- callee-preserved registers remain available unless the instruction itself proves an additional write;
- `r0` is not assumed to contain a meaningful return value unless a later phase/callee summary provides that fact;
- flags and non-general-purpose state are outside the first 7E1 value model unless required for correct conditional handling.

The exact register sets will be spelled out in the implementation plan and tests rather than duplicated as ad hoc logic across modules.

## Phase 7E2: stack-frame recovery

7E2 reuses the 7E1 semantic and fixed-point machinery and adds symbolic stack reasoning.

Track stack position relative to function-entry SP when it remains provable. Recover:

- stack-pointer adjustments from supported `push`, `pop`, and `add/sub sp` forms;
- stable stack slots addressed relative to SP or a proven frame pointer;
- stack access width/direction where the typed memory operand proves it;
- maximum proven local-frame extent / frame-size estimate;
- frame-pointer establishment when it is explicit and trackable.

When control-flow paths disagree on stack displacement, stack position becomes unknown at the join rather than selecting one path.

7E2 does not require full memory alias analysis. Stack slots are symbolic frame locations, not a general memory SSA system.

## Phase 7E2: arguments

Recover conservative function argument evidence:

- usage of entry values in argument registers before those registers are locally overwritten;
- proven incoming stack arguments when stack-relative accesses can be tied to entry-SP locations above the local frame;
- evidence/provenance showing the instructions that consume each candidate argument.

Argument recovery is evidence-based, not a guarantee of a C signature. It should describe likely/used incoming locations without inventing source-level types or parameter names.

## Phase 7E2: return values

At each reachable return, inspect the proven `r0` state immediately before the return. Function summaries may report:

- a single exact return value if all proven return paths agree;
- multiple distinct proven return values as path evidence;
- unknown return behavior where `r0` cannot be established.

Do not infer high-level return types in Phase 7E.

## Function summary model

7E2 extends the function-level result with a stable summary containing, at minimum:

- candidate argument locations/evidence;
- return-value evidence;
- proven stack-frame facts;
- recovered stack slots.

This summary is intended to become a direct input to Phase 7F persistence. Phase 7F should serialize this model rather than invent another representation of the same facts.

## Validation and failure behavior

Analysis rejects structurally inconsistent inputs such as a CFG belonging to a different component.

Malformed or out-of-range literal-pool accesses do not crash whole-function analysis; the affected value becomes `UNKNOWN` and may record a deterministic precision-loss reason.

Unsupported instructions are not fatal unless their decoder metadata is internally inconsistent. Known writes are invalidated conservatively.

No silent fallback may parse `DecodedInstruction.operands` to recover missing semantics.

## Public API and compatibility

Phase 7E exports its stable models and analysis entry points through `nds_disassembly_toolkit.analysis`.

Existing Phase 7A-7D APIs retain their behavior. Adding typed instruction semantics must not change CFG edge construction, xref semantics, symbol identity, or generated symbol names.

Tests that construct `DecodedInstruction` directly must receive a compatibility path, preferably a default empty semantic record/optional field rather than forcing unrelated tests to fabricate Capstone-like detail.

## Testing strategy

### 7E1 tests

Required cases include:

1. ARM and Thumb decoder output produces toolkit-owned typed operands/register effects;
2. register aliases normalize correctly;
3. immediate and register moves propagate values;
4. add/subtract propagate exact constants and proven addresses;
5. PC-relative address construction uses correct ARM/Thumb PC semantics;
6. literal-pool loads read exact in-component values, remain `CONSTANT` until address use is proven, and handle invalid accesses safely;
7. CFG joins preserve identical values and degrade conflicting values to unknown;
8. loops converge deterministically;
9. conditional writes merge with incoming state;
10. unsupported decoder-proven writes invalidate stale values;
11. calls clobber only the modeled caller-clobbered state;
12. overlapping components never gain guessed ownership from runtime address alone;
13. provenance ordering is deterministic;
14. existing Phase 7A-7D tests remain green.

### 7E2 tests

Required cases include:

1. ARM and Thumb push/pop and SP adjustments recover entry-relative stack position;
2. stable stack slots are recovered across straight-line and branched code;
3. conflicting stack depths degrade conservatively;
4. explicit frame-pointer setup is tracked when supported;
5. use-before-overwrite of `r0`-`r3` yields argument evidence;
6. incoming stack argument locations are distinguished from local slots when provable;
7. return-path `r0` values are summarized without inventing types;
8. multiple returns and loops remain deterministic;
9. unsupported stack-affecting behavior reduces precision safely rather than guessing.

Every production behavior follows the project TDD workflow: failing focused contract first, verify RED, minimal implementation, verify GREEN, then full pytest/Ruff/strict-mypy gates.

## Documentation and provenance

Update `docs/disassembly-and-analysis.md` with the public Phase 7E model, precision boundaries, and examples after implementation.

Update `docs/provenance-and-licenses.md` to record that:

- Capstone remains the existing permissively licensed runtime decoder dependency;
- Phase 7E semantic conversion and fixed-point analysis are toolkit-owned implementations;
- angr remains architecture/reference material only and is not imported, vendored, or copied;
- melonDS remains outside this static-analysis implementation and no emulator source is incorporated.

No additional runtime dependency is planned for Phase 7E.

## Explicitly deferred

Phase 7E does not include:

- general memory alias analysis;
- heap/global structure or type inference;
- jump-table recovery unless separately promoted into a prerequisite phase;
- interprocedural whole-program constant propagation;
- callee summary application across the call graph;
- symbolic execution/path solving;
- persistent on-disk analysis projects/databases (Phase 7F);
- interactive query CLI work (Phase 7G);
- emulator/trace integration (Phase 7H);
- pseudo-C/decompiler output (Phase 7I).

## Completion criteria

Phase 7E is complete when both 7E1 and 7E2 are merged and post-merge CI is green, with one shared typed semantic/data-flow architecture, conservative deterministic behavior, public documentation, and no regression to the component-aware or dependency boundaries established by earlier phases.
