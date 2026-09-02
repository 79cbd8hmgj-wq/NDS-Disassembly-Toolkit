# Phase 7I — Conservative Pseudo-C Decompiler Design

## Status

Approved architectural design for Phase 7I. This phase follows the completed Phase 7H runtime tracing/differential work and preserves the existing analysis/project/runtime boundaries.

## Purpose

Phase 7I adds deterministic, conservative pseudo-C generation on top of the toolkit's existing persisted static-analysis model. The goal is to reduce the amount of ARM/Thumb assembly a reverse engineer must manually translate while preserving uncertainty rather than inventing semantics.

Phase 7I is a read-only derived-analysis layer. It does not replace the existing disassembler, CFG engine, data-flow engine, project schema, or runtime trace/ranking subsystem.

## Existing inputs

The decompiler consumes analysis already available through `AnalysisProject` and the established analysis model:

- `FunctionCandidate`;
- `FunctionControlFlowGraph` and basic blocks;
- `DecodedInstruction` and toolkit-owned typed instruction semantics;
- `FunctionDataFlow`;
- `FunctionSummary`;
- stack-frame and stack-slot evidence;
- argument and return evidence;
- generated symbols and user annotations;
- strings and cross-references where they improve names or call targets.

The decompiler must not re-decode component bytes and must not depend on Capstone objects outside the existing decoder boundary.

## Architecture

Phase 7I uses a dedicated toolkit-owned decompiler intermediate representation between persisted analysis and text rendering:

```text
.ndsre / AnalysisProject
        │
        ├── functions
        ├── CFGs
        ├── decoded instruction semantics
        ├── data flow
        ├── stack / ABI summaries
        ├── symbols / annotations
        └── xrefs
             ↓
       Decompiler Lifter
             ↓
     Conservative Decompiler IR
             ↓
   Control-flow Structuring
             ↓
     Pseudo-C Renderer
```

The IR is deliberately separate from the existing instruction/data-flow models. It represents source-like meaning after lifting rather than becoming a second machine-code semantic model.

## Phase staging

### 7I1 — Decompiler IR and lifting

7I1 introduces immutable toolkit-owned models sufficient to represent conservative source-like statements and expressions.

Initial expression categories cover:

- integer constants;
- proven component-owned addresses;
- argument references;
- local/temporary references;
- register fallback references when a higher-level identity cannot be proven;
- unary and binary operations;
- memory reads;
- direct call expressions;
- unknown expressions carrying source-instruction provenance.

Initial statement categories cover:

- assignments;
- memory writes;
- call statements;
- returns;
- conditional branches;
- unconditional branches;
- labels;
- explicit unknown/fallback statements.

Every lifted IR node that originates from machine code retains deterministic source provenance, at minimum the instruction address and instruction set where applicable.

The lifter uses existing `FunctionDataFlow`/`FunctionSummary` evidence rather than attempting independent register propagation, stack recovery, or calling-convention inference.

#### Initial lifting coverage

The first implementation targets common ARM/Thumb operations that can be represented conservatively from existing typed semantics:

- register and immediate moves;
- arithmetic and bitwise operations with known operands;
- compares/test operations used by branches;
- stack/local loads and stores when the existing stack analysis proves the slot;
- direct memory loads/stores when the address expression is recoverable;
- direct calls with known targets;
- simple return-value propagation;
- direct returns;
- conditional/unconditional control transfers.

Unsupported, indirect, or semantically ambiguous instructions remain explicit unknown/fallback IR. They are never silently dropped.

### 7I2 — Variable and control-flow recovery

7I2 maps lower-level IR identities into stable source-like variables and structures only control flow that is proven by the existing CFG.

#### Variable recovery

Preferred naming order:

1. unambiguous user annotation/name;
2. unambiguous generated symbol;
3. recovered argument (`arg0`, `arg1`, ...);
4. recovered stack local (`local_04`, `local_08`, ...);
5. deterministic temporary (`tmp_0`, `tmp_1`, ...);
6. raw register fallback (`r4`, `r7`, ...).

Names are sanitized into deterministic C-like identifiers. Collisions are resolved deterministically.

Phase 7I does not infer C types beyond a minimal presentation-level scalar/pointer distinction already proven by existing address evidence. Unknown values use a neutral fixed-width scalar representation rather than invented structures or classes.

#### Control-flow structuring

Safe structures to recover initially:

- straight-line blocks;
- `if`;
- `if/else`;
- simple pre-test/post-test loops when CFG dominance/back-edge evidence is sufficient;
- simple early returns.

When a region cannot be structured unambiguously, renderer input retains labels/gotos. A valid conservative output is preferable to attractive but incorrect structured C.

Irreducible graphs, unresolved indirect branches, switch/jump tables not yet proven by existing analysis, and other complex control flow remain label/goto based in this phase.

### 7I3 — Rendering and CLI integration

7I3 renders deterministic pseudo-C and exposes it through the persistent project CLI.

Primary command shape:

```bash
nds-toolkit project decompile GAME.ndsre COMPONENT ADDRESS --mode arm
nds-toolkit project decompile GAME.ndsre COMPONENT ADDRESS --mode thumb
```

The command opens the `.ndsre` project read-only and performs exact lookup by `(component, address, instruction_set)`.

Output format is explicit:

```bash
nds-toolkit project decompile GAME.ndsre COMPONENT ADDRESS --mode arm --format text
nds-toolkit project decompile GAME.ndsre COMPONENT ADDRESS --mode arm --format json
```

`--format` accepts exactly `text` or `json` and defaults to `text`.

`--format text` emits human-readable pseudo-C. `--format json` emits a deterministic structured representation of the decompilation result using the existing project CLI conventions: sorted JSON keys, stable ordering, lowercase canonical hexadecimal strings, and a trailing newline.

The command also supports the existing `--output PATH` convention. With `--output`, the selected format is written atomically to the requested file; without it, output is written to stdout.

The renderer uses stable formatting so identical input projects produce byte-for-byte identical output.

## Output policy

Pseudo-C is an evidence-backed representation, not claimed recompilable source.

The output makes uncertainty visible. Examples include:

```c
/* unresolved instruction at 0x02012374: ... */
```

or a deterministic unknown intrinsic-like expression if required by the IR.

The renderer must not fabricate:

- struct names or fields;
- enum names;
- semantic variable names unsupported by symbols/annotations;
- function signatures beyond recovered ABI evidence;
- indirect call targets;
- data types unsupported by evidence.

When a function cannot be safely rendered beyond labels/gotos and low-level expressions, that form is still considered successful output.

## Symbols, annotations, and overlays

Component identity remains mandatory. Runtime address alone never identifies a symbol or function because NDS overlays may overlap.

All symbol/annotation resolution remains component-aware. Ambiguous overlay ownership remains ambiguous rather than being guessed.

User-authored project annotations may improve names in generated pseudo-C, but Phase 7I does not persist generated pseudo-C or decompiler-specific inferred names back into `.ndsre`.

## Runtime evidence boundary

Phase 7H2 runtime trace/differential ranking remains a separate subsystem.

Phase 7I may consume an already-selected function that was discovered through runtime investigation, but initial pseudo-C generation does not change semantics based on dynamic traces. Runtime observations are evidence for prioritization/correlation, not permission to rewrite static program meaning.

A later phase may add optional runtime annotations to pseudo-C if separately designed.

## Error handling

Decompiler errors follow existing toolkit error/CLI conventions.

Expected explicit failures include:

- requested function is absent;
- CFG is absent when required;
- persisted data flow is absent when required by a lifting rule;
- malformed/incompatible project data;
- unsupported mode/address combination.

Unsupported individual instructions are not fatal by default: they produce fallback IR with provenance unless continuing would make the surrounding IR incorrect.

## Determinism

All output is deterministic for identical persisted analysis:

- IR node ordering follows CFG/instruction order under explicit stable rules;
- symbol/name tie-breaking is deterministic;
- temporary numbering is deterministic;
- labels are deterministic from addresses;
- JSON key/order conventions match the existing project CLI;
- renderer whitespace is stable.

No timestamps, randomized identifiers, hash iteration order, or database row insertion order may affect semantic/output ordering.

## Persistence and dependencies

Phase 7I requires:

- no `.ndsre` schema migration;
- no new runtime dependency;
- no second Capstone integration;
- no new decoder;
- no persistence of pseudo-C;
- no copied/vendor decompiler implementation from angr, Ghidra, RetDec, or other external projects.

The implementation remains independently authored against toolkit-owned models and documented public behavior/reference concepts.

## Public API direction

The intended public boundary is a small read-only facade plus toolkit-owned immutable result models:

```python
result = decompile_function(project, component, address, instruction_set)
text = render_pseudo_c(result)
```

Lower-level lifting/structuring helpers may remain module-level/internal unless tests or consumers need a stable public boundary. Public return values are never SQLite rows or Capstone objects.

## Testing strategy

Phase 7I follows RED→GREEN TDD and adds synthetic fixtures rather than commercial ROM content.

Required coverage includes:

- ARM and Thumb lifting;
- constants/register moves/arithmetic;
- loads/stores;
- stack locals;
- recovered arguments;
- return values;
- direct calls and symbol naming;
- conditional branches;
- `if` and `if/else` structuring;
- at least one simple loop;
- label/goto fallback for unstructured CFGs;
- unsupported-instruction fallback;
- component/overlay ambiguity preservation;
- deterministic temporary/name collision handling;
- deterministic text rendering;
- deterministic JSON rendering;
- read-only project access;
- no `.ndsre` schema mutation;
- CLI error mapping.

Existing repository gates remain mandatory:

```text
pytest
Ruff
strict mypy
```

The existing stock-melonDS live CI remains green, although Phase 7I itself is static/read-only and adds no new live-emulator requirement.

## Explicitly deferred

Phase 7I does not include:

- recompilable C generation;
- C-to-ROM round-trip decompilation/recompilation;
- structure/class/type reconstruction;
- aggressive pointer/type inference;
- switch/jump-table recovery beyond existing proven CFG information;
- interprocedural symbolic propagation;
- whole-program SSA framework;
- targeted angr symbolic execution;
- function signature/similarity databases;
- semantic ROM differential analysis;
- automatic RE investigation/prioritization beyond the existing 7H2 dynamic ranker;
- persistence of decompiler output;
- GUI/TUI decompiler views.

The broader evidence-fusion/prioritization engine is reserved for a later Phase 7J.

## Completion criteria

Phase 7I is complete when:

1. toolkit-owned decompiler IR can conservatively lift supported ARM and Thumb analysis fixtures;
2. recovered arguments, stack locals, direct calls, returns, and common expressions render deterministically;
3. safe CFG patterns render as `if`/`if-else`/simple loops while uncertain graphs retain labels/gotos;
4. unsupported instructions remain visible with deterministic provenance;
5. `nds-toolkit project decompile` reads `.ndsre` projects without mutation and produces deterministic `text` and `json` output;
6. no `.ndsre` schema change or new runtime dependency is introduced;
7. all new and existing tests pass, Ruff passes, and strict mypy passes;
8. the existing stock-melonDS CI remains green;
9. the final PR is scope-audited, merged with head protection, and the exact post-merge `main` commit passes CI.
