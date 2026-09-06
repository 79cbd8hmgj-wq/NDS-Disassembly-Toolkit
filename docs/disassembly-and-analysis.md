# Disassembly and static-analysis helpers

The toolkit provides game-neutral preparation and comparison helpers for Nintendo DS ARM9, ARM7, and overlay binaries. It does not attempt to infer game semantics.

## Locate ARM9 Nitro module parameters

```bash
nds-toolkit disasm module-params arm9.bin \
  --base-address 0x02000000 \
  --output module-params.json
```

The scanner looks for a valid aligned Nitro module-parameter block and reports file-relative/runtime information. Ambiguous aligned candidates fail rather than selecting one arbitrarily.

## Report overlay layout

```bash
nds-toolkit disasm overlay-map GAME.nds --output overlays.json
```

The report combines parsed ARM9/ARM7 overlay metadata with ARM9 module parameters when available. It records overlay placement and load relationships without assigning game-specific meaning.

Generic toolkit operation is structural by default. To require an exact ROM profile:

```bash
nds-toolkit disasm overlay-map GAME.nds \
  --profile profile.json \
  --require-supported \
  --output overlays.json
```

Game consumers may wrap this parser with stricter defaults.

## Emit labelled byte blocks

Create a whitespace-separated file of runtime addresses:

```text
0x02201000
0x02201120
0x02201200
```

Then run:

```bash
nds-toolkit disasm labels component.bin labels.txt \
  --vma 0x02200000 \
  --output component-data.s
```

The component base is always emitted as a label, so bytes before the first requested address are not silently dropped. Labels outside the component are rejected.

This is useful for data islands, unknown regions, and incremental reconstruction. It deliberately does not guess whether bytes are code or data.

## Compare disassembly

Install an ARM GNU `objdump` compatible with ARMv5TE code. The default executable is `arm-none-eabi-objdump`.

```bash
nds-toolkit disasm diff original.bin rebuilt.bin \
  --vma 0x02200000 \
  --start 0x02201000 \
  --end 0x02201200 \
  --output comparison.diff
```

Use `--thumb` for Thumb regions, `--processor` to override the default `armv5te` processor string, and `--objdump` to select another executable.

The result is a deterministic unified text diff. Matching disassembly is useful reconstruction evidence, but it is not proof of semantic equivalence.

## Generic static analysis

The `analyze` command scans arbitrary flat executable components. Each component is supplied with a name, file path, and runtime base:

```bash
nds-toolkit analyze \
  --component arm9 arm9.bin 0x02000000 \
  --component overlay7 overlay_007.bin 0x02200000 \
  --keyword battle \
  --keyword power \
  --output static-analysis.json
```

The generic report can include:

- component identity, runtime range, and hashes;
- ASCII strings meeting the minimum length;
- keyword-filtered string evidence;
- exact pointer references to discovered strings;
- optional numeric-record matches and proximity clusters.

Set the minimum string length with `--minimum-string-length`.

### Numeric-record scans

Numeric scanning is opt-in. Supply a JSON array of records plus the field containing numeric values:

```bash
nds-toolkit analyze \
  --component target target.bin 0x02000000 \
  --numeric-records records.json \
  --numeric-values-key values \
  --numeric-divisor 10 \
  --output report.json
```

`--numeric-values-key` and `--numeric-divisor` are meaningful only with `--numeric-records`.

## Phase 7A function discovery

The analysis package now provides a Capstone-backed ARM/Thumb decoder and conservative function discovery for executable components. Callers provide explicit runtime-address seeds; direct `BL`/`BLX` call targets inside the same component are then discovered recursively.

```python
from pathlib import Path

from nds_disassembly_toolkit.analysis import (
    Component,
    FunctionSeed,
    InstructionSet,
    discover_functions,
)

component = Component(
    "arm9",
    Path("arm9.bin"),
    0x02000000,
    Path("arm9.bin").read_bytes(),
)
result = discover_functions(
    component,
    seeds=(FunctionSeed(0x02000000, InstructionSet.ARM),),
)
```

Each function candidate preserves its runtime address, component-relative offset, instruction set, confidence, and stable evidence strings. Direct calls outside the component are reported separately as unresolved calls. Decode failures terminate only the affected path.

Phase 7A intentionally does **not** guess indirect targets, treat every prologue-like byte sequence as authoritative code, or recover jump tables. The older ARM prologue helpers remain available as heuristics.

## Phase 7B control-flow graphs

`build_function_cfg()` consumes a Phase 7A `FunctionCandidate` and builds a deterministic intraprocedural graph from the same toolkit-owned decoded-instruction records.

```python
from nds_disassembly_toolkit.analysis import build_function_cfg

cfg = build_function_cfg(component, result.functions[0])
```

CFG construction first traverses reachable instructions and records successors, then derives basic-block leaders and edges in a second pass. This allows forward and backward branch targets to split earlier linear code without overlapping blocks.

The graph records:

- immutable basic blocks with runtime addresses, component offsets, mode, instructions, size, and end address;
- direct branch and fallthrough edges;
- direct call edges without traversing callee bodies inside the caller graph;
- ARM/Thumb target mode for direct interworking calls;
- direct external branch/call targets without decoding outside the component;
- stable unresolved records for indirect calls/branches;
- decode failures for reachable paths that cannot be decoded.

Indirect targets are never guessed. Indirect calls keep their intraprocedural fallthrough, while indirect unconditional branches terminate the affected path. Calls deliberately start a new fallthrough block so later call-graph/xref analysis can reason about the call site explicitly.

Phase 7B does not add a graph-library dependency or leak Capstone objects into public data models.

## Phase 7C cross-references and call graphs

Phase 7C normalizes semantic code edges and existing pointer records into one deterministic cross-reference model. It does not re-decode executable bytes.

```python
from nds_disassembly_toolkit.analysis import build_call_graph, build_xref_index

index = build_xref_index((cfg,), pointer_references=())
references_to_target = index.to_address(0x02001000)
references_from_site = index.from_address(0x02000040)
call_edges = build_call_graph(index)
```

The index contains three semantic reference kinds:

- `call` for direct call edges;
- `branch` for direct branch edges;
- `data_pointer` for existing exact pointer references.

CFG fallthrough edges are excluded because they describe local graph topology rather than semantic cross-references. Code xrefs preserve their owning component, source function, exact instruction address, source mode when available, target address, and target mode. Data-pointer xrefs deliberately do not invent function ownership or ARM/Thumb metadata.

`to_address()` and `from_address()` return stable tuples and may optionally filter by `CrossReferenceKind`. `build_call_graph()` is a derived view of direct call xrefs, so caller component/function, callsite, external targets, and ARM/Thumb interworking remain available without maintaining a second source of truth.

Phase 7C still does not guess indirect targets or assign symbol names. Phase 7D symbol recovery should consume and annotate these xrefs rather than create a separate reference database.

## Phase 7D symbol recovery

Phase 7D adds one deterministic symbol layer over the records already produced by the toolkit. It does not re-decode instructions and does not infer semantic game names.

```python
from nds_disassembly_toolkit.analysis import build_symbol_table

symbols = build_symbol_table(
    functions=result.functions,
    cfgs=(cfg,),
    strings=(),
    candidates=(),
    components=(component,),
)
```

Symbol identity is **component-aware**: `(component, runtime_address)`. This is required for Nintendo DS overlays because two overlays may legitimately occupy the same runtime address at different times. `SymbolTable.at_address()` and `by_name()` therefore return tuples rather than assuming either addresses or generated names are globally unique.

The builder emits structural names only:

- discovered function entry: `func_XXXXXXXX`;
- local CFG branch target: `loc_XXXXXXXX`;
- discovered string: `str_XXXXXXXX`.

Local branch labels are created only when a `BRANCH` edge targets the start of a basic block in the same CFG/component. External branch targets are deliberately not assigned to an overlay by runtime range alone.

Caller-provided `SymbolCandidate` names have naming precedence over generated names. Structural type is preserved: an explicitly named discovered function remains `SymbolKind.FUNCTION`, while a candidate with no stronger structural evidence becomes `SymbolKind.NAMED`. Evidence strings are de-duplicated and sorted, and confidence keeps the strongest stable level in the order `high > medium > low > unknown`.

When `components` are supplied, validation is performed by component **name**, not by searching overlapping runtime ranges. Duplicate component names, unknown component references, out-of-range addresses, inconsistent component-relative offsets, and empty explicit names are rejected. Overlapping components remain valid and independent.

Phase 7D does not infer structs, signatures, global data types, jump tables, indirect targets, or persistent user annotations. Those remain later analysis phases.

## Phase 7E1 typed semantics and register data flow

Phase 7E1 extends the decoder's toolkit-owned instruction records with typed ARM/Thumb semantics and runs deterministic intraprocedural abstract interpretation over the existing Phase 7B CFG. The data-flow engine never parses the human-readable operand string and never re-decodes instructions.

```python
from nds_disassembly_toolkit.analysis import analyze_data_flow, build_function_cfg

function = result.functions[0]
cfg = build_function_cfg(component, function)
flow = analyze_data_flow(cfg, component)
state = flow.at_instruction(0x02000020)
```

The exact-value lattice is deliberately small:

- `UNKNOWN` means the current value cannot be proven exactly;
- `CONSTANT` is an exact unsigned 32-bit numeric value with no invented pointer ownership;
- `ADDRESS` is an exact address value, optionally tied to the component whose PC-relative construction proved that ownership.

The solver currently propagates unshifted register moves, immediate values, and exact `add`/`sub` combinations. Unsupported instructions conservatively invalidate registers that the decoder reports as written. A numeric constant used as a memory base/index may be refined to an unowned `ADDRESS`, but arbitrary constants are never classified as pointers merely because they happen to fall inside a component's runtime range.

ARM PC reads use `instruction_address + 8`; Thumb PC-relative memory accesses use aligned `(instruction_address + 4)`. Proven PC-derived addresses remain owned by the current component. This preserves overlay identity when two overlays use the same runtime address.

Unsigned PC-relative `ldr`, `ldrh`, and `ldrb` literal-pool reads consume their typed access width and read only in-component bytes. Their loaded contents remain `CONSTANT` even when the numeric value resembles an address. Out-of-component literal reads produce a stable warning and leave the destination unknown rather than reading or guessing outside the supplied component. Signed literal forms remain conservative until they receive dedicated transfer rules and tests.

At CFG joins, equal exact semantic values survive while conflicting values become unknown. Loops are solved to a deterministic fixed point using only existing local branch/fallthrough edges. Direct and indirect calls remain intraprocedural barriers: caller-saved `r0`-`r3`, `r12`, and `lr` become unknown while preserved registers retain proven values. Conditional instructions join the executed and skipped states so a conditional write cannot be treated as unconditional.

Provenance records the instruction addresses that contributed to supported exact values. Semantic convergence is solved independently of provenance; a deterministic enrichment pass then adds bounded provenance without being allowed to change reachability or value semantics.

Phase 7E1 remains intraprocedural and does not perform memory alias analysis, structure/type inference, whole-program symbolic execution, or stack/ABI recovery. Stack frames, arguments, and return summaries are the separate Phase 7E2 layer built on this same flow model.

## Phase 7E2 stack frames, arguments, and return evidence

Phase 7E2 extends the **same** Phase 7E fixed-point state with entry-SP-relative stack facts and entry-argument liveness. It does not introduce another CFG, re-decode instructions, or parse `DecodedInstruction.operands`. `analyze_data_flow()` now returns a `FunctionDataFlow` whose `summary` contains conservative stack, argument, and return evidence when the function is analyzed.

```python
flow = analyze_data_flow(cfg, component)
summary = flow.summary

if summary is not None:
    frame_size = summary.stack_frame.frame_size
    arguments = summary.arguments
    returns = summary.returns
```

Stack position is expressed relative to function-entry SP. The solver tracks exact stack displacement through supported ARM/Thumb `push`, `pop`, and immediate `add/sub sp` forms. Identical stack facts survive CFG joins; conflicting depths become unknown rather than selecting a path. Explicit `mov frame_register, sp` setup is tracked while the frame register remains unmodified. The ARM `fp` register spelling emitted by Capstone is canonicalized to toolkit register `r11` at the decoder/model boundary.

`StackAnalysis` derives slots from the finalized typed flow records. SP-relative or proven frame-pointer-relative memory accesses are converted to entry-SP-relative offsets and preserve decoder-proven access width and load/store direction. Slot classification is structural:

- pushed registers occupy `SAVED_REGISTER` slots in canonical ascending-address order;
- negative entry-SP offsets not identified as saves are `LOCAL` slots;
- non-negative entry-SP offsets are `INCOMING_ARGUMENT` slots;
- insufficiently proven stack locations are not fabricated.

`StackFrame.frame_size` records the deepest proven negative SP displacement reached. If later control-flow joins lose exact stack depth, the proven maximum frame extent remains useful while `stack_depth_known` reports that complete depth tracking was not preserved.

Register-argument evidence is intentionally conservative. Entry values in `r0`-`r3` are considered live until decoder-proven writes replace them; a read before overwrite records evidence for that incoming argument. Read/write instructions record the read first and then kill liveness. Calls kill the caller-saved entry-argument liveness, and CFG joins intersect liveness so an argument is not claimed where one path already overwrote it. Proven incoming stack-slot accesses are exposed as stack argument evidence without inventing a C parameter index.

At every reachable return instruction, the summary records the `r0` abstract value from the instruction's **before** state. Distinct return sites remain separate and deterministically sorted, and an unproven return value remains `UNKNOWN` rather than receiving a guessed type or value.

The stable public models include `StackAccess`, `StackSlot`, `StackFrame`, `StackState`, `StackAnalysis`, `ArgumentEvidence`, `ReturnEvidence`, and `FunctionSummary`, with their associated enums. `analyze_stack()` remains an internal/module-level derivation helper in `analysis.stack`; normal callers consume `analyze_data_flow(...).summary` so stack and ABI evidence cannot drift from the primary data-flow result.

Phase 7E2 does **not** infer source-level function signatures, parameter names, C types, general memory aliases, callee summaries, interprocedural return propagation, symbolic execution, or decompiled source. Those remain later or explicitly out-of-scope capabilities.

## Ownership boundary

The toolkit owns the mechanics above. A game project should own the interpretation layer: known strings, record schemas, confirmed addresses, symbol names, confidence rules, and runtime evidence. Those facts should not be promoted into the generic toolkit unless they are Nintendo DS format behavior rather than game behavior.

## Phase 7F persistent analysis projects

Phase 7F adds a persistent, game-neutral reverse-engineering project format for the toolkit-owned analysis models produced by Phases 7A through 7E. A project is a directory ending in `.ndsre` with two files:

```text
game.ndsre/
  project.json
  analysis.sqlite
```

`project.json` identifies the project-format version and the relative SQLite database path. `analysis.sqlite` stores component fingerprints, generated analysis records, and user annotations. Commercial ROM bytes, extracted component payloads, and other binary component contents are **not** embedded in the project database; component freshness is based on name, runtime base, size, and SHA-256.

Create a project and persist one coherent component analysis bundle with:

```python
from pathlib import Path

from nds_disassembly_toolkit.analysis import (
    AnalysisProject,
    InstructionSet,
)

with AnalysisProject.create(Path("game.ndsre")) as project:
    project.store_component_analysis(bundle)

with AnalysisProject.open(Path("game.ndsre"), read_only=True) as project:
    status = project.component_status(component)
    function = project.function("arm9", 0x02012340, InstructionSet.ARM)
    flow = project.data_flow("arm9", 0x02012340, InstructionSet.ARM)
```

`ComponentAnalysisBundle` is the generated-analysis write boundary. It can carry functions, CFGs, typed instruction semantics, strings, symbols, xrefs, data flow, stack state, warnings, and `FunctionSummary` records for one component. Replacement is atomic: validation happens before mutation, generated rows are replaced in one transaction, and a failure leaves the previous committed analysis intact.

The query API includes component identities/freshness, function lookup/listing, stored strings, symbols by location or name, xrefs to/from addresses, CFG retrieval, data-flow/summary retrieval, and location annotations. Returned tuples use deterministic ordering, and private SQLite row IDs never become semantic identity.

Nintendo DS overlays remain independent even when two components share the same runtime address. Function and symbol identity stays component-aware, and ARM versus Thumb identity remains explicit where required.

`LocationAnnotation` stores user-controlled name overrides, comments, tags, and bookmarks at `(component, address)`. Annotations are deliberately separate from generated symbols and survive successful or failed re-analysis, including when the current generated analysis no longer has a record at the annotated address.

Opening a project read-only uses SQLite read-only mode and does not create or mutate the database. Unsupported or malformed project/schema versions, unsafe database paths, invalid model relationships, and writes through a read-only project raise `AnalysisProjectError`; there is no implicit migration or repair in schema version 1.

Successful generated-analysis writes record toolkit-version and UTC analysis-time provenance without making either field part of freshness equality. The project format uses SQLite rollback-journal mode so a closed `.ndsre` directory remains self-contained and copyable as its manifest plus database.

Phase 7F is a persistence and query substrate. Rich interactive commands such as project browsing, fuzzy symbol search, `who-references`, `what-calls`, `what-writes`, and debugger-facing workflows belong to Phase 7G rather than this storage layer.

## Phase 7G persistent-project CLI

Phase 7G exposes the Phase 7F project APIs through a deterministic command family without changing the underlying analysis models or persistence schema:

```bash
nds-toolkit project create game.ndsre
nds-toolkit project info game.ndsre
nds-toolkit project functions game.ndsre --component arm9
nds-toolkit project function game.ndsre arm9 0x02012340 arm
nds-toolkit project strings game.ndsre --contains battle
nds-toolkit project symbols game.ndsre --address 0x02012340 --component arm9
nds-toolkit project xrefs-to game.ndsre 0x02012340
nds-toolkit project annotations game.ndsre --component arm9
```

The command family also supports `xrefs-from` for exact source locations and exact-name symbol queries. Function inspection is component/address/mode exact and returns the persisted function together with its CFG, typed instruction semantics, data-flow/stack/ABI summary, and entry annotation when those records exist. A missing exact function is an error rather than an ambiguous `null` result.

All query commands open projects read-only. Runtime addresses and analysis offsets are rendered as canonical hexadecimal strings, enum values use their stable toolkit values, and operand access flags are rendered symbolically as `read`/`write` rather than as implementation bitmasks. Output is deterministic JSON. Any command may write that JSON atomically to a file with `--output`:

```bash
nds-toolkit project function game.ndsre arm9 0x02012340 arm \
  --output function-02012340.json
```

Address-based symbol lookup requires a component because Nintendo DS overlays may share the same runtime address. `xrefs-to` deliberately does not invent target-component ownership from a numeric address; source-component filtering is explicit with `--source-component`.

User annotations remain separate from generated symbols. `annotate` performs patch-style updates: omitted fields are preserved, while explicit clear/unbookmark flags remove them. For example:

```bash
nds-toolkit project annotate game.ndsre arm9 0x02012340 \
  --name BattleManager \
  --comment "confirmed from runtime trace" \
  --tag runtime \
  --tag confirmed \
  --bookmark

nds-toolkit project annotate game.ndsre arm9 0x02012340 --clear-comment
```

Repeated `--tag` arguments replace the complete normalized tag set. A no-op `annotate` invocation is rejected rather than performing an unnecessary writable project open.

Phase 7G is a presentation/query layer only. It adds no new function discovery, CFG/xref/symbol/data-flow inference, does not embed ROM or component bytes, and adds no third-party dependency. A stateful REPL/TUI is still deferred. Emulator/debugger trace integration is the separate Phase 7H boundary.

## Phase 7I conservative pseudo-C decompiler

Phase 7I derives deterministic, conservative pseudo-C directly from the evidence already stored in a Phase 7F `.ndsre` project. It is a read-only view: no pseudo-C is written back to the project, no schema migration is required, and current symbols or user annotations affect the next decompilation immediately.

The command identifies a function exactly by component, runtime address, and ARM/Thumb mode:

```bash
nds-toolkit project decompile game.ndsre arm9 0x02012340 --mode arm

nds-toolkit project decompile game.ndsre arm9 0x02012340 \
  --mode arm \
  --format json

nds-toolkit project decompile game.ndsre overlay_7 0x02200000 \
  --mode thumb \
  --output function-02200000.c
```

Text is the default output. `--format json` returns a small deterministic envelope containing component, address, instruction set, resolved function name, pseudo-C, fallback status, and warnings. Both text and JSON use the same atomic `--output` replacement behavior as other project commands.

The decompiler consumes only toolkit-owned persisted evidence:

- exact function and ARM/Thumb identity;
- CFG/basic-block structure and direct control-flow edges;
- typed decoded instruction semantics;
- intraprocedural exact register/address/constant flow;
- recovered stack slots, arguments, and return evidence;
- component-aware symbols and user annotation name overrides;
- exact direct-call targets and persisted project relationships.

The output deliberately prefers truthful incompleteness over convincing guesses. Stack slots become structural names such as `local_04`, register arguments use names such as `arg0`, and memory accesses use only decoder-proven width types such as `uint8_t`, `uint16_t`, or `uint32_t`. Phase 7I does not infer source structs, classes, signed memory types, rich prototypes, or semantic gameplay names.

Control-flow structuring is likewise conservative. Proven straight-line regions, simple `if`, `if/else`, early-return forms, and simple natural pre-test/post-test loops may be rendered with high-level syntax. If a graph is multi-entry, irreducible, or otherwise unsafe to structure, the decompiler retains canonical `loc_XXXXXXXX` labels and `goto` statements instead of fabricating a structured construct.

Unsupported instructions remain visible with their source address. Ambiguous direct calls into overlapping Nintendo DS overlay address ranges retain a structural target name instead of being assigned to a guessed component. Exact component identity is never discarded merely because two overlays share a runtime address.

Pseudo-C is **reverse-engineering assistance, not recovered original source and not a claim of recompilable C**. It is intended to reduce the human work of translating ARM/Thumb instructions into function-level behavior while keeping the evidence boundary inspectable.

Phase 7H runtime traces remain a separate evidence source and are not silently mixed into Phase 7I output.

## Phase 7J investigation and prioritization

Phase 7J provides a read-only evidence-fusion layer that answers which persisted functions should be inspected next and why. It combines explicit text clues, typed immediate constants, requested-address xrefs, optional Phase 7H2 trace differentials, and exactly one hop of persisted call relationships using fixed transparent weights.

```bash
nds-toolkit project investigate game.ndsre \
  --text battle \
  --constant 500 \
  --baseline idle.ndstrace \
  --target battle.ndstrace \
  --top 10 \
  --decompile
```

Candidate identity remains `(component, runtime_address, instruction_set)`. Ambiguous component-less call targets are not guessed, and string/xref evidence is suppressed when overlapping components persist different strings at the same numeric runtime address. Optional pseudo-C is delegated to the Phase 7I decompiler only after deterministic ranking and `--top` truncation, so it is context rather than a hidden score source.

`project investigate` opens `.ndsre` read-only and reads `.ndstrace` files offline. Phase 7J introduces no persistence migration, debugger connection, new decoder/runtime engine, or new third-party dependency. See `docs/investigation.md` for selector semantics, score weights, output formats, and examples.


## Phase 7K SSA and decompiler IR v2

Phase 7K refines the existing Phase 7I decompiler internally without changing the public `decompile_function(...)` or `project decompile` workflow.

The on-demand decompiler pipeline is now:

```text
persisted CFG + typed semantics + FunctionDataFlow
        ↓
Phase 7I source-like lift
        ↓
promotable-storage normalization
        ↓
deterministic SSA
├── dominators / immediate dominators
├── dominance frontiers
├── PHI placement
├── register/stack/temp versioning
└── def-use indexing
        ↓
partial ValueFacts
        ↓
fixed-point simplification
        ↓
SSA lowering
        ↓
existing structurer + renderer
        ↓
pseudo-C
```

Only exact storage identities are promoted: toolkit registers, exact recovered stack slots/arguments, and deterministic decompiler temporaries. Arbitrary memory reads/writes are **not** converted to memory SSA. Memory writes, calls, unsupported statements, and other side effects remain explicit.

The initial value-fact layer tracks conservative 32-bit information including known-zero/known-one masks, derived signed/unsigned bounds, proven nonzero state, alignment, and component-aware proven addresses. A naked numeric constant is not guessed to belong to an overlay.

The simplifier repeatedly applies a stable pass order for constant folding, copy/safe-expression propagation, PHI cleanup, exact algebraic identities, and dead pure-definition removal. It stops at a defensive iteration cap and reports non-convergence rather than making an unsound transformation.

Example machine-register churn such as:

```text
r1 = arg0
r2 = r1 + 4
return r2
```

can now lower to pseudo-C equivalent to:

```c
return arg0 + 4;
```

while conflicting PHIs, calls, memory effects, unsupported operations, and ambiguous overlay ownership remain conservative.

Phase 7K is derived on demand. It does not change the `.ndsre` schema, persist SSA, introduce another decoder, or add Ghidra/LLVM/RetDec/Miasm/angr as runtime dependencies.


## Phase 7L type, pointer, and structure recovery

Phase 7L runs after the Phase 7K SSA/value-fact simplification stage and before final source-like
lowering/rendering. It remains a derived, read-only analysis layer: no Phase 7L type or structure
record is written into `.ndsre`.

The local pipeline is:

```text
persisted analysis
    ↓
Phase 7I lift
    ↓
Phase 7K SSA
    ↓
Phase 7K value facts + simplification
    ↓
Phase 7L access-path normalization
    ↓
pointer/type/field evidence
    ↓
local structure candidates
    ↓
typed source-like lowering
    ↓
existing control-flow structurer
    ↓
typed pseudo-C
```

Memory addresses are normalized from toolkit-owned SSA expressions rather than assembly display
strings. The first supported forms are a unique SSA root plus a constant byte offset and,
optionally, one scaled index. Expressions with multiple equally plausible roots remain unresolved.

A direct non-negative `root + offset` dereference supplies pointer-use and field evidence. Access
width supplies the initial fixed-width integer field type. Signed/unsigned comparison use can
refine signedness; conflicting signedness widens back to unknown. Exact value-fact addresses may
supply pointer/component evidence, but a numeric constant is not promoted to a pointer merely
because its value resembles Nintendo DS RAM.

Local structure recovery groups compatible direct field accesses by canonical pointer root.
Exact SSA copies and PHIs whose inputs resolve to one unique root share that root. Conflicting
PHIs remain independent. Same-offset width conflicts or overlapping incompatible fields prevent
typed rendering and preserve the existing raw-memory form.

The default renderer only emits a synthetic structure when evidence passes a conservative
threshold: at least two distinct compatible fields, repeated accesses to one field from distinct
sites, or compatible interprocedural support. Synthetic names such as `struct_func_arg0` and
`field_18` are deterministic evidence labels, not claims about original source identifiers.

When a candidate qualifies, the decompiler can render:

```c
struct struct_update_arg0 {
    uint32_t field_04;
    uint16_t field_18;
};

uint32_t update(struct struct_update_arg0 *arg0) {
    return arg0->field_04;
}
```

instead of:

```c
uint32_t update(uint32_t arg0) {
    return *(uint32_t *)(arg0 + 4);
}
```

The old conservative memory rendering remains the fallback for insufficient, indexed, negative,
overlapping, or otherwise ambiguous evidence.

Phase 7L also provides a bounded interprocedural propagation service over direct call edges.
Propagation requires a unique target identity `(component, runtime_address, instruction_set)`.
A component-less call whose numeric target matches multiple overlays is not propagated. Compatible
caller/callee root layouts converge through deterministic fixed-point iteration; incompatible
field widths remain conflicts instead of being silently unified.

The current public `decompile_function(...)` service automatically uses local Phase 7L recovery
after Phase 7K simplification. Interprocedural propagation is available as an analysis service but
is not persisted into the project database. Phase 7L adds no decoder, no schema migration, no
runtime/emulator dependency, and no game-specific semantics.
