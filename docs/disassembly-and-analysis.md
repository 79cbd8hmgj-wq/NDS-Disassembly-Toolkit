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

## Ownership boundary

The toolkit owns the mechanics above. A game project should own the interpretation layer: known strings, record schemas, confirmed addresses, symbol names, confidence rules, and runtime evidence. Those facts should not be promoted into the generic toolkit unless they are Nintendo DS format behavior rather than game behavior.