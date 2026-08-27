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

Phase 7B does not add a graph-library dependency or leak Capstone objects into public data models. Phase 7C can build xrefs and call graphs directly from these records rather than introducing a second decoding/CFG implementation.

## Ownership boundary

The toolkit owns the mechanics above. A game project should own the interpretation layer: known strings, record schemas, confirmed addresses, symbol names, confidence rules, and runtime evidence. Those facts should not be promoted into the generic toolkit unless they are Nintendo DS format behavior rather than game behavior.
