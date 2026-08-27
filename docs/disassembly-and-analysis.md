# Disassembly and static-analysis helpers

The toolkit provides game-neutral preparation, comparison, and program-analysis helpers for Nintendo DS ARM9, ARM7, and overlay binaries. It does not assign game-specific semantics.

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

## Generic static analysis report

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

## Phase 7A: ARM/Thumb function discovery

Phase 7A adds a program-analysis layer above the earlier byte-oriented scanners. Capstone performs ARM/Thumb instruction decoding, but Capstone objects do not escape the toolkit boundary. The public analysis API uses toolkit-owned models such as `DecodedInstruction`, `ExecutionMode`, `FunctionSeed`, and `FunctionCandidate`.

Function discovery is intentionally conservative. It starts from explicit evidence and recursively follows decoded control flow:

- an explicit seed becomes a function candidate;
- an in-component direct call target becomes high-confidence function evidence;
- an ordinary branch target is followed as control flow but is **not** promoted to a function merely because it is branched to;
- direct `BLX` mode transitions propagate ARM/Thumb mode;
- returns stop the current path;
- unresolved indirect transfers are reported instead of guessed;
- duplicate discoveries merge evidence and retain the strongest confidence.

### Python API

```python
from pathlib import Path

from nds_disassembly_toolkit.analysis import (
    Component,
    ExecutionMode,
    FunctionSeed,
    arm_prologue_seeds,
    discover_functions,
)

arm9_path = Path("arm9.bin")
component = Component(
    name="arm9",
    path=arm9_path,
    base_address=0x02000000,
    data=arm9_path.read_bytes(),
)

seeds = [
    FunctionSeed(
        address=0x02000800,
        mode=ExecutionMode.ARM,
        evidence="arm9-entry",
        confidence="high",
    ),
    *arm_prologue_seeds(component),
]

result = discover_functions(component, seeds)

for function in result.functions:
    print(
        hex(function.address),
        function.mode,
        function.confidence,
        function.evidence,
    )

for address in result.unresolved_indirect_transfers:
    print("unresolved indirect transfer:", hex(address))
```

ARM function seeds must be 4-byte aligned and Thumb seeds 2-byte aligned. Seeds outside the supplied component are rejected.

### Legacy prologue heuristic

`arm_function_starts`, `nearest_function_start`, and `function_address_for_reference` remain available with their original offset-based behavior. `arm_prologue_seeds` is an adapter that converts those matches to medium-confidence, runtime-addressed ARM `FunctionSeed` records for the new discovery engine.

A prologue match is evidence, not proof. Functions can omit a conventional prologue, and data can occasionally resemble one.

### Current Phase 7 boundary

Phase 7A1 provides decoding and recursive function discovery. It does **not** yet provide persistent basic-block/control-flow graphs, a cross-reference database, symbol recovery, data-flow analysis, an analysis-project database, emulator traces, or pseudo-C. Those are later Phase 7 capability slices and should build on the decoder/discovery models rather than bypassing them.

## Ownership boundary

The toolkit owns the mechanics above. A game project should own the interpretation layer: known strings, record schemas, confirmed addresses, symbol names, confidence overrides, game-specific entry points, and runtime evidence. Those facts should not be promoted into the generic toolkit unless they are Nintendo DS format/runtime behavior rather than game behavior.
