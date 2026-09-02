# NDS Disassembly Toolkit

Reusable Nintendo DS reverse-engineering infrastructure for inspecting, extracting, rebuilding, disassembling, analyzing, tracing, and patching NDS ROMs without tying the core implementation to one game.

## Current capabilities

The standalone toolkit now provides:

- NDS header, FAT, FNT/NitroFS, and ARM9/ARM7 overlay-table parsing;
- deterministic LZ10 compression/decompression;
- BLZ footer parsing, decompression, in-place decode modeling, and deterministic compression;
- optional exact-ROM profiles and structural ROM inspection;
- deterministic editable workspace extraction, validation, and ROM rebuilding;
- guarded fixed-length binary patch application;
- ARM9 Nitro module-parameter discovery, overlay-layout reports, labelled-byte output, and objdump diffs;
- generic string, numeric, pointer-reference, and report helpers for static analysis;
- Nitro asset inventory/classification;
- ARMv5TE C/assembly compilation and guarded ARM/Thumb source-patch application;
- ARM/Thumb function discovery, basic blocks/CFGs, cross-references, direct call graphs, component-aware symbol recovery, and typed instruction semantics;
- intraprocedural constant/address/register flow, stack-frame/slot recovery, argument evidence, return evidence, and function summaries;
- versioned persistent `.ndsre` analysis projects with component fingerprints, stale-analysis detection, generated analysis replacement, annotations, and deterministic query APIs;
- `nds-toolkit project` commands for persistent function/string/symbol/xref/CFG/data-flow/annotation inspection;
- conservative evidence-backed ARM/Thumb pseudo-C generated from persisted CFG, data-flow, stack/ABI, symbol, and annotation evidence, with safe control-flow structuring and explicit uncertainty fallback;
- melonDS GDB-RSP runtime inspection for ARM9/ARM7, including snapshots, memory reads, temporary code conditions, and bounded stepping;
- portable `.ndstrace` capture, BEFORE/AFTER memory differentials, read-only static-project correlation, behavioral trace comparison, and transparent dynamic function ranking;
- deterministic Phase 7J investigation ranking that fuses matching strings/annotations, typed constants, requested-address xrefs, one-hop call relationships, and existing runtime trace differentials, with optional top-candidate pseudo-C previews;
- reusable CLI parser/runner helpers so game projects can consume toolkit commands while enforcing stricter game-specific policy.

The primary CLI entry point is `nds-toolkit` (or `python -m nds_disassembly_toolkit`).

## Development setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

## CLI overview

```bash
nds-toolkit --help
nds-toolkit inspect GAME.nds
nds-toolkit extract GAME.nds work/game
nds-toolkit rebuild GAME.nds work/game output.nds
nds-toolkit patch work/game patch.json
nds-toolkit disasm --help
nds-toolkit analyze --help
nds-toolkit project --help
nds-toolkit project decompile game.ndsre arm9 0x02012340 --mode arm
nds-toolkit project investigate game.ndsre --text power --constant 500 --top 25
nds-toolkit project investigate game.ndsre --baseline idle.ndstrace --target attack.ndstrace --decompile
nds-toolkit runtime --help
nds-toolkit assets inventory GAME.nds --output assets.json
nds-toolkit source-patch build work/game source-patch.json
```

`project investigate` is read-only. Supply at least one text, constant, address, or baseline/target trace selector. Static and runtime evidence are scored with fixed transparent weights, ambiguous overlapping-overlay call targets are never guessed, and `--decompile` runs the existing conservative decompiler only for candidates that survive ranking and `--top` truncation.

### ROM profiles and support policy

Generic toolkit ROM commands are structural by default. A profile can be supplied with `--profile PROFILE.json`; use `--require-supported` when the operation must fail unless the ROM exactly matches that profile.

Profiles bind an ID, SHA-256, size, Nintendo DS identity fields, and expected ROM-layout values. Game-specific consumers may intentionally wrap the reusable parser/runner helpers with stricter defaults. For example, a project may require an exact supported profile for every write command while allowing an explicit read-only unsupported inspection path.

The toolkit itself contains no canonical commercial-game profile.

## Workflow documentation

- [Workspace extraction and rebuild](docs/workspace-and-rebuild.md)
- [Disassembly, static analysis, and persistent projects](docs/disassembly-and-analysis.md)
- [Runtime debugging, `.ndstrace`, and behavioral differentials](docs/runtime-debugging.md)
- [Nitro asset inventory](docs/assets.md)
- [Guarded binary patching](docs/binary-patching.md)
- [Guarded ARM/Thumb source patching](docs/source-patching.md)
- [Provenance and third-party reference audit](docs/provenance-and-licenses.md)

Architecture and migration history remain under `docs/superpowers/`.

## Reuse and project separation

This repository is the source of truth for reusable Nintendo DS mechanics. Game projects should consume the toolkit rather than copy its implementations.

Game-specific repositories remain responsible for knowledge and policy such as:

- exact supported ROM profiles and reference hashes;
- game-specific addresses, symbols, table layouts, and reverse-engineering evidence;
- gameplay rules and modifications;
- game-specific patch manifests and source placements;
- stricter profile/application policy layered around generic toolkit operations.

Thin compatibility adapters are acceptable when they preserve an existing consumer API or enforce game-specific policy. They should delegate the underlying Nintendo DS mechanics to this toolkit.

## License and provenance

The toolkit is distributed under the [MIT License](LICENSE).

External Nintendo DS projects used during research are treated as reference material or external interoperability targets unless a separately reviewed incorporation decision says otherwise. The [provenance audit](docs/provenance-and-licenses.md) records the GPL/unlicensed upstream boundaries and the project's clean-room policy. Commercial ROMs, extracted copyrighted assets, and rebuilt ROMs are not part of this repository.

## Legal boundary

This repository contains source code, documentation, schemas, synthetic tests, and headless interoperability harness code. It does not contain commercial ROM images, extracted copyrighted game assets, or rebuilt ROM images. Users are responsible for supplying any legally obtained ROMs used with the toolkit.
