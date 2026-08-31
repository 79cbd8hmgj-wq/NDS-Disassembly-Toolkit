# Provenance and third-party reference audit

Audit date: 2026-08-28

This document records the provenance boundary for external Nintendo DS and reverse-engineering tools that informed the development of `NDS-Disassembly-Toolkit` and its predecessor work in `Bakugan-DS-`.

The toolkit itself is distributed under the MIT License. See the repository root `LICENSE` file.

## Policy

External repositories listed here are either **reference material** or explicitly documented runtime dependencies. No external implementation source is vendored unless a future audit records that decision here.

The migration and capability-development policy is:

1. reuse the project's own proven game-independent Python code when it was already independently implemented;
2. use external tools to understand public Nintendo DS formats, expected behavior, workflow ideas, interoperability constraints, and mature reverse-engineering architecture;
3. do not copy GPL implementation source into the MIT toolkit unless the licensing model is deliberately changed and the required GPL obligations are satisfied;
4. treat source with no explicit license as unavailable for implementation copying;
5. document direct third-party runtime dependencies and their licensing boundary before merging them;
6. keep copied code or incorporated licensed assets out of the repository unless they are separately reviewed and their license/attribution obligations are documented here.

This is an engineering provenance record, not a substitute for legal advice.

## Audited references

| Reference | Repository examined | License observed on 2026-08-27 | How it informed this project | Incorporation boundary |
| --- | --- | --- | --- | --- |
| NDSFactory | https://github.com/Luca1991/NDSFactory | GNU GPL v3 (`LICENSE`) | Comparison/reference for NDS extraction and repacking concepts already covered by the project's stricter parser/workspace/rebuild implementation | No NDSFactory source vendored or copied; extraction/repacking implementation was not imported |
| Tinke | https://github.com/pleonex/tinke | GNU GPL v3 (`Licence.txt`) | Standard Nintendo Nitro asset/container conventions and signatures relevant to read-only asset classification | No Tinke source vendored or copied; the toolkit uses a clean-room Python classifier |
| NitroPacker | https://github.com/haroohie-club/NitroPacker | GNU GPL v3 (`LICENSE`) | Architectural reference for an external ARM source-compilation workflow | No NitroPacker source vendored or copied; source compilation/application is independently implemented in Python around user-selected LLVM/binutils-compatible tools |
| ndstool | https://github.com/devkitPro/ndstool | GNU GPL v3 (`COPYING`) | Comparison/reference for conventional NDS extraction/repacking behavior | No ndstool source vendored or copied; the toolkit's parser/rebuilder remains its own implementation |
| pret DS disassembly tools | https://github.com/pret/ds_disassembly_tools | **No explicit license found** in the repository root or README during this audit | Workflow concepts such as finding Nitro module parameters, overlay-layout investigation, labelled binary regions, and disassembly comparison | Implementation source is treated as unavailable for copying; toolkit behavior was reimplemented independently and extended with its own validation/error model |
| Capstone | https://github.com/capstone-engine/capstone | BSD 3-Clause-style license (`LICENSES/LICENSE.TXT` in supplied `capstone-next.zip`) | ARM/Thumb instruction decoding and semantic instruction metadata for Phase 7 analysis | Added as `capstone>=5,<7` runtime dependency; no Capstone source is vendored or copied into toolkit modules |
| angr | https://github.com/angr/angr | BSD 2-Clause-style license (`LICENSE` in supplied `angr-master.zip`) | Reference architecture for function recovery, CFGs, data flow, symbolic analysis, and analysis persistence | Reference only during Phase 7 design; no angr runtime dependency or source incorporation |
| melonDS | https://github.com/melonDS-emu/melonDS | GNU GPL v3 (`LICENSE` in supplied `melonDS-master.zip`) | Nintendo DS runtime/emulator behavior and future debugger/trace integration concepts | Reference/external-integration boundary only; no melonDS implementation source is copied or linked into the MIT toolkit |

### Archive-origin caveats

Earlier project work used a supplied archive named `ndstool-master.zip`. That filename alone does not preserve a verifiable remote repository origin in the current source tree. This audit records `devkitPro/ndstool` as the examined upstream repository for the ndstool lineage. If the exact supplied archive is later identified as a different fork or commit, add its repository, commit/hash, and license here rather than assuming equivalence.

Phase 7 reference archives were supplied as `capstone-next.zip`, `angr-master.zip`, and `melonDS-master.zip`. Their exact commit hashes are not encoded in this repository, so the audit records the canonical project lineage and the license text observed inside each supplied archive rather than asserting an exact upstream commit.

## Clean-room implementation notes

### NDSFactory and ndstool

The predecessor Bakugan project already had stricter NDS header/FAT/FNT/overlay parsing, deterministic extraction, workspace validation, compression handling, and deterministic rebuild behavior. NDSFactory and ndstool were therefore used to compare concepts and expected workflows rather than as implementation sources.

The standalone toolkit migrated those existing Python implementations into the `nds_disassembly_toolkit` namespace and generalized game/profile policy at the package boundary.

### Tinke

Tinke helped identify standard Nitro format conventions relevant to the asset inventory. The toolkit's asset implementation performs its own LZ10 handling and signature/extension classification in Python. Game-specific interpretation remains outside the generic classifier.

Format identifiers such as `BMD0`, `BTX0`, `SDAT`, `NARC`, `RGCN`, `RLCN`, `RCSN`, `BCA0`, `BMA0`, `BTP0`, `BTA0`, and `BVA0` are treated as format facts, not copied implementation expression.

### NitroPacker

NitroPacker informed the high-level idea of compiling external C/assembly into approved Nintendo DS runtime placements. The toolkit independently implements:

- manifest parsing and validation;
- safe relative source-path resolution;
- explicit ARMv5TE clang command construction;
- temporary linker-script generation;
- symbol parsing;
- ARM/Thumb branch encoding;
- runtime/address validation;
- exact-byte/hash guards;
- BLZ storage validation;
- stale-write protection and rollback;
- deterministic reporting.

No NitroPacker runtime/library code is linked, imported, or redistributed by the toolkit.

### pret/ds_disassembly_tools

Because no explicit license was found, its implementation is treated more restrictively than the GPL references: concepts may guide independent engineering, but source text must not be copied into the toolkit.

A direct audit of the shortest overlapping helpers illustrates the separation:

- upstream `find_module_params.py` finds the `0xDEC00621` magic byte sequence and subtracts 28;
- toolkit `find_module_params` independently validates aligned candidates, rejects ambiguous matches, parses the complete eight-word module-parameter structure, checks the magic again, handles base addresses, and returns a typed `ModuleParams` model;
- upstream `insert_labels.py` is a command-line byte dumper over supplied offsets;
- toolkit `render_labelled_bytes` validates label bounds, guarantees a component-base label, deduplicates/sorts boundaries, and renders deterministic labelled byte ranges as a reusable function;
- toolkit objdump invocation and unified diff generation are implemented directly in Python rather than incorporating `asmdiff.sh`.

The toolkit does not contain the upstream scripts `asmdiff.sh`, `dump_fs.py`, `find_module_params.py`, `get_overlay_load_order.py`, `insert_labels.py`, `merge_nef.py`, `ntruncompbw.c`, or their source text.

### Phase 7 analysis references

Capstone is intentionally different from the earlier clean-room references: it is a permissively licensed runtime dependency used through its public Python API. `analysis/decoder.py` is toolkit-owned code that converts Capstone results into toolkit-owned immutable models, so Capstone objects do not become the public analysis data model.

angr is being used to study mature approaches to function discovery, CFG recovery, data-flow analysis, and persistent analysis state. Phases 7A through 7E2 do not import angr or copy its analysis implementation. Phase 7B uses an independently implemented two-pass reachable-instruction/basic-block design, Phase 7C independently normalizes toolkit-owned CFG/pointer records into immutable xref, query-index, and call-graph models, Phase 7D independently merges toolkit-owned function, CFG, string, and explicit-name records into a component-aware immutable symbol table, Phase 7E1 independently implements toolkit-owned typed instruction semantics plus an intraprocedural abstract-value fixed-point solver over those existing CFGs, and Phase 7E2 extends that same solver with toolkit-owned stack position and entry-argument liveness before deriving function summaries from the finalized flow records.

Phase 7E2 adds no new third-party dependency. Capstone remains confined to the decoder boundary; stack displacement, frame-pointer facts, stack-slot classification, use-before-overwrite argument evidence, per-return `r0` evidence, and `FunctionSummary` construction are toolkit-owned logic over the typed 7E1 records. The ARM `fp` spelling is normalized to canonical `r11` at that boundary rather than interpreted from presentation text downstream. angr remains reference material only and is not imported or linked.

The Phase 7E2 implementation deliberately does not adopt angr's abstract-state or calling-convention implementation. It uses the toolkit's existing deterministic CFG/worklist, finite exact-value lattice, decoder-proven register effects, and immutable flow records. `analysis/stack.py` derives stack-frame/slot summaries only from `FunctionDataFlow` and does not decode bytes or construct a second control-flow graph.

### Phase 7F persistence boundary

Phase 7F persists the toolkit-owned Phase 7A through 7E analysis models using Python's standard-library `sqlite3` module. It adds no runtime dependency and does not import, link, vendor, or copy angr's persistence implementation. angr remains architecture/reference material only.

The `.ndsre` schema stores normalized toolkit records for component fingerprints, functions, CFGs, typed instruction semantics, strings, generated symbols, xrefs, register/data-flow state, stack/argument/return summaries, warnings, and user location annotations. It does **not** embed ROM images, melonDS payloads, extracted executable component bytes, or commercial game assets. Component bytes are used only to compute the SHA-256 fingerprint supplied to persistence.

Capstone remains confined to the decoder boundary established in Phase 7A. Phase 7F serializes only toolkit-owned typed instruction models and reconstructs those models without Capstone objects, Capstone enum types, or reparsing the human-readable operand string.

melonDS remains a GPL reference/external-integration boundary. Phase 7F neither embeds melonDS data structures nor copies/link its project/debugger implementation. Any future dynamic-analysis bridge should preserve the process/interface separation already recorded above.

SQLite schema design, canonical JSON codecs, transactional replacement, component freshness, deterministic queries, and annotation persistence are independently implemented toolkit logic. No third-party persistence code was incorporated.

melonDS is GPL-licensed and therefore remains on the same strict reference boundary as the earlier GPL Nintendo DS tools. Future dynamic-analysis work should prefer process/debugger integration or documented interfaces rather than incorporating melonDS implementation source into this MIT repository.

### Phase 7G persistent-project CLI boundary

Phase 7G is a toolkit-owned presentation and query layer over the public Phase 7F `AnalysisProject` API. Its implementation uses only the Python standard library plus existing toolkit models and project interfaces; it introduces no third-party runtime dependency and incorporates no external implementation source.

The CLI serializer converts toolkit-owned immutable analysis records into deterministic JSON. It does not import Capstone, `sqlite3`, private persistence schema/codec modules, or third-party analysis objects. Query commands open projects read-only, while annotation mutation goes through the existing public writable annotation API rather than issuing direct SQL or altering the project schema.

Phase 7G adds no ROM/component byte persistence, new reverse-engineering inference, emulator integration, game-specific policy, or commercial game data. Capstone therefore remains confined to the decoder boundary, angr remains reference material only, and melonDS remains on the external-integration boundary reserved for the later dynamic-analysis phase.

## Repository audit observations

During Phase 6 consolidation:

- no source-tree references to `NDSFactory`, `Tinke`, or `NitroPacker` were found under `src/nds_disassembly_toolkit`;
- no upstream source tree is vendored beneath the toolkit repository;
- the repository contains only the toolkit's Python source, tests, documentation, and CI/configuration files;
- historical design documents explicitly state that the supplied upstream archives were reference material only and that GPL/upstream implementation source was not vendored or copied;
- Bakugan remains the owner of B6RE-specific evidence, addresses, patches, and gameplay systems rather than transferring game-specific material into the toolkit.

Phase 7A deliberately adds Capstone only as a package dependency. Phases 7B through 7E2 add toolkit-owned CFG, xref/index/call-graph, symbol-recovery, typed-semantic, register-data-flow, stack-frame, argument-evidence, return-evidence, and function-summary models and logic; angr and melonDS remain non-vendored reference material. Phase 7F adds only toolkit-owned SQLite persistence/query logic over those models and no new third-party dependency. Phase 7G adds only toolkit-owned argparse/JSON project presentation, query, and annotation wiring over the Phase 7F public API; it changes neither `pyproject.toml` nor the persistence schema and adds no dependency.

Text search and manual comparison are useful audit evidence but cannot mathematically prove independent authorship. Future contributors should preserve the boundary above and document any deliberate third-party code incorporation before merging it.

## Contributor checklist

Before adding code based on an external NDS or reverse-engineering project:

1. identify the exact repository and commit/release when available;
2. record the license before reading/copying implementation source for reuse;
3. decide whether the need is a public format fact, behavioral reference, architecture reference, runtime dependency, or actual code reuse;
4. prefer independent implementation for format facts/behavior when the upstream license is incompatible with the toolkit's MIT distribution goals;
5. never copy code from a repository with no explicit reuse license;
6. if a direct dependency or licensed code reuse is intentional, preserve required notices/attribution and review whether the toolkit's distribution license must change;
7. add the source and decision to this document;
8. keep commercial ROMs, extracted copyrighted assets, and rebuilt ROM images out of the repository.
