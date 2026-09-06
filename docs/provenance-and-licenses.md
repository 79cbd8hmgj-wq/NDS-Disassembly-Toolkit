# Provenance and third-party reference audit

Audit updated: 2026-09-06

This document records the provenance boundary for external Nintendo DS and reverse-engineering tools that informed `NDS-Disassembly-Toolkit` and its predecessor work in `Bakugan-DS-`.

The toolkit itself is distributed under the MIT License. See the repository root `LICENSE` file.

## Policy

External repositories listed here are either **reference material**, **permissively licensed runtime dependencies**, or **external interoperability targets**. No external implementation source is vendored unless a future audit records that decision here.

The development policy is:

1. reuse the project's own proven game-independent code when it was already independently implemented;
2. use external tools to understand public Nintendo DS formats, expected behavior, workflow ideas, interoperability constraints, and mature reverse-engineering architecture;
3. do not copy GPL implementation source into the MIT toolkit unless the licensing model is deliberately changed and the required GPL obligations are satisfied;
4. treat source with no explicit license as unavailable for implementation copying;
5. document direct runtime dependencies and external-process interoperability boundaries before merging them;
6. keep copied code or incorporated licensed assets out of the repository unless separately reviewed and documented here.

This is an engineering provenance record, not a substitute for legal advice.

## Audited references

| Reference | Repository examined | License observed | How it informed this project | Incorporation boundary |
| --- | --- | --- | --- | --- |
| NDSFactory | https://github.com/Luca1991/NDSFactory | GNU GPL v3 (`LICENSE`) | Comparison/reference for NDS extraction and repacking concepts | No source vendored or copied; toolkit extraction/rebuild implementation is independent |
| Tinke | https://github.com/pleonex/tinke | GNU GPL v3 (`Licence.txt`) | Nintendo Nitro asset/container conventions and signatures | No source vendored or copied; toolkit asset classification is independently implemented |
| NitroPacker | https://github.com/haroohie-club/NitroPacker | GNU GPL v3 (`LICENSE`) | Architectural reference for external ARM source-compilation workflow | No source vendored or copied; compiler/linker/patch workflow is toolkit-owned |
| ndstool | https://github.com/devkitPro/ndstool | GNU GPL v3 (`COPYING`) | Comparison/reference for conventional NDS extraction/repacking behavior | No source vendored or copied; parser/rebuilder remains toolkit-owned |
| pret DS disassembly tools | https://github.com/pret/ds_disassembly_tools | **No explicit license found** during audit | Workflow concepts such as module parameters, overlay layout, labelled regions, and disassembly comparison | Implementation source is treated as unavailable for copying |
| Capstone | https://github.com/capstone-engine/capstone | BSD 3-Clause-style license (`LICENSES/LICENSE.TXT` in supplied archive) | ARM/Thumb decoding and semantic instruction metadata | `capstone>=5,<7` is a runtime dependency; no Capstone source is vendored |
| angr | https://github.com/angr/angr | BSD 2-Clause-style license (`LICENSE` in supplied archive) | Reference architecture for function recovery, CFGs, data flow, symbolic analysis, persistence, decompiler-stage separation, and evidence-oriented RE workflow design | Reference only through Phase 7J; no angr runtime dependency or source incorporation |
| Ghidra | https://github.com/NationalSecurityAgency/ghidra | Apache License 2.0 | Phase 7K architecture reference for SSA heritage, storage-vs-value identity, PHI/rename staging, transform pools, and decompiler type-system organization | Reference only; no Ghidra source copied, translated, vendored, linked, or imported |
| Miasm | supplied source archive / https://github.com/cea-sec/miasm | GNU GPL v2 | Phase 7K behavioral/architectural comparison for graph SSA, PHI placement/renaming, fixed-point simplification, and conservative treatment of memory | GPL reference-only; no implementation source incorporated into the MIT toolkit |
| RetDec | supplied source archive / https://github.com/avast/retdec | MIT plus repository third-party notices | Phase 7K reference for def-use/reaching-definitions, HLL optimization, alias-analysis boundaries, and type/composite-type architecture | Reference only in Phase 7K; no RetDec implementation source incorporated |
| LLVM ValueTracking | supplied `ValueTracking.cpp` / https://github.com/llvm/llvm-project | Apache-2.0 WITH LLVM-exception | Phase 7K concept reference for known-zero/known-one bits, ranges, nonzero facts, PHI/select reasoning, and conservative value tracking | Concepts only; no LLVM implementation source copied or ported |
| melonDS | https://github.com/melonDS-emu/melonDS | GNU GPL v3 | Nintendo DS runtime behavior and GDB-RSP interoperability | External GPL process/build only; no melonDS implementation is copied, linked, translated, or vendored into the MIT toolkit |

### Archive-origin caveats

Earlier work used a supplied archive named `ndstool-master.zip`. That filename alone does not preserve a verifiable remote repository origin in the source tree. This audit records `devkitPro/ndstool` as the examined upstream lineage. If the exact supplied archive is later identified as a different fork or commit, record it separately rather than assuming equivalence.

Phase 7 reference archives were supplied as `capstone-next.zip`, `angr-master.zip`, and `melonDS-master.zip`. Their exact commit hashes are not encoded by those archive names, so the audit records the canonical project lineage and observed license text rather than asserting an archive commit identity.

## Clean-room implementation notes

### NDSFactory and ndstool

The predecessor Bakugan project already had stricter NDS header/FAT/FNT/overlay parsing, deterministic extraction, workspace validation, compression handling, and deterministic rebuild behavior. NDSFactory and ndstool were used to compare concepts and expected workflows rather than as implementation sources.

The standalone toolkit migrated those existing Python implementations into the `nds_disassembly_toolkit` namespace and generalized game/profile policy at the package boundary.

### Tinke

Tinke helped identify standard Nitro format conventions relevant to the asset inventory. The toolkit's asset implementation performs its own LZ10 handling and signature/extension classification in Python. Game-specific interpretation remains outside the generic classifier.

Format identifiers such as `BMD0`, `BTX0`, `SDAT`, `NARC`, `RGCN`, `RLCN`, `RCSN`, `BCA0`, `BMA0`, `BTP0`, `BTA0`, and `BVA0` are treated as format facts rather than copied implementation expression.

### NitroPacker

NitroPacker informed the high-level idea of compiling external C/assembly into approved Nintendo DS runtime placements. The toolkit independently implements manifest validation, safe source paths, ARMv5TE command construction, linker scripts, symbol parsing, branch encoding, runtime/address validation, exact-byte/hash guards, BLZ storage validation, stale-write protection, rollback, and deterministic reporting.

No NitroPacker runtime/library code is linked, imported, or redistributed by the toolkit.

### pret/ds_disassembly_tools

Because no explicit license was found, its implementation is treated more restrictively than the GPL references: concepts may guide independent engineering, but source text must not be copied into the toolkit.

The toolkit's overlapping helpers are materially independent. For example, toolkit module-parameter discovery validates aligned candidates, rejects ambiguous matches, parses the complete structure, validates the magic, handles runtime bases, and returns a typed model; labelled-byte rendering validates bounds, guarantees a component-base label, deduplicates/sorts boundaries, and emits deterministic ranges.

The toolkit does not contain the upstream scripts `asmdiff.sh`, `dump_fs.py`, `find_module_params.py`, `get_overlay_load_order.py`, `insert_labels.py`, `merge_nef.py`, `ntruncompbw.c`, or their source text.

## Phase 7 analysis boundaries

### Capstone and static analysis

Capstone is a permissively licensed runtime dependency used only through its public Python API. `analysis/decoder.py` converts Capstone results into toolkit-owned immutable models so Capstone objects do not become the public analysis model.

Phases 7A through 7E independently implement function discovery, CFGs, xrefs/call graphs, component-aware symbol recovery, typed semantics, an intraprocedural abstract-value fixed-point solver, stack/frame recovery, argument evidence, return evidence, and `FunctionSummary` construction.

Capstone remains confined to the decoder boundary. Downstream analysis does not parse human-readable operand strings and does not persist Capstone objects or enums.

### angr

angr is architecture/reference material only. The toolkit does not import or copy angr's function-recovery, CFG, abstract-state, calling-convention, symbolic-execution, persistence, or decompiler implementations.

The current static pipeline uses toolkit-owned deterministic CFG/worklist models and immutable analysis records. Targeted angr integration, if added later, must be separately designed and audited rather than becoming an implicit dependency.

### Phase 7F persistence

Phase 7F persists toolkit-owned analysis models with Python's standard-library `sqlite3`. It adds no third-party runtime dependency and does not import or copy angr persistence code.

The `.ndsre` schema stores normalized toolkit records for component fingerprints, functions, CFGs, typed instruction semantics, strings, generated symbols, xrefs, register/data-flow state, stack/argument/return summaries, warnings, and user annotations. It does **not** embed ROM images, melonDS payloads, executable component bytes, or commercial game assets.

Schema design, canonical JSON codecs, transactional replacement, component freshness, deterministic queries, and annotation persistence are toolkit-owned logic.

### Phase 7G persistent-project CLI

Phase 7G is a toolkit-owned presentation/query layer over the public Phase 7F `AnalysisProject` API. It introduces no third-party runtime dependency and incorporates no external implementation source.

The CLI serializer converts toolkit-owned records into deterministic JSON. Query commands open projects read-only; annotation mutation uses the public project API rather than direct SQL. Phase 7G does not change the persistence schema.

## Phase 7H melonDS runtime boundary

Phases 7H1 and 7H2 integrate with melonDS only through the standard external GDB Remote Serial Protocol interface.

The toolkit independently implements its RSP transport in Python using the standard library. melonDS-specific register ordering and CPU endpoint defaults are confined to `MelonDSSession`. No melonDS source file is imported, translated, copied into toolkit modules, linked into the Python package, or distributed as a runtime dependency.

The repository CI is permitted to clone and build a pinned **external stock melonDS** checkout as an interoperability test target. That GPL build runs as test infrastructure; it is not linked into the MIT toolkit distribution. The headless harness in this repository uses public melonDS APIs to create a deterministic synthetic ARM9 target and contains no commercial ROM data.

Phase 7H2 `.ndstrace` persistence uses Python's standard-library `sqlite3` and is independent of `.ndsre`. No `.ndsre` schema migration is introduced by runtime tracing.

### Stock melonDS watchpoint finding

During the final Phase 7H2 live gate on 2026-09-02, the pinned stock melonDS commit
`906e9ebb27da8c6a715cd7abab4abfe8a8d29427` was found to accept GDB `Z2`, `Z3`, and `Z4` watchpoint packets while not invoking the GDB stub's `CheckWatchpt` hook from CPU execution. Its `GdbCmds.cpp` routes watchpoint insert/remove packets into `AddWatchpt`/`DelWatchpt`, and `GdbStub` contains `CheckWatchpt`, but the stock CPU debugger path checks code breakpoints and stepping without calling that watchpoint hook.

Therefore the stock build cannot provide a genuine runtime watchpoint stop for the live CI harness. The toolkit does **not** patch melonDS, synthesize a fake stop, or weaken trace-format semantics to hide that limitation.

The verification boundary is instead:

- stock-melonDS live CI proves real probe, snapshot, memory, code-breakpoint, step, persisted step trace, real memory mutation, repeated breakpoint/control-advance capture, static correlation, trace differential, and ranking behavior;
- toolkit tests prove RSP watchpoint packet mapping/removal, cleanup on failure, stop normalization, and repeated read/write/access watchpoint orchestration;
- documentation explicitly states that real watchpoint stops depend on debugger/emulator support.

If a future stock melonDS release wires watchpoint checks into execution, it can be added to the live gate without changing the toolkit's public watchpoint or `.ndstrace` model.

## Phase 7I conservative pseudo-C boundary

Phase 7I is independently authored toolkit code over toolkit-owned persisted analysis models. It consumes exact `FunctionCandidate`, CFG, typed instruction semantics, data-flow, stack/ABI summaries, symbols, xrefs, and annotations through the public analysis/project APIs, then derives a conservative decompiler IR, safe control-flow structure, and deterministic pseudo-C presentation.

Capstone remains confined to the existing decoder boundary. Phase 7I does not import Capstone directly, introduce a second decoder, or parse Capstone objects. The decompiler does not import angr, Ghidra, RetDec, or another decompiler implementation, and no source from those projects is copied, translated, vendored, or linked into the toolkit.

The pseudo-C is a read-only derived view. It is not stored in `.ndsre`, does not change schema version 1, and introduces no new runtime dependency. Project annotations and symbols therefore improve subsequent decompilation output immediately without cached source becoming stale.

Phase 7I deliberately preserves uncertainty rather than inventing source semantics: unsupported instructions remain visible, ambiguous overlay targets are not assigned to a guessed component, unproven control flow falls back to labels/gotos, and memory typing is limited to decoder-proven access widths. It does not claim source-level type recovery or recompilable-C equivalence.

## Phase 7J investigation/prioritization boundary

Phase 7J is independently authored toolkit code that combines existing toolkit-owned evidence rather than adding a new decoder, emulator integration, symbolic executor, decompiler, or persistence layer. It reads persisted `.ndsre` functions, CFG instruction semantics, strings, xrefs, symbols, and annotations through the public project API; optional runtime evidence is obtained by delegating to the existing Phase 7H2 `.ndstrace` comparison service; optional pseudo-C context is obtained by delegating to the existing Phase 7I decompiler service.

The investigation engine uses deterministic fixed weights and preserves component-aware `(component, runtime_address, instruction_set)` identity. Typed constants are read from toolkit-owned semantic operands rather than assembly display strings. One-hop call-neighbor evidence is propagated only when a call target has a unique persisted `(runtime address, instruction set)` identity, so overlapping Nintendo DS overlays are not guessed.

Phase 7J is read-only: it adds no `.ndsre` or `.ndstrace` schema migration, persists no rankings or pseudo-C, opens analysis projects read-only, and establishes no melonDS connection. It introduces no new third-party dependency and incorporates no source from angr, Ghidra, RetDec, melonDS, or another reverse-engineering implementation.

## Phase 7K SSA/decompiler refinement boundary

Phase 7K is independently authored toolkit code inserted between the existing Phase 7I source-like lift and its existing structurer/renderer. It adds deterministic SSA construction, dominance/frontier analysis, PHI placement and renaming, def-use indexing, partial value facts, fixed-point simplification, and lowering back to the Phase 7I source-like IR.

The external sources above were used only as architecture/concept references:

- **Ghidra** informed high-level SSA heritage staging, storage-vs-definition identity, conservative alias boundaries, repeated transform architecture, and decompiler type-system organization.
- **Miasm** provided an independent comparison point for graph SSA, PHI handling, and repeated simplification. Its GPL implementation is not copied.
- **RetDec** informed the separation of def-use/reaching-definition, alias-analysis, HLL optimization, and type/composite-type concerns. No RetDec source is incorporated.
- **LLVM ValueTracking** informed the concept of partial known-bit/range/nonzero facts instead of an all-or-nothing constant lattice. LLVM implementation code is not copied or ported.
- **angr** remains a future targeted symbolic-analysis reference and is not used by the Phase 7K runtime path.

Phase 7K adds no new third-party runtime dependency, no second decoder, no Capstone use outside the existing decoder boundary, no `.ndsre` schema migration, no SSA persistence, and no game-specific policy. The public decompiler remains a read-only derived view of persisted toolkit analysis.

## Repository audit observations

- no upstream NDSFactory, Tinke, NitroPacker, ndstool, pret, angr, melonDS, Ghidra, or RetDec source tree is vendored beneath toolkit source;
- Capstone is the only Phase 7 external runtime analysis dependency and remains behind the decoder boundary;
- Phase 7F/7G/7H/7I/7J add toolkit-owned persistence, CLI, RSP, trace, differential, ranking, conservative pseudo-C, and evidence-fusion code without changing that dependency boundary;
- Phase 7H uses an external stock melonDS build only in interoperability CI;
- Phase 7I changes neither `.ndsre` schema nor runtime-analysis behavior and persists no generated pseudo-C;
- Phase 7J changes neither `.ndsre` nor `.ndstrace` schema, persists no investigation ranking, and reuses the existing Phase 7H2 differential and Phase 7I decompiler boundaries;
- the repository contains source, tests, documentation, schemas, and synthetic/headless test harness material, not commercial ROMs or extracted copyrighted game assets;
- Bakugan remains the owner of B6RE-specific evidence, addresses, patches, and gameplay systems.

Text search and manual comparison are useful audit evidence but cannot mathematically prove independent authorship. Future contributors should preserve these boundaries and document any deliberate third-party code incorporation before merging it.

## Contributor checklist

Before adding code based on an external NDS or reverse-engineering project:

1. identify the exact repository and commit/release when available;
2. record the license before reading/copying implementation source for reuse;
3. decide whether the need is a public format fact, behavioral reference, architecture reference, runtime dependency, external-process interoperability, or actual code reuse;
4. prefer independent implementation for format facts/behavior when the upstream license is incompatible with the toolkit's MIT distribution goals;
5. never copy code from a repository with no explicit reuse license;
6. if a direct dependency or licensed code reuse is intentional, preserve required notices/attribution and review whether the toolkit's distribution license must change;
7. add the source and decision to this document;
8. keep commercial ROMs, extracted copyrighted assets, and rebuilt ROM images out of the repository.


## DeSmuME interoperability target

Phase 7H3 tests interoperability with the external DeSmuME emulator from the upstream `TASEmulators/desmume` project. The managed live-gate lineage is pinned to upstream release tag `release_0_9_13`.

DeSmuME is GPL-licensed software and remains an external executable/interoperability target. The MIT-licensed NDS Disassembly Toolkit does not vendor, copy, link, or redistribute DeSmuME implementation source. The toolkit implements its own generic orchestration and shared GDB-RSP client and communicates with the external emulator through documented/process-level interfaces.

No DeSmuME source code is incorporated into this repository. CI may clone/build the pinned upstream release solely to exercise interoperability against a disposable synthetic Nintendo DS target.
