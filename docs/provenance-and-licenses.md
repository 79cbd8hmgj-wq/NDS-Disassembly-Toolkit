# Provenance and third-party reference audit

Audit date: 2026-08-27

This document records the provenance boundary for external Nintendo DS and reverse-engineering tools that informed the development of `NDS-Disassembly-Toolkit` and its predecessor work in `Bakugan-DS-`.

The toolkit itself is distributed under the MIT License. See the repository root `LICENSE` file.

## Policy

External repositories listed here are either **reference material** or separately reviewed **direct dependencies**. No external source tree is vendored into this repository.

The migration and capability-development policy is:

1. reuse the project's own proven game-independent Python code when it was already independently implemented;
2. use external tools to understand public Nintendo DS formats, expected behavior, workflow ideas, interoperability constraints, and analysis architecture;
3. do not copy GPL implementation source into the MIT toolkit unless the licensing model is deliberately changed and the required GPL obligations are satisfied;
4. treat source with no explicit license as unavailable for implementation copying;
5. permit direct third-party dependencies only after their license and API boundary are reviewed and documented here;
6. keep third-party implementation types behind toolkit-owned interfaces when practical, so the public toolkit model does not become coupled to a dependency's internal API.

This is an engineering provenance record, not a substitute for legal advice.

## Audited references and dependencies

| Reference | Repository examined | License observed on 2026-08-27 | How it informed this project | Incorporation boundary |
| --- | --- | --- | --- | --- |
| NDSFactory | https://github.com/Luca1991/NDSFactory | GNU GPL v3 (`LICENSE`) | Comparison/reference for NDS extraction and repacking concepts already covered by the project's stricter parser/workspace/rebuild implementation | No NDSFactory source vendored or copied; extraction/repacking implementation was not imported |
| Tinke | https://github.com/pleonex/tinke | GNU GPL v3 (`Licence.txt`) | Standard Nintendo Nitro asset/container conventions and signatures relevant to read-only asset classification | No Tinke source vendored or copied; the toolkit uses a clean-room Python classifier |
| NitroPacker | https://github.com/haroohie-club/NitroPacker | GNU GPL v3 (`LICENSE`) | Architectural reference for an external ARM source-compilation workflow | No NitroPacker source vendored or copied; source compilation/application is independently implemented in Python around user-selected LLVM/binutils-compatible tools |
| ndstool | https://github.com/devkitPro/ndstool | GNU GPL v3 (`COPYING`) | Comparison/reference for conventional NDS extraction/repacking behavior | No ndstool source vendored or copied; the toolkit's parser/rebuilder remains its own implementation |
| pret DS disassembly tools | https://github.com/pret/ds_disassembly_tools | **No explicit license found** in the repository root or README during this audit | Workflow concepts such as finding Nitro module parameters, overlay-layout investigation, labelled binary regions, and disassembly comparison | Implementation source is treated as unavailable for copying; toolkit behavior was reimplemented independently and extended with its own validation/error model |
| Capstone | https://github.com/capstone-engine/capstone | BSD 3-clause-style license (`LICENSES/LICENSE.TXT` in the supplied `capstone-next.zip`) | ARM/Thumb instruction decoding and instruction metadata for Phase 7 program analysis | Reviewed direct runtime dependency (`capstone>=5.0.9,<6`); no Capstone source is vendored; Capstone objects/constants are translated behind toolkit-owned decoder models |
| angr | https://github.com/angr/angr | BSD 2-clause license (`LICENSE` in the supplied `angr-master.zip`) | Architectural reference for CFG/function-recovery, knowledge-base, and later data-flow analysis design | Reference only in Phase 7A; angr is not a toolkit dependency and no angr implementation source is copied |
| melonDS | https://github.com/melonDS-emu/melonDS | GNU GPL v3 (`LICENSE` in the supplied `melonDS-master.zip`) | Nintendo DS runtime/emulator/debugger reference for a future dynamic-analysis integration layer | Reference/external-integration material only; no melonDS implementation source is copied, linked, or vendored into the MIT toolkit |

### ndstool archive-origin caveat

Earlier project work used a supplied archive named `ndstool-master.zip`. That filename alone does not preserve a verifiable remote repository origin in the current source tree. This audit records `devkitPro/ndstool` as the examined upstream repository for the ndstool lineage. If the exact supplied archive is later identified as a different fork or commit, add its repository, commit/hash, and license here rather than assuming equivalence.

### Phase 7 supplied-source caveat

Phase 7A was informed by supplied archives named `capstone-next.zip`, `angr-master.zip`, and `melonDS-master.zip`. Their embedded license files were inspected directly. The filenames do not by themselves establish an immutable upstream commit. Capstone's executable dependency is therefore pinned by package version range in `pyproject.toml`, while the supplied source archives remain reference material rather than vendored source.

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

### Phase 7 program-analysis sources

Capstone is different from the earlier reference-only sources: it is intentionally used as a direct decoder dependency. The toolkit isolates it behind `CapstoneArmDecoder` and toolkit-owned `ExecutionMode`, `ControlFlowKind`, and `DecodedInstruction` models. This keeps Capstone's untyped Python constants and objects from leaking through the public analysis API.

The initial recursive function-discovery engine is toolkit-owned Python code. It uses decoded control-flow facts to distinguish direct calls from ordinary branches, propagate ARM/Thumb mode on direct BLX targets, merge confidence/evidence, and report unresolved indirect transfers.

angr informed the architectural separation between decoding, function discovery, and later graph/data-flow knowledge, but its implementation is not imported or copied. melonDS is reserved for behavioral reference and a possible future external debugger/emulator bridge; its GPL implementation remains outside the MIT toolkit.

## Repository audit observations

During Phase 6 consolidation and Phase 7A development:

- no source-tree references to `NDSFactory`, `Tinke`, or `NitroPacker` were found under `src/nds_disassembly_toolkit`;
- no upstream source tree is vendored beneath the toolkit repository;
- Capstone is the only Phase 7 source promoted to a direct dependency, and its public boundary is adapter-based;
- angr and melonDS remain reference-only sources;
- the repository contains only the toolkit's Python source, tests, documentation, and CI/configuration files;
- historical design documents explicitly state that the supplied upstream archives were reference material only and that GPL/upstream implementation source was not vendored or copied;
- Bakugan remains the owner of B6RE-specific evidence, addresses, patches, and gameplay systems rather than transferring game-specific material into the toolkit.

Text search and manual comparison are useful audit evidence but cannot mathematically prove independent authorship. Future contributors should preserve the boundary above and document any deliberate third-party code incorporation before merging it.

## Contributor checklist

Before adding code based on an external NDS or reverse-engineering project:

1. identify the exact repository and commit/release when available;
2. record the license before reading/copying implementation source for reuse;
3. decide whether the need is a public format fact, behavioral/architectural reference, direct dependency, or actual code reuse;
4. prefer independent implementation for format facts/behavior when the upstream license is incompatible with the toolkit's MIT distribution goals;
5. never copy code from a repository with no explicit reuse license;
6. if a direct dependency is intentional, keep its API boundary narrow and record its version/license here;
7. if direct licensed code reuse is intentional, preserve notices/attribution and review whether the toolkit's distribution license must change;
8. add the source and decision to this document;
9. keep commercial ROMs, extracted copyrighted assets, and rebuilt ROM images out of the repository.
