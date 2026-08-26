# Standalone NDS Disassembly Toolkit Architecture

Date: 2026-08-26
Status: Approved architecture, pending implementation plan

## Purpose

`NDS-Disassembly-Toolkit` is the canonical reusable Nintendo DS reverse-engineering toolkit. It separates platform-level ROM inspection, extraction, rebuilding, compression, disassembly, analysis, asset discovery, and patch infrastructure from game-specific projects.

`Bakugan-DS-` becomes a consumer and integration target for the toolkit rather than the repository that owns generic Nintendo DS functionality.

The migration rule is: **reuse proven generic code, refactor only where required to remove Bakugan coupling, and rewrite only when the existing implementation is unsuitable for a reusable toolkit.**

## Goals

1. Preserve as much working code and test coverage as possible from `79cbd8hmgj-wq/Bakugan-DS-`.
2. Establish a game-agnostic Python package and CLI for Nintendo DS reverse engineering.
3. Move generic NDS parsers and infrastructure out of the `bakugan_ds` namespace.
4. Keep Bakugan ROM identity, addresses, gameplay systems, patches, and game-specific analysis in `Bakugan-DS-`.
5. Allow Bakugan and future NDS projects to depend on the toolkit without copying platform code.
6. Preserve deterministic extraction/rebuild behavior and guarded write operations.
7. Preserve or improve existing unit and integration tests during migration.

## Non-goals

- Rewriting working parsers merely to make them look different.
- Moving Bakugan Gate Card, G-Power, balance, or other gameplay-specific systems into the toolkit.
- Shipping ROMs, extracted copyrighted game assets, rebuilt ROMs, or other user-provided copyrighted data.
- Making the toolkit depend on a single commercial game or ROM hash.
- Expanding into unrelated console formats during this migration.

## Repository responsibilities

### `NDS-Disassembly-Toolkit`

Owns reusable platform functionality, including:

- NDS header parsing and validation
- FAT parsing
- FNT parsing
- NitroFS traversal and extraction
- ARM9 and ARM7 extraction
- overlay table parsing and overlay extraction
- LZ10 compression/decompression
- BLZ compression/decompression
- deterministic workspace extraction
- deterministic ROM rebuilding
- generic ROM inspection and reporting
- ARM/Thumb disassembly infrastructure
- generic code/data/string/reference/numeric analysis
- generic asset discovery and extraction primitives
- source patch/apply/compile infrastructure where game-independent
- guarded binary patch primitives
- workspace/manifests and reusable schemas
- shared errors and utilities
- reusable CLI commands
- synthetic fixtures and platform-level tests
- optional integrations/adapters derived from prior work with NDSFactory, Tinke, NitroPacker, ndstool, and DS disassembly tooling when the resulting implementation is legally and technically appropriate

### `Bakugan-DS-`

Retains game-specific functionality, including:

- `B6RE` / `BAKUGAN W` ROM profile and supported-ROM hashes
- Bakugan-specific addresses, signatures, offsets, and runtime discoveries
- Gate Card System 2.0
- G-Power research and gameplay patches
- Bakugan-specific asset definitions and formats when they are not general NDS formats
- Bakugan-specific authoring/configuration files
- Bakugan patches
- Bakugan runtime evidence and analysis reports
- Bakugan-specific integration tests

## Package boundary

The reusable code moves from the game namespace into a toolkit namespace.

Example:

```text
bakugan_ds.nds.header
        -> nds_disassembly_toolkit.nds.header

bakugan_ds.nds.fat
        -> nds_disassembly_toolkit.nds.fat

bakugan_ds.compression.lz10
        -> nds_disassembly_toolkit.compression.lz10
```

Bakugan then imports the toolkit rather than maintaining duplicate implementations.

## Reuse policy

### Move with minimal changes

Code that is already game-agnostic should be copied/migrated with only the changes required for:

- namespace updates
- imports
- package metadata
- CLI naming
- generalized type/config names
- tests and fixtures

Initial high-confidence candidates include the existing NDS FAT/FNT/header/overlay modules, compression modules, generic disassembly helpers, generic analysis helpers, and shared low-level utilities.

### Split mixed modules

A module containing both reusable logic and Bakugan assumptions is divided at the narrowest stable interface.

The toolkit receives the generic parser/engine/model. Bakugan retains the ROM profile, addresses, signatures, game-specific interpretation, and gameplay policy.

### Keep game-specific modules in Bakugan

Anything whose purpose or data model is specific to Bakugan remains in `Bakugan-DS-`. The existing `gates` subsystem is the clearest example.

### Rewrite only when necessary

Reimplementation is justified only when:

- Bakugan assumptions are inseparable from the current implementation,
- the current API cannot support multiple NDS games cleanly,
- correctness problems are discovered,
- licensing/provenance prevents direct reuse, or
- existing code lacks the abstraction needed for safe reuse.

## Proposed toolkit structure

```text
NDS-Disassembly-Toolkit/
├── pyproject.toml
├── README.md
├── src/
│   └── nds_disassembly_toolkit/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── errors.py
│       ├── inspection.py
│       ├── workspace.py
│       ├── rebuild.py
│       ├── patching.py
│       ├── disassembly.py
│       ├── assets.py
│       ├── nds/
│       │   ├── header.py
│       │   ├── fat.py
│       │   ├── fnt.py
│       │   └── overlays.py
│       ├── compression/
│       │   ├── lz10.py
│       │   └── blz.py
│       └── analysis/
│           ├── arm.py
│           ├── model.py
│           ├── numeric.py
│           ├── references.py
│           ├── report.py
│           └── strings.py
├── schemas/
├── tests/
└── docs/
```

Exact filenames may change during migration when the old code shows that two responsibilities should remain together or when a module is demonstrably Bakugan-specific. Such changes must preserve the architecture boundary above.

## Game profile interface

The toolkit must not encode a single supported-ROM hash as global policy. Game repositories provide profiles describing identity and any write-safety requirements.

A reusable profile should be capable of representing at least:

- internal title
- game code
- revision
- expected hashes when a game project requires exact-ROM matching
- optional descriptive metadata

Generic structural inspection may operate without a game profile. Mutating operations used by a game project may require that project's profile/guards.

## CLI direction

The standalone command should use a toolkit-oriented name rather than `bakugan-ds`.

Primary generic command groups should cover:

```text
inspect
extract
rebuild
disassemble
analyze
assets
patch
```

Game-specific commands such as `gate` remain in the Bakugan project.

The migration should favor preserving current command behavior and report formats where they are already generic, minimizing disruption to scripts and tests.

## Data flow

```text
user-owned .nds ROM
      |
      v
NDS toolkit structural parser
      |
      +--> inspection reports
      +--> extracted ARM9 / ARM7
      +--> overlays
      +--> NitroFS
      +--> analysis/disassembly outputs
      |
      v
editable workspace
      |
      +--> generic guarded patches
      +--> game-specific consumer modifications
      |
      v
deterministic rebuild
```

A game project may add knowledge and modifications above the toolkit layer without changing the toolkit's basic understanding of NDS containers.

## Safety and integrity requirements

The existing defensive behavior is preserved where applicable:

- no ROM images committed to the repository
- no extracted copyrighted game assets committed to the repository
- generated workspaces and reports ignored where appropriate
- deterministic extraction/rebuild behavior
- stale/out-of-bounds patch guards fail before writes
- unsupported-game structural inspection is read-only unless a consumer explicitly supplies safe write semantics
- write operations must not silently bypass consumer ROM-profile checks

## Testing strategy

Migration is behavior-preserving first.

For each migrated subsystem:

1. Move or adapt the existing synthetic tests before changing behavior.
2. Confirm the migrated implementation passes those tests under the new namespace.
3. Add focused tests for any new abstraction introduced to remove Bakugan coupling.
4. Keep ROM-dependent tests marked as integration tests and require user-supplied ROM paths.
5. Verify deterministic outputs where the old implementation promises determinism.
6. Compare toolkit output against the existing Bakugan implementation during the transition when practical.

The first milestone is complete only when the standalone generic core passes its own tests independently of the Bakugan package.

## Migration sequence

### Phase 1 — Bootstrap and low-level core

- package metadata and CLI skeleton
- shared errors/utilities
- NDS header/FAT/FNT/overlay modules
- LZ10/BLZ compression
- corresponding tests

### Phase 2 — Workspace and ROM lifecycle

- inspection
- extraction/workspace manifests
- rebuild
- deterministic round-trip tests

### Phase 3 — Reverse-engineering layer

- disassembly
- ARM/Thumb helpers
- strings, references, numeric analysis, reports
- generic asset discovery/extraction

### Phase 4 — Generic patch/source infrastructure

- guarded binary patch primitives
- source patch/apply/compile components that do not rely on Bakugan assumptions
- schemas and tests

### Phase 5 — Bakugan consumer conversion

- add toolkit dependency to `Bakugan-DS-`
- replace duplicated generic imports with toolkit imports
- keep Bakugan-specific profiles and systems local
- run Bakugan test suite against the toolkit-backed implementation
- remove duplicated platform code only after consumer tests pass

### Phase 6 — Consolidation

- audit remaining duplicated generic code
- documentation and migration notes
- CI for standalone toolkit
- compatibility cleanup
- provenance/license audit for third-party-derived integrations

## Compatibility strategy

During the transition, deletion from `Bakugan-DS-` is intentionally delayed. Generic code is first migrated and verified in the standalone toolkit. Bakugan is then switched to consume it. Only after the Bakugan tests pass should duplicate generic implementations be removed.

This avoids turning the repository split into a simultaneous rewrite.

## Third-party source reuse

Prior research and integrations involving NDSFactory, Tinke, NitroPacker, ndstool, DS disassembly tools, and similar projects remain valuable inputs. Reuse must preserve applicable licenses and attribution. When direct copying is not license-compatible or provenance is unclear, the toolkit may reuse documented behavior, format knowledge, test vectors, and architectural lessons while implementing compatible functionality independently.

## Success criteria

The separation is successful when:

1. `NDS-Disassembly-Toolkit` can inspect and structurally extract an arbitrary valid NDS ROM without importing Bakugan code.
2. The toolkit can deterministically rebuild supported workspaces using generic NDS infrastructure.
3. Generic disassembly/analysis functionality operates under the toolkit namespace.
4. Bakugan uses the toolkit for platform operations while retaining its game-specific systems.
5. The Bakugan test suite continues to pass after the dependency switch.
6. No reusable NDS parser needs to remain duplicated in Bakugan solely because of the old repository structure.
7. Existing proven code is retained wherever technically and legally appropriate rather than unnecessarily rewritten.
