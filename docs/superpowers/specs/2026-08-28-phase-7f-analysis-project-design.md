# Phase 7F Persistent Analysis Project Design

## Status

Approved continuation of the Phase 7 analysis roadmap on 2026-08-28.

Phase 7E is complete on `main` at `379f79c6d04cbfa1c7f1e73b89054b31612421b6`. Phase 7F begins from that verified commit.

## Goal

Add a durable, versioned analysis-project format that persists the toolkit-owned analysis models already produced by Phases 7A through 7E. The project must let later phases reopen a Nintendo DS reverse-engineering workspace without recomputing every function, CFG, cross-reference, symbol, and data-flow summary on every invocation.

Phase 7F is a persistence and project-model phase. It does not add new reverse-engineering inference. It serializes the current analysis truth, preserves component identity, detects stale results when analyzed bytes change, and provides deterministic read/write APIs suitable for Phase 7G query tooling.

The core transition is:

```text
ROM/component bytes
        ↓
existing Phase 7A-7E analysis
        ↓
AnalysisProject
        ↓
versioned durable storage
        ↓
reopen / query / refine later
```

The project format must preserve the architecture already established by the toolkit:

- component identity is explicit;
- overlapping overlay runtime ranges never collapse into one identity;
- public records remain toolkit-owned immutable models;
- generated analysis and user-authored annotations are distinct;
- persistence never reparses display strings or re-decodes machine code;
- no Bakugan-specific identity, addresses, policies, or gameplay state enter the generic project model.

## Chosen storage architecture

Use a directory-backed analysis project with a small JSON manifest and one SQLite database:

```text
my-game.ndsre/
├── project.json
└── analysis.sqlite
```

SQLite is the primary persistent store because the later interactive query phase needs indexed relationships across functions, symbols, xrefs, callsites, stack evidence, and addresses. Python's standard-library `sqlite3` module is sufficient; Phase 7F adds no runtime dependency.

A pure JSON bundle was rejected as the primary store because large analysis projects would require repeated full-file loading or a second custom indexing layer. A hybrid SQLite-plus-opaque-blob design was rejected because the current analysis models are small enough to normalize directly and the extra consistency layer is unnecessary.

SQLite is an implementation detail. Public callers interact with toolkit-owned `AnalysisProject` and immutable result models rather than SQL connection objects, table names, row objects, or SQLite-specific exceptions.

## Project manifest

`project.json` identifies the directory as a toolkit analysis project and points to the database file. Version 1 remains intentionally small:

```json
{
  "format": "nds-disassembly-toolkit-analysis-project",
  "project_format_version": 1,
  "database": "analysis.sqlite"
}
```

The manifest does not duplicate analysis records, component bytes, ROM paths, timestamps, or mutable query indexes. Those belong either in the database or outside the project.

The manifest path is always resolved relative to the project directory. Absolute database paths and path traversal are invalid.

The project format version and SQLite schema version are distinct concepts:

- `project_format_version` controls the directory/manifest contract;
- `schema_version` controls the database schema.

Both begin at version 1.

## Project and database lifecycle

The public lifecycle is conceptually:

```python
project = AnalysisProject.create(path)
project = AnalysisProject.open(path)
project.close()
```

Exact constructor/function spellings may be refined in the implementation plan, but the responsibilities are fixed.

### Create

Creation:

1. rejects an existing non-empty destination unless a future explicit replacement mode is introduced;
2. creates the project directory;
3. writes `project.json` atomically;
4. creates `analysis.sqlite` with schema version 1;
5. enables foreign-key enforcement;
6. commits the complete schema before returning a usable project.

If creation fails, it must not leave a project that appears valid but contains a partial schema.

### Open

Opening:

1. validates `project.json` structure and version;
2. resolves the database path safely inside the project directory;
3. opens the database;
4. enables foreign-key enforcement;
5. validates required schema metadata and tables;
6. refuses unsupported newer project or database versions;
7. returns a project object only after structural validation succeeds.

Phase 7F does not perform automatic destructive migrations. Older schema versions may become migratable in future phases through explicit migration functions. Version 1 opening logic only recognizes the current schema and rejects unsupported versions clearly.

Phase 7F includes explicit read-only opening. A read-only project supports all query and freshness APIs but rejects generated-analysis or annotation writes with `AnalysisProjectError`. Opening read-only must not create, migrate, repair, or otherwise mutate project files.

## Current-state model, not historical snapshots

Phase 7F stores the **current generated analysis state** for each component/function. It does not preserve every historical analysis revision.

Re-analysis transactionally replaces generated records that belong to the replaced scope. Old generated records are deleted when the replacement commits successfully. User-authored annotations are stored separately and survive generated-analysis replacement.

The database records the identity of the last successful analysis inputs and toolkit/schema metadata, but this is provenance for the current state rather than an append-only history system.

Historical snapshots, branches of analysis state, undo logs, and collaborative version histories are explicitly deferred.

## Binary ownership and copyright boundary

The persistent project does **not** embed the source ROM, extracted ARM binaries, overlays, NitroFS files, or other component byte payloads.

For each analyzed component, Phase 7F stores only the metadata needed to identify and validate the analyzed bytes:

- component name;
- runtime base address;
- byte length;
- SHA-256 digest.

The caller supplies current `Component` bytes when freshness must be checked or analysis must be recomputed.

This keeps commercial ROM contents and extracted copyrighted payloads outside the project database while still allowing exact stale-analysis detection.

## Persistent identity rules

Nintendo DS overlays may occupy identical runtime addresses at different times. Runtime address alone is therefore never a globally unique identity.

### Component identity

A component has a stable project-local identity keyed primarily by its unique component name. Its persisted analysis identity also includes its runtime base address, size, and SHA-256 fingerprint.

Duplicate component names are invalid.

### Address-owned records

Persistent symbols, strings, annotations, and similar records use:

```text
(component, runtime_address)
```

as their address identity unless the underlying existing model requires additional differentiation.

### Code-mode identity

Functions, basic blocks, and code records where ARM/Thumb mode matters use:

```text
(component, runtime_address, instruction_set)
```

or the equivalent parent-function-scoped key.

`arm9:0x02010000:arm` and `arm9:0x02010000:thumb` must not be silently treated as one record.

### Cross-reference targets

Persistence must not invent a target component for a cross-reference when the existing `CrossReference` model only proves a numeric target address. The database preserves exactly the component ownership that current analysis has established and no more.

This is particularly important for overlapping overlays.

## Component freshness and staleness

Each component row stores:

- unique component name;
- base address;
- size;
- SHA-256 digest;
- last successful generated-analysis metadata.

Given a current `Component`, the project classifies persisted state as:

```text
CURRENT   fingerprint/base/size agree
STALE     known component name but analyzed identity differs
MISSING   no persisted component analysis exists
```

A component with the same name but different bytes must not silently reuse old generated analysis.

A base-address or size change is also stale even if a hash collision were theoretically possible.

Stale detection is deterministic and independent of filesystem timestamps.

## Analysis provenance metadata

The database stores enough provenance to explain which analyzer/schema produced current generated records:

- database schema version;
- `analysis_model_version = 1` for the Phase 7F serialization contract;
- toolkit package version when available;
- component fingerprint/base/size;
- successful-analysis timestamp as informational metadata only.

Timestamps never participate in semantic equality, ordering, generated symbol identity, cache validity, or deterministic query results.

The implementation must not require a Git checkout SHA to function. Installed packages may not have repository metadata available.

## Generated analysis persisted by Phase 7F

Phase 7F persists the models already produced by prior phases. It must not invent a separate semantic representation of those facts.

### Components

Persist `Component` identity metadata but not `Component.data`.

### Functions

Persist `FunctionCandidate` information including:

- component;
- runtime address;
- offset;
- instruction set;
- confidence;
- deterministic evidence.

### Control-flow graphs

Persist function CFG structure:

- basic blocks;
- decoded instructions needed to reconstruct/query existing CFG records;
- CFG edges;
- unresolved transfers;
- decode failures.

Decoded instructions retain their toolkit-owned display and typed semantic fields. Capstone objects are never persisted.

Nested semantic payloads that are not query-critical may be stored as canonical JSON within SQLite, provided round-trip reconstruction is exact and deterministic. Core query keys such as component, address, instruction set, control-flow kind, direct target, and block/function ownership remain indexed columns.

### Cross-references and calls

Persist `CrossReference` records and the information required to derive/query the existing direct-call graph.

The database must not store an independently mutable second copy of the call graph while it remains a deterministic view of call xrefs. The query layer derives call relationships from persisted `CALL` cross-references.

### Strings

Persist `StringRecord` values needed for later address/text queries.

### Symbols

Persist the generated `SymbolTable` facts:

- component;
- address/offset;
- name;
- structural kind;
- instruction set where relevant;
- confidence;
- deterministic evidence.

Generated symbols remain distinct from user-authored name/comment annotations.

### Data flow

Persist `FunctionDataFlow` without changing its public meaning:

- block entry/exit register states;
- instruction before/after register states;
- block/instruction stack states;
- warnings;
- abstract values including kind, exact value, owner component, and provenance;
- attached `FunctionSummary`.

Query-critical register and stack facts are represented as indexed relational rows rather than one opaque function-sized blob. Small nested deterministic collections such as provenance address tuples or frame-pointer maps may use canonical JSON if that keeps the schema simpler without preventing expected Phase 7G queries.

### Function summaries

Persist the existing `FunctionSummary` directly:

- argument evidence;
- argument-use sites;
- return evidence and `r0` abstract values;
- stack-frame facts;
- stack slots;
- slot accesses.

Phase 7F must not create a competing signature/ABI model.

## Proposed relational shape

Exact SQL names are implementation details, but schema version 1 has tables conceptually equivalent to:

```text
metadata
components
analysis_metadata
functions
basic_blocks
instructions
cfg_edges
unresolved_transfers
decode_failures
xrefs
strings
generated_symbols
register_flow
stack_flow
function_warnings
function_summaries
argument_evidence
argument_uses
return_evidence
stack_frames
stack_slots
stack_accesses
location_annotations
```

`analysis_metadata` represents only current successful analysis provenance. It is not an append-only analysis-run history.

Foreign keys connect generated records to their component/function owners. Deleting/replacing one generated function analysis must not orphan dependent rows.

Indexes support the likely 7G access paths from the start:

- component + address;
- component + address + instruction set;
- symbol name;
- xref source address;
- xref target address;
- caller/function address;
- string text/address where practical;
- stack slot/function;
- argument/return function.

The schema must not be over-normalized merely to eliminate tiny JSON fields that are never independently queried.

## Public project API

The stable Python API exposes toolkit-owned project/query models and hides SQL details.

Conceptually:

```python
with AnalysisProject.open(path) as project:
    status = project.component_status(component)
    project.store_component_analysis(...)
    function = project.function(
        component="arm9",
        address=0x02012340,
        instruction_set=InstructionSet.ARM,
    )
    symbols = project.symbols_at(
        component="overlay_3",
        address=0x02200000,
    )
```

The implementation plan may split storage methods by model when that makes testing clearer, but the external architecture favors transactionally coherent operations rather than forcing consumers to manually coordinate a dozen table writes.

Expected public concepts are:

- `AnalysisProject`;
- `AnalysisProjectMetadata`;
- `ComponentAnalysisIdentity` or equivalent fingerprint model;
- `AnalysisFreshness` (`CURRENT`, `STALE`, `MISSING`);
- `LocationAnnotation`;
- `AnalysisProjectError`.

Raw `sqlite3.Connection`, `sqlite3.Row`, SQL strings, cursor objects, and table-specific persistence classes are private implementation details.

## Transaction model

Generated analysis replacement must be atomic.

A conceptual component/function replacement transaction is:

```text
BEGIN
  validate project/schema
  validate component identity
  validate incoming model relationships
  delete/replace generated records for the requested scope
  insert new generated records
  validate relational invariants
  update successful-analysis metadata
COMMIT
```

On any failure:

```text
ROLLBACK
```

The project must never expose a committed state containing a new CFG with stale data-flow rows, new function summaries with old stack slots, or partially replaced xrefs.

Public storage helpers either own their transaction or participate in one clearly documented higher-level transaction. Nested helpers must not accidentally commit partial work.

SQLite foreign-key enforcement is mandatory for every writable connection.

## Generated analysis versus user annotations

Generated analysis is replaceable. User-authored information is durable.

Phase 7F introduces immutable `LocationAnnotation` keyed by component plus runtime address with exactly these user-controlled fields:

```text
component: str
address: int
name_override: str | None
comment: str | None
tags: tuple[str, ...]
bookmarked: bool
```

Empty component names and empty non-null name overrides are invalid. Tags are normalized to a deterministic sorted unique tuple and empty tags are invalid. `comment` may be an empty string because clearing/replacing comment text is a normal edit operation.

Annotations are not merged into or rewritten as generated `Symbol` rows. Query APIs may later present an effective display name that overlays `name_override` on a generated symbol, but storage keeps both sources explicit.

Re-analysis of a component must not delete its annotations merely because generated functions/symbols moved or disappeared. An annotation can therefore become orphaned from current generated analysis while remaining attached to its component/address location. Phase 7G may expose orphaned annotations for review.

Phase 7F does not add collaborative authorship, rich text, source-level types, renaming propagation, or undo history.

## Determinism

Persistence must preserve the deterministic behavior established by the analysis layers.

Required rules:

- deterministic ordering when public APIs return tuples/collections;
- canonical JSON serialization with stable key ordering where JSON is used inside SQLite;
- evidence/provenance tuples normalized before storage;
- no database row ID may become semantic identity exposed to callers;
- timestamps and insertion order do not affect query results;
- round-tripping a model through the database reconstructs an equivalent toolkit-owned model.

SQLite integer primary keys may be used internally for foreign keys, but callers must never depend on their values.

## Validation and errors

Phase 7F adds `AnalysisProjectError(NdsToolkitError)` for expected project-format, schema, freshness/write-mode, validation, and translated SQLite failures. Existing `WorkspaceError` remains specific to extracted/rebuild workspace operations and is not reused for the persistent RE-project subsystem.

Raw SQLite exceptions do not cross the public `AnalysisProject` API boundary for expected operational failures.

Validation rejects at least:

- malformed or unsupported `project.json`;
- project manifest path traversal/absolute database path;
- missing or corrupt schema metadata;
- unsupported future schema/project versions;
- duplicate component names;
- invalid component addresses/sizes/digests;
- model records referencing a different component/function than the transaction scope;
- inconsistent offsets versus component base addresses;
- invalid ARM/Thumb identity where alignment is required;
- impossible foreign-key/model relationships;
- writes through a read-only project.

A stale component is not database corruption. It is a first-class freshness result and only blocks operations that explicitly require current generated analysis.

## Concurrency and file behavior

Phase 7F supports SQLite's normal transactional file safety but does not promise a multi-process collaborative editing model.

The public `AnalysisProject` object is not required to be thread-safe. A single writable project connection is the expected Phase 7F usage pattern.

Phase 7F uses SQLite's normal rollback-journal mode rather than WAL mode so a closed project remains a self-contained two-file directory without persistent WAL/SHM sidecars.

Project copying remains as simple as copying the closed `.ndsre` directory.

## Query surface for Phase 7F

Phase 7F includes enough read APIs to prove persistence is useful and to support Phase 7G without direct SQL access. It does not implement the final interactive command set yet.

Minimum query coverage includes:

- component listing and freshness;
- function lookup/listing by component/address/mode;
- symbols by component/address and by name;
- xrefs to/from an address;
- stored strings by component/address;
- CFG retrieval for a function;
- data-flow/`FunctionSummary` retrieval for a function;
- location annotation get/set/list.

Rich search syntax, CLI formatting, fuzzy search, `who-references`, `what-calls`, `what-writes`, and similar user-facing commands remain Phase 7G work built on these APIs.

## Persistence granularity

The preferred write boundary is a coherent generated-analysis bundle for a component or function, not one row at a time from public callers.

The implementation plan chooses the smallest boundaries that maintain consistency:

- component identity/fingerprint registration;
- component-level generated facts such as strings/symbols/xrefs where appropriate;
- function-level CFG + data flow + summary replacement in one transaction.

If a cross-component/project-wide index is entirely derivable from persisted canonical facts, derive it rather than introducing an independently mutable copy.

## Schema evolution

Schema version 1 is created with explicit metadata.

Opening behavior:

- current supported version: open normally;
- older version: reject with a clear `AnalysisProjectError` stating that migration is required until an explicit migration exists;
- newer version: reject with `AnalysisProjectError` because the current toolkit cannot safely interpret it;
- incomplete/corrupt schema: fail validation rather than attempting automatic repair.

Future migrations must be explicit, transactional, tested against fixture databases, and preserve user annotations.

Phase 7F itself only implements schema version 1 creation/opening and the validation hooks necessary for later migration support.

## Testing strategy

Every production behavior follows the existing TDD workflow: focused failing contract, verify RED, minimal implementation, verify GREEN, then full pytest/Ruff/strict-mypy gates.

Required test groups include:

### Project format

1. create a new `.ndsre` project and reopen it;
2. reject existing/unsafe creation targets;
3. reject malformed manifest JSON;
4. reject unsupported manifest versions;
5. reject absolute/traversing database paths;
6. reject missing/corrupt/unsupported database schema metadata;
7. read-only open performs no mutation and rejects writes.

### Component identity

8. persist component metadata without storing component bytes;
9. classify identical current bytes as `CURRENT`;
10. classify changed hash/base/size as `STALE`;
11. classify unknown components as `MISSING`;
12. preserve independent identities for overlapping overlays.

### Model round trips

13. round-trip functions and confidence/evidence;
14. round-trip CFG blocks/instructions/edges/unresolved transfers/decode failures;
15. round-trip typed instruction semantics without Capstone objects;
16. round-trip strings;
17. round-trip generated symbols including overlapping-overlay addresses;
18. round-trip xrefs without inventing target-component ownership;
19. round-trip abstract values and deterministic provenance;
20. round-trip stack states;
21. round-trip `FunctionDataFlow` and `FunctionSummary` including arguments, returns, frame, slots, and accesses.

### Transactions

22. simulated insertion failure rolls back a generated-analysis replacement;
23. failed replacement leaves prior committed analysis intact;
24. replacing generated analysis removes obsolete generated rows but preserves annotations;
25. foreign-key/model mismatch is rejected before commit.

### Annotations

26. user name/comment/tags/bookmark persist across reopen;
27. annotations survive generated symbol/function replacement;
28. annotations at the same runtime address in two components remain independent;
29. annotation return order is deterministic.

### Queries and determinism

30. function lookup distinguishes ARM/Thumb identities;
31. symbol and xref address queries are indexed/semantically correct;
32. returned collections have deterministic ordering independent of insertion order;
33. persistence round-trip does not change model equality or generated names/evidence ordering.

### Regression gates

34. existing Phase 7A-7E tests remain green;
35. Ruff passes;
36. strict mypy passes;
37. no new runtime dependency appears in project metadata.

## Documentation and provenance

After implementation, update `docs/disassembly-and-analysis.md` with:

- project creation/opening;
- current/stale/missing component semantics;
- persistence/query examples;
- annotation behavior;
- explicit statement that ROM/component bytes are not stored.

Update `docs/provenance-and-licenses.md` to record that Phase 7F is toolkit-owned persistence code using Python's standard-library SQLite API and does not incorporate angr's project/database implementation or melonDS source.

SQLite is provided through the Python standard library and does not require a new package dependency.

## Explicitly deferred

Phase 7F does not include:

- new function/CFG/xref/symbol/data-flow inference;
- historical analysis snapshots or undo history;
- collaborative/multi-user editing;
- a server/database daemon;
- embedding source ROM/component bytes;
- general structure/type inference;
- interprocedural symbolic propagation;
- full interactive query CLI commands (Phase 7G);
- emulator/trace integration (Phase 7H);
- pseudo-C/decompiler output (Phase 7I);
- plugin scripting framework unless separately promoted later.

## Completion criteria

Phase 7F is complete when:

1. a version-1 `.ndsre` project can be created, closed, reopened, and structurally validated;
2. explicit read-only opening supports queries without mutating files and rejects writes;
3. component fingerprints detect current/stale/missing state without storing binary payloads;
4. the canonical Phase 7A-7E generated analysis models can be persisted and reconstructed without semantic loss;
5. generated analysis replacement is transactional and preserves user annotations;
6. component-aware and ARM/Thumb-aware identities survive round trips, including overlapping overlays;
7. stable read APIs cover the data required by Phase 7G without exposing SQL details;
8. project/schema versions are explicit and unsupported versions fail safely;
9. public documentation and provenance are updated;
10. full pytest, Ruff, and strict-mypy gates pass on the exact PR head and post-merge `main`.
