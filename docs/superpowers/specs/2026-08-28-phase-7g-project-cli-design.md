# Phase 7G persistent-project CLI design

Date: 2026-08-28
Status: approved for implementation under the standing instruction to continue unless a real blocker is hit
Base: Phase 7F squash commit `b4d4bc9d860cc090b69247243e02138027b44f97`

## Purpose

Phase 7F introduced a versioned `.ndsre` persistent analysis-project format and stable Python read/write APIs. Phase 7G exposes that persistence layer through a deterministic command-line interface suitable for interactive reverse-engineering workflows, shell scripting, editor integration, and later debugger/UI layers.

This phase consumes persisted Phase 7A-7F records. It does not add new disassembly or analysis inference.

## Scope classification

This is an architectural phase because it adds a new top-level CLI subsystem and defines a stable external command/output contract consumed by users and future tooling.

## Chosen architecture

Add a new top-level command family:

```text
nds-toolkit project <subcommand> ...
```

The existing `nds-toolkit analyze` command remains a one-shot flat-component scanner and is not overloaded with persistent-project behavior.

All project query commands open the project with `read_only=True`. Only commands that intentionally mutate user annotations open the project writable. Project creation uses `AnalysisProject.create()`.

Phase 7G uses only public Phase 7F project APIs and toolkit-owned analysis models. CLI code must not import SQLite, schema helpers, record codecs, Capstone objects, or private persistence helpers.

## Why this shape

Three alternatives were considered:

1. **Top-level `project` command family — selected.** Clear separation between one-shot analysis and persistent projects; easy to script; future-compatible with TUI/GUI/debugger layers.
2. Nest project commands beneath `analyze`. Rejected because it conflates transient scanning with project lifecycle/query operations and complicates parser help/error behavior.
3. Build a REPL/TUI immediately. Rejected for Phase 7G because it introduces stateful terminal behavior, pagination/key handling, and presentation concerns not required to expose the persistence API.

## Command contract

### `project create`

```bash
nds-toolkit project create game.ndsre
```

Creates a version-1 `.ndsre` project through `AnalysisProject.create()` and prints a deterministic JSON description of the created project.

It does not import ROM bytes or automatically run analysis.

### `project info`

```bash
nds-toolkit project info game.ndsre
```

Returns:

- project path;
- project-format version;
- schema version;
- analysis-model version;
- read-only state;
- registered component identities sorted by component name.

No component byte payload is read or required.

### `project functions`

```bash
nds-toolkit project functions game.ndsre
nds-toolkit project functions game.ndsre --component arm9
```

Lists persisted `FunctionCandidate` records using the deterministic ordering already guaranteed by `AnalysisProject.functions()`.

### `project function`

```bash
nds-toolkit project function game.ndsre arm9 0x02012340 arm
nds-toolkit project function game.ndsre overlay7 0x02201000 thumb
```

Performs exact lookup by `(component, address, instruction_set)`.

The response contains:

- the function record;
- its CFG when persisted;
- its `FunctionDataFlow` when persisted;
- its `FunctionSummary` through the data-flow record when present;
- the user `LocationAnnotation` at the function entry when present.

A missing exact function is a user-input/query error rather than an empty success response. It must produce a stable toolkit error and nonzero exit status.

### `project strings`

```bash
nds-toolkit project strings game.ndsre
nds-toolkit project strings game.ndsre --component arm9
nds-toolkit project strings game.ndsre --component arm9 --contains battle
```

The project API provides deterministic string ordering. `--contains` is a case-insensitive CLI-side filter over the returned `StringRecord.text`; it does not add a second SQL query API or alter persistence.

### `project symbols`

Exact-name mode:

```bash
nds-toolkit project symbols game.ndsre --name func_02012340
nds-toolkit project symbols game.ndsre --name UpdateThing --component arm9
```

Exact-address mode:

```bash
nds-toolkit project symbols game.ndsre --address 0x02012340 --component arm9
```

`--name` and `--address` are mutually exclusive and one is required. Address lookup requires `--component` because runtime addresses can overlap across Nintendo DS overlays. This intentionally preserves the Phase 7D/7F component-aware identity rule.

Generated symbols remain separate from user annotation name overrides. The command reports generated symbols only; the deep `function` command and annotation commands expose user annotations explicitly.

### `project xrefs-from`

```bash
nds-toolkit project xrefs-from game.ndsre arm9 0x02001234
```

Lists xrefs whose source site is the exact `(component, address)`.

### `project xrefs-to`

```bash
nds-toolkit project xrefs-to game.ndsre 0x02012340
nds-toolkit project xrefs-to game.ndsre 0x02012340 --source-component arm9
```

Lists xrefs targeting a runtime address. Target-component ownership is not invented because Phase 7C/7F deliberately does not infer it from overlapping runtime ranges.

### `project annotations`

```bash
nds-toolkit project annotations game.ndsre
nds-toolkit project annotations game.ndsre --component overlay7
```

Lists durable user annotations in the project API's deterministic order.

### `project annotate`

```bash
nds-toolkit project annotate game.ndsre arm9 0x02012340 \
  --name BattleManager \
  --comment "confirmed from runtime trace" \
  --tag runtime \
  --tag confirmed \
  --bookmark
```

Annotation updates are patch-style rather than destructive replacement.

For an existing annotation:

- omitted fields preserve their current values;
- `--name TEXT` replaces `name_override`;
- `--clear-name` sets `name_override=None`;
- `--comment TEXT` replaces `comment`;
- `--clear-comment` sets `comment=None`;
- one or more `--tag TAG` options replace the complete tag tuple after normal `LocationAnnotation` normalization;
- `--clear-tags` sets tags to an empty tuple;
- `--bookmark` sets bookmark true;
- `--unbookmark` sets bookmark false.

For a new annotation, omitted fields use `LocationAnnotation` defaults.

`--name`/`--clear-name`, `--comment`/`--clear-comment`, `--tag`/`--clear-tags`, and `--bookmark`/`--unbookmark` are mutually exclusive pairs.

The command requires at least one actual field mutation. A no-op invocation is rejected as user input error.

The component must already be registered in the project; `AnalysisProject.set_annotation()` remains the authority for that validation.

## Output contract

### JSON only in Phase 7G

All successful Phase 7G commands emit deterministic JSON followed by a newline. Human-readable table/TUI formatting is deliberately deferred rather than maintaining two presentation contracts now.

All dictionaries are serialized with `sort_keys=True` and indentation for stable review/diff behavior.

### Address representation

Runtime addresses, offsets, sizes that represent memory extents/locations, branch/call targets, stack offsets, and provenance instruction addresses are emitted as canonical hexadecimal strings rather than decimal JSON integers.

Unsigned runtime-like values use at least eight hexadecimal digits:

```text
0x02012340
```

Signed stack offsets use an explicit sign:

```text
-0x0000000c
```

Enumerations use their existing stable `.value` strings.

Ordinary counts and version integers remain JSON integers.

### Output files

Every query/mutation command accepts optional:

```text
--output PATH
```

When omitted, JSON is written to stdout.

When supplied, output is written atomically using the existing toolkit pattern: write a sibling `.tmp` file and replace the destination only after complete serialization.

The output writer is shared inside the Phase 7G CLI module and does not duplicate persistence transactions.

## Serialization boundary

Create a toolkit-owned CLI serializer layer in the project CLI module. It converts public immutable models to JSON-compatible primitive dictionaries/lists.

The serializer covers only types required by Phase 7G:

- `AnalysisProjectMetadata`;
- `ComponentAnalysisIdentity`;
- `FunctionCandidate`;
- `FunctionControlFlowGraph` and nested blocks/edges/unresolved records/instructions/semantics;
- `FunctionDataFlow` and nested abstract/register/stack states;
- `FunctionSummary`, arguments, returns, stack frame/slots/accesses;
- `StringRecord`;
- `Symbol`;
- `CrossReference`;
- `LocationAnnotation`.

It must not import persistence codecs from `analysis.project.codec`, `cfg_records`, or `flow_records`. Those encode database representation; the CLI contract is an independent public presentation boundary.

Capstone objects must never appear in CLI responses.

## Top-level CLI integration

Add a dedicated module:

```text
src/nds_disassembly_toolkit/analysis/project_cli.py
```

It owns:

- parser construction for `project` and its subcommands;
- integer/address parsing;
- instruction-set parsing;
- deterministic model-to-JSON conversion;
- output writing;
- read-only/writable project opening;
- command dispatch.

`src/nds_disassembly_toolkit/cli.py` only imports and registers the new parser/dispatcher, following the existing `assets`, `disasm`, `analyze`, and `source-patch` pattern.

No Phase 7G code is added to `analysis/project/project.py` unless a real missing stable read API is discovered by tests. CLI-side filtering is preferred over expanding persistence APIs for presentation-only needs.

## Error behavior

The existing top-level exit-code policy remains authoritative:

- argument parser errors: argparse standard status 2;
- explicit `ValueError` input/configuration failures caught by top-level CLI: status 2;
- `NdsToolkitError`/`AnalysisProjectError`: status 4;
- `OSError`: status 5.

Phase 7G converts query misses that represent a requested exact entity not existing into `AnalysisProjectError` so callers receive the established toolkit error status rather than ambiguous empty JSON.

Malformed project/schema/version errors continue to originate from Phase 7F and are not rewrapped into SQLite-specific messages.

Read queries always use `AnalysisProject.open(..., read_only=True)`.

## Determinism and overlay safety

The CLI preserves Phase 7F ordering rather than re-sorting with presentation-specific heuristics except where CLI-side filtering removes entries.

Any command that resolves a specific stored entity by runtime address must require component identity whenever the underlying model is component-scoped.

No command may choose a component solely because a runtime address falls in that component's range. Overlapping overlays remain independent.

## Security and filesystem behavior

Phase 7G inherits Phase 7F manifest/database path validation and does not bypass it.

`project create` delegates destination safety to `AnalysisProject.create()`.

Output paths use atomic sibling temporary files. The CLI does not write inside the project except through explicit project creation or annotation persistence.

No arbitrary SQL, expression evaluation, plugin loading, or shell execution is introduced.

## Testing strategy

All production behavior follows RED -> GREEN TDD with exact-head CI.

Required test groups:

### Parser and dispatch

1. top-level parser registers `project`;
2. `project` without a subcommand is a deterministic usage error;
3. address parser accepts decimal and `0x` forms and rejects malformed input;
4. instruction mode accepts only ARM/Thumb values;
5. symbol name/address modes enforce exclusivity and component requirement for address mode;
6. annotation mutually exclusive flags are enforced.

### Lifecycle/info

7. `project create` produces a valid reopenable project and JSON response;
8. `project info` opens read-only and reports versions/components deterministically;
9. malformed/missing projects preserve the Phase 7F error mapping.

### Queries

10. `functions` lists deterministic records and filters by component;
11. exact `function` lookup distinguishes ARM and Thumb identities;
12. `function` includes persisted CFG/data-flow/summary and annotation when present;
13. missing exact function exits with toolkit error rather than returning `null`;
14. `strings --contains` filters case-insensitively while preserving original order;
15. symbol exact-name query can span components;
16. symbol exact-address query requires component and preserves overlapping-overlay independence;
17. `xrefs-from` uses exact source component/address;
18. `xrefs-to` does not invent target component ownership and supports source-component filter;
19. annotation listing is deterministic.

### Annotation mutation

20. new annotation uses defaults for omitted fields;
21. patch update preserves unspecified existing fields;
22. clear-name/comment/tags and unbookmark work independently;
23. repeated `--tag` replaces the complete normalized tag set;
24. no-op mutation is rejected;
25. unknown component remains a Phase 7F `AnalysisProjectError`;
26. annotation survives close/reopen and generated-analysis replacement regression remains green.

### Serialization/output

27. addresses and offsets use canonical hex strings;
28. signed stack offsets use signed canonical hex;
29. enum values are stable strings;
30. output ordering/JSON bytes are deterministic;
31. `--output` writes atomically and leaves no `.tmp` file after success;
32. failed serialization/write does not replace an existing destination when practical to inject/test at the writer boundary;
33. CLI serialized deep function data contains no Capstone/SQLite objects.

### Regression gates

34. existing Phase 1-7F tests remain green;
35. Ruff clean;
36. strict mypy clean;
37. `pyproject.toml` remains unchanged unless a genuine implementation blocker requires a dependency, which would require explicit review before proceeding;
38. diff contains no Bakugan/B6RE/game-specific policy.

## Documentation

Update `docs/disassembly-and-analysis.md` with:

- creation and info examples;
- read-only query commands;
- deep function inspection;
- component-aware symbol/xref behavior;
- annotation patch examples;
- deterministic JSON and `--output` behavior;
- statement that Phase 7G does not add analysis inference or store ROM bytes.

Update `docs/provenance-and-licenses.md` to record that Phase 7G is toolkit-owned CLI/serialization code built only over toolkit-owned Phase 7F public APIs and adds no third-party dependency.

## Explicitly deferred

Phase 7G does not include:

- automatic project population from a ROM/workspace pipeline beyond already-persisted bundles;
- new function/CFG/xref/symbol/data-flow inference;
- fuzzy symbol search beyond the specified string substring filter;
- historical analysis snapshots or undo;
- a REPL, curses TUI, GUI, or web UI;
- emulator/debugger trace integration (Phase 7H);
- pseudo-C/decompiler output (Phase 7I);
- plugin scripting;
- arbitrary SQL access;
- collaborative/multi-user project editing.

## Completion criteria

Phase 7G is complete when:

1. `nds-toolkit project` exposes creation, metadata, function/string/symbol/xref/annotation queries, and annotation mutation;
2. all read commands open projects read-only;
3. exact component/address/mode identity is preserved, including overlapping overlays and ARM/Thumb entries;
4. deep function output reconstructs persisted CFG/data-flow/summary through public Phase 7F APIs only;
5. deterministic JSON serialization contains no SQLite or Capstone implementation objects;
6. annotation updates preserve unspecified fields and support explicit clears;
7. optional output files are written atomically;
8. existing CLI error/exit-code behavior remains consistent;
9. no analysis semantics, project schema, ROM byte storage, or third-party dependencies are added;
10. docs/provenance are updated;
11. exact PR head passes full pytest, Ruff, and strict mypy;
12. the squash commit on `main` passes the same post-merge CI gate before Phase 7G is declared complete.
