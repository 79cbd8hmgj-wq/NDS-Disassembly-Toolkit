# Phase 7F Persistent Analysis Project Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable, versioned `.ndsre` analysis-project format that persists Phase 7A-7E analysis results, detects stale component analysis, preserves user annotations, and exposes deterministic query APIs without leaking SQLite into the public model.

**Architecture:** Add a focused `analysis/project/` package. `project.json` owns only project-format metadata; `analysis.sqlite` owns normalized/indexed analysis records. `AnalysisProject` is the public facade, `ComponentAnalysisBundle` is the atomic generated-analysis write boundary, and SQLite/manifest/codec helpers remain private implementation details.

**Tech Stack:** Python 3.11+, standard-library `sqlite3`, `json`, `hashlib`, `pathlib`, dataclasses/StrEnum, pytest, Ruff, strict mypy. No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-08-28-phase-7f-analysis-project-design.md`

## Global Constraints

- Project layout is exactly a directory containing `project.json` and `analysis.sqlite` in format version 1.
- `project_format_version = 1`, `schema_version = 1`, and `analysis_model_version = 1`.
- The project stores component metadata/fingerprints only; it never stores ROM or component byte payloads.
- Component identity is explicit and component names are unique; overlapping overlay runtime ranges remain independent.
- Address-owned records retain `(component, runtime_address)` identity; code records retain ARM/Thumb mode where the source model requires it.
- Generated analysis is replaceable current state, not historical snapshots.
- User annotations are stored separately and survive generated-analysis replacement.
- Raw `sqlite3.Connection`, cursors, rows, SQL strings, and SQLite exceptions do not cross the public API boundary.
- Capstone objects are never persisted; only toolkit-owned typed semantic records are serialized.
- No Bakugan/B6RE/game-specific identity or policy enters this package.
- SQLite foreign keys are enabled for every writable connection.
- Use rollback-journal mode, not WAL mode.
- Public collection ordering and canonical JSON encoding are deterministic.
- All production behavior follows RED -> minimal GREEN -> focused tests -> full pytest/Ruff/strict-mypy gate.

## File Structure

Create a new focused package rather than expanding `analysis/model.py` or mixing SQL into existing analyzers:

```text
src/nds_disassembly_toolkit/analysis/project/
├── __init__.py      # public project API re-exports
├── model.py         # AnalysisFreshness, identities, annotations, bundle
├── manifest.py      # project.json parsing/writing/path validation
├── schema.py        # schema v1 DDL, connection configuration, validation
├── codec.py         # canonical JSON + typed nested-model codecs
├── records.py       # functions/strings/symbols/xrefs relational persistence
├── functions.py     # CFG + FunctionDataFlow/FunctionSummary persistence
└── project.py       # AnalysisProject facade, transactions, public queries
```

Modify:

```text
src/nds_disassembly_toolkit/errors.py
src/nds_disassembly_toolkit/analysis/__init__.py
docs/disassembly-and-analysis.md
docs/provenance-and-licenses.md
```

Tests:

```text
tests/unit/test_analysis_project_model.py
tests/unit/test_analysis_project_lifecycle.py
tests/unit/test_analysis_project_components.py
tests/unit/test_analysis_project_records.py
tests/unit/test_analysis_project_cfg.py
tests/unit/test_analysis_project_data_flow.py
tests/unit/test_analysis_project_transactions.py
tests/unit/test_analysis_project_exports.py
```

---

### Task 1: Define the public project models and error boundary

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/project/__init__.py`
- Create: `src/nds_disassembly_toolkit/analysis/project/model.py`
- Modify: `src/nds_disassembly_toolkit/errors.py`
- Test: `tests/unit/test_analysis_project_model.py`

**Interfaces:**
- Consumes: existing `Component`, `FunctionCandidate`, `FunctionControlFlowGraph`, `CrossReference`, `StringRecord`, `SymbolTable`, `FunctionDataFlow` from `nds_disassembly_toolkit.analysis.model`.
- Produces:
  - `AnalysisProjectError(NdsToolkitError)`
  - `AnalysisFreshness(StrEnum)` with `CURRENT`, `STALE`, `MISSING`
  - `AnalysisProjectMetadata(project_format_version: int, schema_version: int, analysis_model_version: int, read_only: bool)`
  - `ComponentAnalysisIdentity(name: str, base_address: int, size: int, sha256: str)`
  - `LocationAnnotation(component: str, address: int, name_override: str | None = None, comment: str | None = None, tags: tuple[str, ...] = (), bookmarked: bool = False)`
  - `ComponentAnalysisBundle(component: Component, functions: tuple[FunctionCandidate, ...] = (), cfgs: tuple[FunctionControlFlowGraph, ...] = (), xrefs: tuple[CrossReference, ...] = (), strings: tuple[StringRecord, ...] = (), symbols: SymbolTable = SymbolTable(()), data_flows: tuple[FunctionDataFlow, ...] = ())`

- [ ] **Step 1: Write the failing model contract**

```python
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.model import Component, SymbolTable
from nds_disassembly_toolkit.analysis.project import (
    AnalysisFreshness,
    ComponentAnalysisBundle,
    ComponentAnalysisIdentity,
    LocationAnnotation,
)


def test_component_identity_hashes_component_bytes() -> None:
    component = Component("overlay_3", Path("overlay_3.bin"), 0x02200000, b"abc")

    identity = ComponentAnalysisIdentity.from_component(component)

    assert identity.name == "overlay_3"
    assert identity.base_address == 0x02200000
    assert identity.size == 3
    assert identity.sha256 == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_annotation_normalizes_tags_and_rejects_empty_name() -> None:
    annotation = LocationAnnotation(
        component="arm9",
        address=0x02000000,
        tags=("combat", "ai", "combat"),
    )
    assert annotation.tags == ("ai", "combat")
    with pytest.raises(ValueError, match="name override"):
        LocationAnnotation("arm9", 0x02000000, name_override="")


def test_bundle_defaults_are_immutable_and_empty() -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, b"\0\0\0\0")
    bundle = ComponentAnalysisBundle(component=component)
    assert bundle.symbols == SymbolTable(())
    assert bundle.functions == ()
    assert AnalysisFreshness.CURRENT.value == "current"
```

- [ ] **Step 2: Run the focused test to verify RED**

Run:

```bash
python -m pytest tests/unit/test_analysis_project_model.py -v
```

Expected: collection/import failure because `analysis.project` does not exist.

- [ ] **Step 3: Implement the minimal immutable models**

Use `hashlib.sha256(component.data).hexdigest()` in `ComponentAnalysisIdentity.from_component()`. In `LocationAnnotation.__post_init__`, require non-empty component, non-negative address, non-empty non-null `name_override`, and normalize tags with `tuple(sorted(set(tags)))`; reject `""` tags. `ComponentAnalysisBundle.__post_init__` validates every supplied record belongs to `component.name` and every CFG/data-flow function belongs to the same component.

Add to `errors.py`:

```python
class AnalysisProjectError(NdsToolkitError):
    """Raised when a persistent analysis project cannot be used safely."""
```

- [ ] **Step 4: Verify GREEN and static checks for this slice**

Run:

```bash
python -m pytest tests/unit/test_analysis_project_model.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_model.py src/nds_disassembly_toolkit/errors.py
python -m mypy src/nds_disassembly_toolkit
```

Expected: all commands succeed.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project src/nds_disassembly_toolkit/errors.py tests/unit/test_analysis_project_model.py
git commit -m "feat: define analysis project models"
```

---

### Task 2: Implement manifest/schema lifecycle and read-only opening

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/project/manifest.py`
- Create: `src/nds_disassembly_toolkit/analysis/project/schema.py`
- Create: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Test: `tests/unit/test_analysis_project_lifecycle.py`

**Interfaces:**
- Consumes: Task 1 models/error.
- Produces:
  - `AnalysisProject.create(path: Path) -> AnalysisProject`
  - `AnalysisProject.open(path: Path, *, read_only: bool = False) -> AnalysisProject`
  - context-manager support and `close()`
  - `metadata: AnalysisProjectMetadata`
  - private `_connect(database_path: Path, *, read_only: bool) -> sqlite3.Connection`
  - private `create_schema(connection)` / `validate_schema(connection)`

- [ ] **Step 1: Write failing lifecycle tests**

Cover exact v1 manifest contents, schema metadata, foreign-key enablement, context-manager close, malformed JSON, unsupported project version, absolute/traversing database paths, missing schema metadata, unsupported schema version, and read-only write rejection.

Core contract:

```python
def test_create_and_reopen_project(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        assert project.metadata.project_format_version == 1
        assert project.metadata.schema_version == 1
        assert project.metadata.analysis_model_version == 1
        assert not project.metadata.read_only

    manifest = json.loads((root / "project.json").read_text())
    assert manifest == {
        "format": "nds-disassembly-toolkit-analysis-project",
        "project_format_version": 1,
        "database": "analysis.sqlite",
    }

    with AnalysisProject.open(root, read_only=True) as project:
        assert project.metadata.read_only
```

For read-only mutation, call a temporary internal guard exposed only through the public annotation write added in Task 3; until Task 3 exists, assert the connection URI is opened with `mode=ro` by removing write permission from the fixture database and confirming `open(read_only=True)` still succeeds.

- [ ] **Step 2: Run lifecycle tests and verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_lifecycle.py -v
```

Expected: failures because lifecycle/schema methods are absent.

- [ ] **Step 3: Implement manifest helpers**

`manifest.py` constants:

```python
PROJECT_FORMAT = "nds-disassembly-toolkit-analysis-project"
PROJECT_FORMAT_VERSION = 1
DEFAULT_DATABASE_NAME = "analysis.sqlite"
```

Write manifest atomically via sibling temporary file + `Path.replace()`. Resolve the database path with `Path.resolve()` and reject it unless `database_path.parent == project_root.resolve()`; version 1 allows a filename only, not subdirectories.

- [ ] **Step 4: Implement schema v1 and connection configuration**

`schema.py` must create at least these tables now so schema identity is stable before later tasks add persistence code:

```sql
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE components (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    base_address INTEGER NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    toolkit_version TEXT,
    analyzed_at TEXT
);
CREATE TABLE location_annotations (
    component_id INTEGER NOT NULL,
    address INTEGER NOT NULL,
    name_override TEXT,
    comment TEXT,
    tags_json TEXT NOT NULL,
    bookmarked INTEGER NOT NULL CHECK(bookmarked IN (0, 1)),
    PRIMARY KEY(component_id, address),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);
```

Create the remaining tables from the spec as empty relational tables in this task, with their foreign keys/indexes, so later tasks fill behavior without changing `schema_version`. Store metadata rows:

```text
schema_version = 1
analysis_model_version = 1
```

Every writable connection executes:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = DELETE;
```

Read-only opening uses SQLite URI `file:<quoted-path>?mode=ro` with `uri=True`, validates schema, and does not execute mutating pragmas.

- [ ] **Step 5: Implement `AnalysisProject` lifecycle facade**

Translate expected `sqlite3.Error`, malformed manifest/schema, unsupported versions, and write-mode errors to `AnalysisProjectError`. `close()` is idempotent. `__enter__` returns `self`; `__exit__` closes.

- [ ] **Step 6: Run focused and full static gates**

```bash
python -m pytest tests/unit/test_analysis_project_lifecycle.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_lifecycle.py
python -m mypy src/nds_disassembly_toolkit
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_lifecycle.py
git commit -m "feat: add analysis project lifecycle"
```

---

### Task 3: Persist component identity, freshness, and user annotations

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/schema.py`
- Test: `tests/unit/test_analysis_project_components.py`

**Interfaces:**
- Produces:
  - `component_identities() -> tuple[ComponentAnalysisIdentity, ...]`
  - `component_status(component: Component) -> AnalysisFreshness`
  - `annotation(component: str, address: int) -> LocationAnnotation | None`
  - `annotations(*, component: str | None = None) -> tuple[LocationAnnotation, ...]`
  - `set_annotation(annotation: LocationAnnotation) -> None`

- [ ] **Step 1: Write failing component/freshness tests**

Use two overlays with identical runtime ranges and different names to prove independent identity. Persist one component identity through a small private registration helper invoked by `store_component_analysis(ComponentAnalysisBundle(component=...))`; Task 7 will later expand that method atomically to all generated records.

Required assertions:

```python
assert project.component_status(original) is AnalysisFreshness.CURRENT
assert project.component_status(changed_bytes) is AnalysisFreshness.STALE
assert project.component_status(changed_base) is AnalysisFreshness.STALE
assert project.component_status(changed_size) is AnalysisFreshness.STALE
assert project.component_status(unknown_name) is AnalysisFreshness.MISSING
```

Also assert no component payload appears in SQLite by searching `sqlite_master`/declared columns and by checking the `components` table contains only name/base/size/hash/metadata.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_components.py -v
```

Expected: missing APIs.

- [ ] **Step 3: Implement component upsert and freshness**

`store_component_analysis()` may initially write only component identity inside a transaction. Existing name + different fingerprint replaces the stored identity only when the whole transaction commits. `component_identities()` orders by component name.

- [ ] **Step 4: Implement annotation CRUD subset**

Serialize tags with canonical JSON:

```python
json.dumps(annotation.tags, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
```

`set_annotation()` requires an existing component row, uses UPSERT on `(component_id, address)`, and calls `_require_writable()` first. `annotations()` orders by component name then address. Read-only `set_annotation()` must raise `AnalysisProjectError` before SQL mutation.

- [ ] **Step 5: Verify focused tests + static gates**

```bash
python -m pytest tests/unit/test_analysis_project_components.py tests/unit/test_analysis_project_lifecycle.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_components.py
python -m mypy src/nds_disassembly_toolkit
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_components.py tests/unit/test_analysis_project_lifecycle.py
git commit -m "feat: persist component identity and annotations"
```

---

### Task 4: Persist functions, strings, generated symbols, and xrefs

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/project/codec.py`
- Create: `src/nds_disassembly_toolkit/analysis/project/records.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Test: `tests/unit/test_analysis_project_records.py`

**Interfaces:**
- Produces query methods:
  - `functions(*, component: str | None = None) -> tuple[FunctionCandidate, ...]`
  - `function(component: str, address: int, instruction_set: InstructionSet) -> FunctionCandidate | None`
  - `strings(*, component: str | None = None) -> tuple[StringRecord, ...]`
  - `string_at(component: str, address: int) -> StringRecord | None`
  - `symbols_at(component: str, address: int) -> tuple[Symbol, ...]`
  - `symbols_named(name: str, *, component: str | None = None) -> tuple[Symbol, ...]`
  - `xrefs_from(component: str, address: int) -> tuple[CrossReference, ...]`
  - `xrefs_to(address: int, *, source_component: str | None = None) -> tuple[CrossReference, ...]`
- Private codec helpers:
  - `_dump_str_tuple(values: tuple[str, ...]) -> str`
  - `_load_str_tuple(value: str) -> tuple[str, ...]`

- [ ] **Step 1: Write RED round-trip/query tests**

Build fixtures directly from existing immutable models. Required cases:

1. ARM and Thumb functions at the same component/address remain distinct.
2. function confidence/evidence round-trip exactly.
3. generated symbols at identical numeric address in two overlays remain independent.
4. string address/offset/text round-trip.
5. xrefs preserve source component/function/mode and numeric target without invented target component.
6. insertion order does not affect returned tuple order.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_records.py -v
```

- [ ] **Step 3: Implement canonical simple codecs**

All tuple JSON uses `ensure_ascii=False`, compact separators, stable ordering, and exact type validation on load. Invalid persisted JSON raises `AnalysisProjectError`, not `JSONDecodeError`.

- [ ] **Step 4: Implement relational storage/query helpers in `records.py`**

Use component foreign keys internally, but reconstruct original toolkit models on reads. Do not expose database IDs. Store call xrefs only; do not materialize an independently mutable call-graph table. Required indexes from schema v1 must cover symbol name and xref source/target lookup.

- [ ] **Step 5: Wire `AnalysisProject` methods and bundle writes**

Extend the current `store_component_analysis()` transaction to replace functions/strings/symbols/xrefs for the component. Before replacement, validate every record's `component`/`source_component` equals `bundle.component.name`; xrefs to external numeric addresses remain valid.

- [ ] **Step 6: Verify GREEN**

```bash
python -m pytest tests/unit/test_analysis_project_records.py tests/unit/test_analysis_project_components.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_records.py
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_records.py
git commit -m "feat: persist analysis records"
```

---

### Task 5: Persist CFGs and typed decoded-instruction semantics

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/codec.py`
- Create: `src/nds_disassembly_toolkit/analysis/project/functions.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Test: `tests/unit/test_analysis_project_cfg.py`

**Interfaces:**
- Produces:
  - `cfg(component: str, address: int, instruction_set: InstructionSet) -> FunctionControlFlowGraph | None`
  - private exact round-trip codecs for `InstructionSemantics`, `InstructionOperand`, `MemoryOperand`, `OperandShift`.

- [ ] **Step 1: Write RED CFG round-trip tests**

Create one CFG containing:

- multiple basic blocks;
- branch/fallthrough/call edges;
- unresolved transfer;
- decode failure;
- direct target and target instruction set;
- conditional instruction;
- typed register/immediate/memory/register-list semantics;
- writeback/condition/access width/shift metadata.

Assert `project.cfg(...) == original_cfg` after close/reopen.

Also assert the database contains no Capstone class/module names in serialized semantic JSON.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_cfg.py -v
```

- [ ] **Step 3: Implement typed semantic codecs**

Encode enums by `.value`, register aliases by canonical `Register.value`, bytes as lowercase hex, and optional values explicitly as JSON null. Decoder display `mnemonic` and `operands` remain persisted as presentation fields, but no persistence logic parses those strings.

- [ ] **Step 4: Implement CFG relational storage**

`functions.py` writes basic blocks, instructions, CFG edges, unresolved transfers, and decode failures under a function key `(component, function_address, instruction_set)`. Instruction order within a block is stored explicitly with an ordinal; block query order is address then mode; edge order reconstructs deterministically using source/target/kind keys consistent with existing models.

- [ ] **Step 5: Validate bundle relationships before transaction mutation**

Reject CFGs whose function component differs, whose block component differs, or whose function is not present in `bundle.functions`. Reject inconsistent block offset versus component base. Raise `AnalysisProjectError` before deleting old rows.

- [ ] **Step 6: Verify GREEN and regression tests**

```bash
python -m pytest tests/unit/test_analysis_project_cfg.py tests/unit/test_analysis_cfg.py tests/unit/test_analysis_decoder.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_cfg.py
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_cfg.py
git commit -m "feat: persist analysis control flow"
```

---

### Task 6: Persist data-flow state and FunctionSummary

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/codec.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/functions.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Test: `tests/unit/test_analysis_project_data_flow.py`

**Interfaces:**
- Produces:
  - `data_flow(component: str, address: int, instruction_set: InstructionSet) -> FunctionDataFlow | None`
  - exact codecs for `AbstractValue`, `RegisterState`, `StackState` and deterministic provenance/frame-pointer collections.

- [ ] **Step 1: Write RED data-flow round-trip tests**

Construct a `FunctionDataFlow` fixture containing:

- block entry/exit register states;
- instruction before/after states;
- `CONSTANT`, `ADDRESS`, and unknown values;
- component-owned and unowned addresses;
- deterministic provenance tuples;
- stack offsets and explicit frame-pointer maps;
- warnings;
- `FunctionSummary` with register argument evidence, incoming stack argument evidence, multiple return sites, stack frame, saved-register/local/incoming slots, and load/store accesses.

Assert exact model equality after close/reopen and deterministic ordering regardless of insertion order.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_data_flow.py -v
```

- [ ] **Step 3: Implement abstract/register/stack codecs**

Known `AbstractValue` persists kind/value/component/provenance. Unknown values persist kind only and reconstruct with `value=None`, `component=None`. Register state uses relational rows keyed by function/block-or-instruction/state-side/register so Phase 7G can query register facts without decoding a function-sized blob. Frame-pointer maps and provenance tuples may use canonical JSON because they are deterministic nested facts, not primary query keys.

- [ ] **Step 4: Implement `FunctionDataFlow` relational persistence**

Persist:

```text
block_flow
instruction_flow
register_flow
stack_flow
function_warnings
stack_frames
stack_slots
stack_accesses
argument_evidence
argument_uses
return_evidence
```

Use existing instruction identity from the persisted CFG; do not duplicate instruction bytes/semantics as a second authority. `FunctionSummary` is reconstructed from its persisted rows and attached to the returned `FunctionDataFlow`.

- [ ] **Step 5: Validate function/CFG consistency**

A data-flow record is valid only when its function is present in the bundle and the corresponding CFG is present. Every instruction flow address must match an instruction in that CFG. Reject mismatches with `AnalysisProjectError` before mutation.

- [ ] **Step 6: Verify GREEN and existing 7E regressions**

```bash
python -m pytest \
  tests/unit/test_analysis_project_data_flow.py \
  tests/unit/test_analysis_data_flow.py \
  tests/unit/test_analysis_stack.py \
  tests/unit/test_analysis_function_summary.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_data_flow.py
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_data_flow.py
git commit -m "feat: persist function data flow"
```

---

### Task 7: Make component replacement fully atomic and preserve annotations

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/records.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/functions.py`
- Test: `tests/unit/test_analysis_project_transactions.py`

**Interfaces:**
- Finalizes `store_component_analysis(bundle: ComponentAnalysisBundle) -> None` as the single coherent public generated-analysis replacement boundary.

- [ ] **Step 1: Write RED rollback/replacement tests**

Required tests:

1. store bundle A; inject a deterministic failure halfway through storing bundle B; verify all A generated rows remain and no B rows commit;
2. successful B replacement removes A functions/symbols/xrefs/CFG/data-flow rows absent from B;
3. `LocationAnnotation` rows survive both failed and successful generated replacement;
4. relationship validation failure occurs before destructive deletion;
5. component fingerprint/provenance metadata updates only on successful commit;
6. stale prior analysis remains queryable until successful replacement rather than being partially erased.

Use monkeypatch on one internal insertion helper, for example `_insert_cfgs`, to raise `AnalysisProjectError("injected failure")` after earlier helpers have run inside the same transaction.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_transactions.py -v
```

- [ ] **Step 3: Centralize preflight validation**

Add a pure `_validate_bundle(bundle)` phase before `BEGIN IMMEDIATE`. It validates component names, offsets, ARM/Thumb alignment, function ownership, CFG/function membership, xref source ownership, symbol/string ownership, and flow/CFG instruction consistency. It does not execute SQL.

- [ ] **Step 4: Centralize the transaction**

`store_component_analysis()` must perform exactly one outer transaction:

```python
self._require_writable()
_validate_bundle(bundle)
try:
    self._connection.execute("BEGIN IMMEDIATE")
    component_id = _upsert_component_identity(...)
    _delete_generated_component_rows(...)
    _insert_records(...)
    _insert_cfgs(...)
    _insert_data_flows(...)
    _update_analysis_metadata(...)
    self._connection.commit()
except Exception:
    self._connection.rollback()
    raise
```

Internal helpers never call `commit()` or `rollback()`.

Delete generated children through explicit deletion/order or foreign-key cascades; never delete the component row itself because `location_annotations` must survive replacement.

- [ ] **Step 5: Persist current-analysis provenance**

Record toolkit package version with `importlib.metadata.version("nds-disassembly-toolkit")`, falling back to `None` on `PackageNotFoundError`, and an ISO-8601 UTC success timestamp. Neither affects equality/freshness; freshness remains name/base/size/SHA-256 only.

- [ ] **Step 6: Verify transactional GREEN plus all project tests**

```bash
python -m pytest tests/unit/test_analysis_project_*.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_*.py
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_transactions.py
git commit -m "feat: make analysis replacement atomic"
```

---

### Task 8: Stabilize public exports, documentation, provenance, and final verification

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/__init__.py`
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`
- Test: `tests/unit/test_analysis_project_exports.py`

**Interfaces:**
- Public exports through `nds_disassembly_toolkit.analysis`:
  - `AnalysisProject`
  - `AnalysisProjectMetadata`
  - `AnalysisFreshness`
  - `ComponentAnalysisIdentity`
  - `ComponentAnalysisBundle`
  - `LocationAnnotation`
- `AnalysisProjectError` remains defined in `nds_disassembly_toolkit.errors`; re-export it from `analysis.project` only if consistent with current package export conventions.

- [ ] **Step 1: Write RED export contract**

```python
def test_analysis_project_api_is_exported() -> None:
    from nds_disassembly_toolkit.analysis import (
        AnalysisFreshness,
        AnalysisProject,
        AnalysisProjectMetadata,
        ComponentAnalysisBundle,
        ComponentAnalysisIdentity,
        LocationAnnotation,
    )

    assert AnalysisProject is not None
    assert AnalysisProjectMetadata is not None
    assert AnalysisFreshness.CURRENT.value == "current"
    assert ComponentAnalysisBundle is not None
    assert ComponentAnalysisIdentity is not None
    assert LocationAnnotation is not None
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_exports.py -v
```

Expected: import failure until public re-exports are added.

- [ ] **Step 3: Add stable exports**

Update both `analysis/project/__init__.py` and `analysis/__init__.py` with explicit imports and `__all__` entries. Do not export private schema/codec/record helpers.

- [ ] **Step 4: Document the public workflow**

Add to `docs/disassembly-and-analysis.md`:

```python
with AnalysisProject.create(Path("game.ndsre")) as project:
    project.store_component_analysis(bundle)

with AnalysisProject.open(Path("game.ndsre"), read_only=True) as project:
    status = project.component_status(component)
    function = project.function("arm9", 0x02012340, InstructionSet.ARM)
    flow = project.data_flow("arm9", 0x02012340, InstructionSet.ARM)
```

Document `.ndsre` layout, freshness states, annotation preservation, current-state replacement, read-only behavior, no embedded ROM/component bytes, deterministic/overlay-aware identity, and that 7G—not 7F—owns the interactive query CLI.

- [ ] **Step 5: Update provenance boundary**

Record in `docs/provenance-and-licenses.md` that Phase 7F uses Python's standard-library SQLite API, adds no runtime dependency, persists toolkit-owned Phase 7A-7E models, does not import/copy angr persistence machinery, does not embed melonDS or ROM payloads, and keeps Capstone confined to decoding rather than persistence.

- [ ] **Step 6: Run the complete project verification gate**

Run exactly:

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected:

```text
pytest: 0 failed
Ruff: All checks passed
mypy: Success: no issues found
```

- [ ] **Step 7: Final scope audit**

Run:

```bash
git diff --check main...HEAD
git diff --name-only main...HEAD
```

Confirm the diff contains only the Phase 7F spec/plan, `analysis/project/`, the explicit public/error exports, focused tests, and analysis/provenance documentation. Confirm `pyproject.toml` is unchanged and no Bakugan/B6RE/game-specific file exists in the diff.

- [ ] **Step 8: Commit final API/docs**

```bash
git add \
  src/nds_disassembly_toolkit/analysis/project/__init__.py \
  src/nds_disassembly_toolkit/analysis/__init__.py \
  docs/disassembly-and-analysis.md \
  docs/provenance-and-licenses.md \
  tests/unit/test_analysis_project_exports.py
git commit -m "docs: publish Phase 7F analysis project API"
```

- [ ] **Step 9: PR integration gate**

Open a draft PR from `phase-7f-analysis-project` to `main`, record the exact head SHA, require exact-head pytest/Ruff/strict-mypy CI, audit the full PR diff, then mark ready and squash-merge only after the exact head is green and mergeable. Finally require post-merge `main` CI on the squash commit before declaring Phase 7F complete.

## Completion Criteria

Phase 7F is complete only when all of the following are true:

1. `.ndsre/project.json` + `.ndsre/analysis.sqlite` version-1 projects create/open safely.
2. Read-only opening performs no mutation and rejects writes.
3. Component identity/freshness uses name + base + size + SHA-256 and keeps overlapping overlays independent.
4. ROM/component bytes are never persisted.
5. Functions, CFGs, decoded typed semantics, strings, generated symbols, xrefs, register/stack flow, warnings, and `FunctionSummary` round-trip into equivalent toolkit-owned models.
6. Call relationships remain derived from persisted CALL xrefs rather than a second mutable authority.
7. `ComponentAnalysisBundle` replacement is atomic and removes obsolete generated facts only after successful commit.
8. `LocationAnnotation` survives generated-analysis replacement and remains component/address scoped.
9. Public queries return deterministic ordering independent of insertion order/internal row IDs.
10. Public APIs expose no SQLite implementation objects/exceptions.
11. Schema/project/model versions are all explicit v1 and unsupported versions fail clearly without migration/repair.
12. Full pytest, Ruff, and strict mypy pass on exact PR head and again on post-merge `main`.
