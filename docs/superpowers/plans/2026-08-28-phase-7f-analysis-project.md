# Phase 7F Persistent Analysis Project Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable, versioned `.ndsre` analysis-project format that persists Phase 7A-7E analysis results, detects stale component analysis, preserves user annotations, and exposes deterministic queries without leaking SQLite into the public API.

**Architecture:** Add a focused `nds_disassembly_toolkit.analysis.project` package. `project.json` owns directory-format metadata; `analysis.sqlite` owns normalized current analysis. `AnalysisProject` is the facade, `ComponentAnalysisBundle` is the atomic generated-analysis write boundary, and SQLite/manifest/codec helpers remain private.

**Tech Stack:** Python 3.11+, standard-library `sqlite3`, `json`, `hashlib`, `pathlib`, `importlib.metadata`, dataclasses/StrEnum, pytest, Ruff, strict mypy. No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-08-28-phase-7f-analysis-project-design.md`

## Global Constraints

- Project layout is exactly `project.json` plus `analysis.sqlite` inside a `.ndsre` directory.
- `project_format_version = 1`, `schema_version = 1`, `analysis_model_version = 1`.
- Never persist ROM/component byte payloads; persist component name/base/size/SHA-256 only.
- Overlapping overlay addresses stay independent because component identity is explicit.
- Generated analysis is current replaceable state, not history.
- User annotations are separate and survive generated-analysis replacement.
- Do not persist Capstone objects or parse display operand text.
- Do not add Bakugan/B6RE/game-specific policy.
- Public APIs expose no `sqlite3.Connection`, cursor, row, SQL text, or raw SQLite exception.
- Writable connections use foreign keys and rollback-journal mode, not WAL.
- Public query ordering and JSON serialization are deterministic.
- Each production slice follows RED -> minimal GREEN -> focused gate -> commit.

## File Structure

```text
src/nds_disassembly_toolkit/analysis/project/
├── __init__.py      # public re-exports
├── model.py         # project-owned immutable models
├── manifest.py      # project.json create/load/path validation
├── schema.py        # schema v1 DDL/configuration/validation
├── codec.py         # deterministic typed nested-model codecs
├── records.py       # functions/strings/symbols/xrefs persistence
├── functions.py     # CFG/data-flow/summary persistence
└── project.py       # AnalysisProject facade + transaction orchestration
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

### Task 1: Public models and project error

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/project/__init__.py`
- Create: `src/nds_disassembly_toolkit/analysis/project/model.py`
- Modify: `src/nds_disassembly_toolkit/errors.py`
- Test: `tests/unit/test_analysis_project_model.py`

**Interfaces:**
- `AnalysisProjectError(NdsToolkitError)`
- `AnalysisFreshness`: `CURRENT`, `STALE`, `MISSING`
- `AnalysisProjectMetadata(project_format_version: int, schema_version: int, analysis_model_version: int, read_only: bool)`
- `ComponentAnalysisIdentity(name: str, base_address: int, size: int, sha256: str)` with `from_component(component: Component)`
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


def test_component_identity_hashes_bytes() -> None:
    component = Component("overlay_3", Path("overlay_3.bin"), 0x02200000, b"abc")
    identity = ComponentAnalysisIdentity.from_component(component)
    assert identity.name == "overlay_3"
    assert identity.base_address == 0x02200000
    assert identity.size == 3
    assert identity.sha256 == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_annotation_normalizes_tags() -> None:
    annotation = LocationAnnotation(
        "arm9", 0x02000000, tags=("combat", "ai", "combat")
    )
    assert annotation.tags == ("ai", "combat")
    with pytest.raises(ValueError, match="name override"):
        LocationAnnotation("arm9", 0x02000000, name_override="")


def test_bundle_defaults_are_empty() -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, b"\0\0\0\0")
    bundle = ComponentAnalysisBundle(component)
    assert bundle.functions == ()
    assert bundle.symbols == SymbolTable(())
    assert AnalysisFreshness.CURRENT.value == "current"
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_model.py -v
```

Expected: import failure because `analysis.project` does not exist.

- [ ] **Step 3: Implement minimal models**

`ComponentAnalysisIdentity.from_component()` uses `sha256(component.data).hexdigest()`. Validate non-empty component names, non-negative addresses/base/size, and 64 lowercase hexadecimal digest characters. Normalize annotation tags with `tuple(sorted(set(tags)))`; reject empty tags and empty non-null `name_override`. `ComponentAnalysisBundle.__post_init__` validates top-level component ownership only; deeper CFG/flow relationship validation belongs to Task 7.

Add:

```python
class AnalysisProjectError(NdsToolkitError):
    """Raised when a persistent analysis project cannot be used safely."""
```

- [ ] **Step 4: Verify GREEN**

```bash
python -m pytest tests/unit/test_analysis_project_model.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_model.py src/nds_disassembly_toolkit/errors.py
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project src/nds_disassembly_toolkit/errors.py tests/unit/test_analysis_project_model.py
git commit -m "feat: define analysis project models"
```

---

### Task 2: Manifest, core schema, create/open/read-only lifecycle

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/project/manifest.py`
- Create: `src/nds_disassembly_toolkit/analysis/project/schema.py`
- Create: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Test: `tests/unit/test_analysis_project_lifecycle.py`

**Interfaces:**
- `AnalysisProject.create(path: Path) -> AnalysisProject`
- `AnalysisProject.open(path: Path, *, read_only: bool = False) -> AnalysisProject`
- `AnalysisProject.metadata -> AnalysisProjectMetadata`
- context manager + idempotent `close()`

- [ ] **Step 1: Write failing lifecycle tests**

```python
def test_create_and_reopen_project(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root) as project:
        assert project.metadata == AnalysisProjectMetadata(1, 1, 1, False)

    assert json.loads((root / "project.json").read_text()) == {
        "format": "nds-disassembly-toolkit-analysis-project",
        "project_format_version": 1,
        "database": "analysis.sqlite",
    }
    assert (root / "analysis.sqlite").is_file()

    with AnalysisProject.open(root, read_only=True) as project:
        assert project.metadata.read_only
```

Add explicit tests named:

```text
test_create_rejects_existing_nonempty_directory
test_open_rejects_malformed_manifest_json
test_open_rejects_future_project_version
test_open_rejects_absolute_database_path
test_open_rejects_traversing_database_path
test_open_rejects_missing_schema_metadata
test_open_rejects_future_schema_version
test_read_only_open_does_not_create_missing_database
```

Each asserts `AnalysisProjectError` with a stable phrase naming the failed contract.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_lifecycle.py -v
```

- [ ] **Step 3: Implement `project.json` helpers**

Constants:

```python
PROJECT_FORMAT = "nds-disassembly-toolkit-analysis-project"
PROJECT_FORMAT_VERSION = 1
DEFAULT_DATABASE_NAME = "analysis.sqlite"
```

Write the manifest through `project.json.tmp` then `replace()`. Version 1 accepts only a filename for `database`; reject `/absolute`, `../escape`, and nested paths.

- [ ] **Step 4: Implement the initial schema v1**

At this point schema v1 contains exactly the tables required by Tasks 2-3; later tasks extend the unreleased v1 schema and `REQUIRED_TABLES` without incrementing the version.

```sql
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE components (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    base_address INTEGER NOT NULL CHECK(base_address >= 0),
    size INTEGER NOT NULL CHECK(size >= 0),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    toolkit_version TEXT,
    analyzed_at TEXT
);

CREATE TABLE location_annotations (
    component_id INTEGER NOT NULL,
    address INTEGER NOT NULL CHECK(address >= 0),
    name_override TEXT,
    comment TEXT,
    tags_json TEXT NOT NULL,
    bookmarked INTEGER NOT NULL CHECK(bookmarked IN (0, 1)),
    PRIMARY KEY(component_id, address),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);
```

Insert metadata rows `schema_version=1` and `analysis_model_version=1`. Writable connections run `PRAGMA foreign_keys=ON` and `PRAGMA journal_mode=DELETE`. Read-only uses SQLite URI `mode=ro` and never executes mutating schema setup.

- [ ] **Step 5: Implement `AnalysisProject` lifecycle**

Translate expected manifest/schema/SQLite failures into `AnalysisProjectError`. `open()` validates required tables and both version rows before returning. `close()` is safe twice.

- [ ] **Step 6: Verify GREEN**

```bash
python -m pytest tests/unit/test_analysis_project_lifecycle.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_lifecycle.py
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_lifecycle.py
git commit -m "feat: add analysis project lifecycle"
```

---

### Task 3: Component freshness and durable annotations

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Test: `tests/unit/test_analysis_project_components.py`

**Interfaces:**
- `component_identities() -> tuple[ComponentAnalysisIdentity, ...]`
- `component_status(component: Component) -> AnalysisFreshness`
- `annotation(component: str, address: int) -> LocationAnnotation | None`
- `annotations(*, component: str | None = None) -> tuple[LocationAnnotation, ...]`
- `set_annotation(annotation: LocationAnnotation) -> None`
- initial `store_component_analysis(bundle: ComponentAnalysisBundle) -> None` stores only component identity; later tasks extend the same transaction.

- [ ] **Step 1: Write RED tests**

```python
def test_component_freshness_uses_name_base_size_and_hash(tmp_path: Path) -> None:
    original = Component("arm9", Path("arm9.bin"), 0x02000000, b"abcd")
    changed = Component("arm9", Path("arm9.bin"), 0x02000000, b"abce")
    missing = Component("arm7", Path("arm7.bin"), 0x03800000, b"abcd")

    with AnalysisProject.create(tmp_path / "p.ndsre") as project:
        project.store_component_analysis(ComponentAnalysisBundle(original))
        assert project.component_status(original) is AnalysisFreshness.CURRENT
        assert project.component_status(changed) is AnalysisFreshness.STALE
        assert project.component_status(missing) is AnalysisFreshness.MISSING
```

Add tests proving changed base and changed size are `STALE`, two overlay names at `0x02200000` remain separate, annotations persist after close/reopen, annotation order is component then address, and `set_annotation()` on read-only raises `AnalysisProjectError`.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_components.py -v
```

- [ ] **Step 3: Implement freshness and component identity queries**

Freshness compares only component name + base + size + SHA-256. `component_identities()` orders by name. Component data is never inserted into SQLite.

- [ ] **Step 4: Implement annotation storage**

Canonical tag JSON:

```python
json.dumps(annotation.tags, ensure_ascii=False, separators=(",", ":"))
```

Use UPSERT on `(component_id,address)`. Require the component already exists. Queries reconstruct `LocationAnnotation` and order deterministically.

- [ ] **Step 5: Verify GREEN**

```bash
python -m pytest tests/unit/test_analysis_project_components.py tests/unit/test_analysis_project_lifecycle.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_components.py
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 6: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_components.py
git commit -m "feat: persist component identity and annotations"
```

---

### Task 4: Functions, strings, symbols, and xrefs

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/project/codec.py`
- Create: `src/nds_disassembly_toolkit/analysis/project/records.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/schema.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Test: `tests/unit/test_analysis_project_records.py`

**Interfaces:**
- `functions(*, component: str | None = None) -> tuple[FunctionCandidate, ...]`
- `function(component: str, address: int, instruction_set: InstructionSet) -> FunctionCandidate | None`
- `strings(*, component: str | None = None) -> tuple[StringRecord, ...]`
- `string_at(component: str, address: int) -> StringRecord | None`
- `symbols_at(component: str, address: int) -> tuple[Symbol, ...]`
- `symbols_named(name: str, *, component: str | None = None) -> tuple[Symbol, ...]`
- `xrefs_from(component: str, address: int) -> tuple[CrossReference, ...]`
- `xrefs_to(address: int, *, source_component: str | None = None) -> tuple[CrossReference, ...]`

- [ ] **Step 1: Add RED round-trip/query tests**

Tests must construct existing immutable models directly and assert exact equality after close/reopen. Include ARM and Thumb functions at one address, same-address symbols in two overlays, source-component-scoped xrefs, and insertion-order independence.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_records.py -v
```

- [ ] **Step 3: Extend schema v1 with exact record tables**

```sql
CREATE TABLE functions (
    component_id INTEGER NOT NULL,
    address INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    instruction_set TEXT NOT NULL,
    confidence TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY(component_id,address,instruction_set),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE TABLE strings (
    component_id INTEGER NOT NULL,
    address INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY(component_id,address),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE TABLE generated_symbols (
    component_id INTEGER NOT NULL,
    address INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    instruction_set TEXT,
    confidence TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY(component_id,address,name),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE TABLE xrefs (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    source_component_id INTEGER NOT NULL,
    source_address INTEGER NOT NULL,
    source_function_address INTEGER,
    source_instruction_set TEXT,
    target_address INTEGER NOT NULL,
    target_instruction_set TEXT,
    FOREIGN KEY(source_component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE INDEX idx_symbol_name ON generated_symbols(name);
CREATE INDEX idx_xref_source ON xrefs(source_component_id,source_address);
CREATE INDEX idx_xref_target ON xrefs(target_address);
```

Add these names to `REQUIRED_TABLES`.

- [ ] **Step 4: Implement canonical tuple codecs and record helpers**

`codec.py` serializes string/int tuples as compact JSON and validates decoded element types. Invalid persisted JSON raises `AnalysisProjectError`. `records.py` converts only between SQL rows and existing toolkit models; internal row IDs never escape.

- [ ] **Step 5: Extend component bundle storage**

Inside the existing component transaction, replace function/string/symbol/xref rows for that component and then insert the bundle's current rows. Do not create a call-graph table; call relationships remain derivable from `CALL` xrefs.

- [ ] **Step 6: Verify GREEN**

```bash
python -m pytest tests/unit/test_analysis_project_records.py tests/unit/test_analysis_project_components.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_records.py
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project tests/unit/test_analysis_project_records.py
git commit -m "feat: persist core analysis records"
```

---

### Task 5: CFG and typed instruction semantics

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/project/functions.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/codec.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/schema.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Test: `tests/unit/test_analysis_project_cfg.py`

**Interfaces:**
- `cfg(component: str, address: int, instruction_set: InstructionSet) -> FunctionControlFlowGraph | None`

- [ ] **Step 1: Write RED CFG round-trip test**

Build one CFG containing multiple blocks, branch/fallthrough/call edges, unresolved transfer, decode failure, conditional instruction, direct target/mode, and typed register/immediate/memory/register-list operands. Assert returned CFG equals original after reopen.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_cfg.py -v
```

- [ ] **Step 3: Extend schema v1 with CFG tables**

```sql
CREATE TABLE basic_blocks (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    address INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    instruction_set TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    PRIMARY KEY(component_id,function_address,function_instruction_set,address,instruction_set),
    FOREIGN KEY(component_id,function_address,function_instruction_set)
      REFERENCES functions(component_id,address,instruction_set) ON DELETE CASCADE
);

CREATE TABLE instructions (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    block_address INTEGER NOT NULL,
    block_instruction_set TEXT NOT NULL,
    address INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    size INTEGER NOT NULL,
    data_hex TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    operands TEXT NOT NULL,
    instruction_set TEXT NOT NULL,
    control_flow TEXT NOT NULL,
    direct_target INTEGER,
    target_instruction_set TEXT,
    conditional INTEGER NOT NULL,
    semantics_json TEXT NOT NULL,
    PRIMARY KEY(component_id,function_address,function_instruction_set,address),
    FOREIGN KEY(component_id,function_address,function_instruction_set,block_address,block_instruction_set)
      REFERENCES basic_blocks(component_id,function_address,function_instruction_set,address,instruction_set) ON DELETE CASCADE
);

CREATE TABLE cfg_edges (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    source_address INTEGER NOT NULL,
    source_instruction_address INTEGER NOT NULL,
    target_address INTEGER NOT NULL,
    target_instruction_set TEXT NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY(component_id,function_address,function_instruction_set,source_instruction_address,target_address,target_instruction_set,kind),
    FOREIGN KEY(component_id,function_address,function_instruction_set)
      REFERENCES functions(component_id,address,instruction_set) ON DELETE CASCADE
);

CREATE TABLE unresolved_transfers (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    source_address INTEGER NOT NULL,
    instruction_set TEXT NOT NULL,
    control_flow TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    operands TEXT NOT NULL,
    PRIMARY KEY(component_id,function_address,function_instruction_set,source_address),
    FOREIGN KEY(component_id,function_address,function_instruction_set)
      REFERENCES functions(component_id,address,instruction_set) ON DELETE CASCADE
);

CREATE TABLE decode_failures (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    address INTEGER NOT NULL,
    PRIMARY KEY(component_id,function_address,function_instruction_set,address),
    FOREIGN KEY(component_id,function_address,function_instruction_set)
      REFERENCES functions(component_id,address,instruction_set) ON DELETE CASCADE
);
```

- [ ] **Step 4: Implement typed semantic codecs**

Encode enum/register values by `.value`, bytes as lowercase hex, optional fields as JSON null, operand order exactly, and `InstructionSemantics` fields `operands`, `registers_read`, `registers_written`, `condition`, `writeback`. Never parse `DecodedInstruction.operands` during reconstruction.

- [ ] **Step 5: Implement CFG persistence and validation**

`functions.py` stores blocks/instructions with explicit ordinals and reconstructs existing models. Before SQL mutation reject wrong component, wrong block component, inconsistent block offset, and CFG function not present in bundle functions.

- [ ] **Step 6: Verify GREEN + CFG/decoder regressions**

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

### Task 6: FunctionDataFlow and FunctionSummary persistence

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/functions.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/codec.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/schema.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Test: `tests/unit/test_analysis_project_data_flow.py`

**Interfaces:**
- `data_flow(component: str, address: int, instruction_set: InstructionSet) -> FunctionDataFlow | None`

- [ ] **Step 1: Write RED data-flow round-trip test**

Construct a flow containing block/instruction register states, `CONSTANT` and component-owned/unowned `ADDRESS` values, provenance, stack offsets/frame pointers, warnings, register + stack arguments, multiple returns, stack frame, local/saved/incoming slots, and load/store accesses. Assert exact equality after reopen.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_data_flow.py -v
```

- [ ] **Step 3: Extend schema v1 with exact flow/summary tables**

Use these tables and keys:

```text
block_flow(component_id,function_address,function_instruction_set,block_address,block_instruction_set,stack_entry_json,stack_exit_json)
instruction_flow(component_id,function_address,function_instruction_set,instruction_address,stack_before_json,stack_after_json)
register_flow(component_id,function_address,function_instruction_set,scope_kind,scope_address,scope_side,register,value_kind,value,owner_component,provenance_json)
function_warnings(component_id,function_address,function_instruction_set,ordinal,text)
stack_frames(component_id,function_address,function_instruction_set,frame_size,frame_pointer,stack_depth_known)
stack_slots(component_id,function_address,function_instruction_set,slot_offset,kind)
stack_accesses(component_id,function_address,function_instruction_set,slot_offset,ordinal,instruction_address,kind,width)
argument_evidence(component_id,function_address,function_instruction_set,ordinal,arg_index,kind,register,stack_offset)
argument_uses(component_id,function_address,function_instruction_set,argument_ordinal,ordinal,instruction_address)
return_evidence(component_id,function_address,function_instruction_set,ordinal,return_address,value_kind,value,owner_component,provenance_json)
```

Every table has a foreign key to the function key; `stack_accesses` references its stack slot; `argument_uses` references its argument row. Add indexes on function keys and `register_flow(register)`.

- [ ] **Step 4: Implement exact value/state codecs**

`AbstractValue` persists kind/value/component/provenance. Unknown values reconstruct with no value/component. Register values are relational rows; `StackState.frame_pointers` and provenance tuples use canonical compact JSON.

- [ ] **Step 5: Implement flow/summary storage**

Use persisted CFG instruction identities rather than duplicating instruction semantics. Reconstruct `BlockFlowState`, `InstructionFlowState`, then `FunctionSummary`, then attach summary to `FunctionDataFlow`. Validate every instruction-flow address exists in the corresponding CFG before deletion/insertion.

- [ ] **Step 6: Verify GREEN + Phase 7E regressions**

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

### Task 7: Finalize atomic component replacement

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/records.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project/functions.py`
- Test: `tests/unit/test_analysis_project_transactions.py`

**Interface:**
- Final `store_component_analysis(bundle: ComponentAnalysisBundle) -> None`

- [ ] **Step 1: Write RED rollback tests**

Test exact scenarios:

```text
store A -> inject failure during B -> A remains completely intact
successful B -> obsolete A generated rows disappear
annotation survives failed B
annotation survives successful B
invalid bundle relationship -> rejection before any deletion
component hash/toolkit_version/analyzed_at update only after successful commit
```

Monkeypatch private `_insert_cfgs` to raise `AnalysisProjectError("injected failure")` after core records have been inserted inside the same outer transaction.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_project_transactions.py -v
```

- [ ] **Step 3: Add pure preflight validation**

`_validate_bundle()` performs no SQL and checks component ownership, offsets, ARM/Thumb alignment, function membership, CFG/function membership, xref source ownership, symbol/string ownership, and flow/CFG instruction consistency.

- [ ] **Step 4: Centralize one transaction**

```python
self._require_writable()
_validate_bundle(bundle)
try:
    self._connection.execute("BEGIN IMMEDIATE")
    component_id = _upsert_component_identity(self._connection, bundle.component)
    _delete_generated_component_rows(self._connection, component_id)
    _insert_records(self._connection, component_id, bundle)
    _insert_cfgs(self._connection, component_id, bundle)
    _insert_data_flows(self._connection, component_id, bundle)
    _update_component_analysis_metadata(self._connection, component_id)
    self._connection.commit()
except Exception:
    self._connection.rollback()
    raise
```

No nested helper commits. Do not delete the `components` row because annotations reference it and must survive replacement.

- [ ] **Step 5: Add current-analysis provenance**

Use `importlib.metadata.version("nds-disassembly-toolkit")`, falling back to `None` on `PackageNotFoundError`, plus UTC ISO-8601 `analyzed_at`. Neither participates in freshness/equality.

- [ ] **Step 6: Verify GREEN + all project tests**

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

### Task 8: Public exports, documentation, provenance, final gate

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/__init__.py`
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`
- Test: `tests/unit/test_analysis_project_exports.py`

**Public exports:**
- `AnalysisProject`
- `AnalysisProjectMetadata`
- `AnalysisFreshness`
- `ComponentAnalysisIdentity`
- `ComponentAnalysisBundle`
- `LocationAnnotation`

- [ ] **Step 1: Write RED export test**

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

- [ ] **Step 3: Add exports only for stable API**

Update `analysis/project/__init__.py` and `analysis/__init__.py`; do not export schema/codec/record helpers or SQL objects.

- [ ] **Step 4: Document Phase 7F**

Document `.ndsre` layout, create/open/read-only, freshness, `ComponentAnalysisBundle`, query examples, annotation preservation, no embedded binary bytes, overlay-aware identity, version/error behavior, and that interactive CLI belongs to 7G.

Use this example:

```python
with AnalysisProject.create(Path("game.ndsre")) as project:
    project.store_component_analysis(bundle)

with AnalysisProject.open(Path("game.ndsre"), read_only=True) as project:
    status = project.component_status(component)
    function = project.function("arm9", 0x02012340, InstructionSet.ARM)
    flow = project.data_flow("arm9", 0x02012340, InstructionSet.ARM)
```

- [ ] **Step 5: Update provenance**

Record that Phase 7F uses standard-library SQLite, adds no dependency, persists toolkit-owned Phase 7A-7E models, does not import/copy angr persistence machinery, does not embed melonDS/ROM payloads, and does not move Capstone outside the decoder boundary.

- [ ] **Step 6: Run complete verification**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: zero pytest failures, Ruff clean, strict mypy clean.

- [ ] **Step 7: Run scope audit**

```bash
git diff --check main...HEAD
git diff --name-only main...HEAD
```

Confirm `pyproject.toml` is unchanged and the diff contains no Bakugan/B6RE/game-specific files.

- [ ] **Step 8: Commit final API/docs**

```bash
git add src/nds_disassembly_toolkit/analysis/project/__init__.py src/nds_disassembly_toolkit/analysis/__init__.py docs/disassembly-and-analysis.md docs/provenance-and-licenses.md tests/unit/test_analysis_project_exports.py
git commit -m "docs: publish Phase 7F analysis project API"
```

- [ ] **Step 9: PR and post-merge gate**

Open a draft PR `phase-7f-analysis-project -> main`. Record exact head SHA. Require exact-head pytest/Ruff/strict-mypy, audit the full diff, mark ready only when green/mergeable, squash-merge with expected-head protection, then require post-merge `main` CI on the squash commit before declaring Phase 7F complete.

## Completion Criteria

1. Version-1 `.ndsre` projects create/open safely and read-only open does not mutate.
2. Component freshness is exact and overlapping overlays remain independent.
3. No ROM/component bytes are persisted.
4. Functions, CFGs, typed semantics, strings, symbols, xrefs, data flow, stack state, warnings, and `FunctionSummary` round-trip to equivalent toolkit-owned models.
5. Call relationships remain derived from CALL xrefs, not a second mutable authority.
6. `ComponentAnalysisBundle` replacement is atomic and removes obsolete generated facts only on successful commit.
7. `LocationAnnotation` survives replacement and remains `(component,address)` scoped.
8. Query ordering is deterministic and internal row IDs never become public identity.
9. Raw SQLite implementation details/exceptions do not cross public APIs.
10. Unsupported project/schema versions fail clearly with no implicit migration/repair.
11. Exact PR head and post-merge `main` both pass full pytest, Ruff, and strict mypy.
