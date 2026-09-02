# Phase 7H2 Runtime Trace and Behavioral Differentials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded persisted runtime tracing, memory before/after evidence, static-project correlation, trace-vs-trace behavioral differentials, and transparent dynamic function ranking on top of the verified Phase 7H1 melonDS GDB bridge.

**Architecture:** Keep Phase 7H1 `RSPClient` and `MelonDSSession` as the only debugger transport/session path. Add immutable trace records in `analysis/runtime/trace_model.py`, independent SQLite `.ndstrace` persistence in `trace_store.py`, capture orchestration in `capture.py`, memory comparison in `memory_diff.py`, and offline inspection/differential/ranking logic in `trace_diff.py`. Extend `AnalysisProject` only with narrowly scoped read-only queries; do not change `.ndsre` schema version 1. The CLI adds online `runtime trace capture` and offline `runtime trace inspect` / `runtime diff` commands.

**Tech Stack:** Python 3.11+, standard-library `sqlite3`/`hashlib`/`json`/`importlib.metadata`, existing immutable analysis/runtime models, existing `MelonDSSession`, argparse, pytest, Ruff, strict mypy, stock melonDS headless GDB smoke harness.

**Spec:** `docs/superpowers/specs/2026-09-02-phase-7h2-runtime-trace-differentials-design.md`

## Global Constraints

- Start implementation from `phase-7h2-trace-differentials`, whose design base is verified `main` commit `61372597461ad119d4787c6ac34356d2f73c39bd`.
- The existing Phase 7H1 `analysis/runtime/rsp.py` remains the only GDB RSP implementation. Do not create another socket/RSP transport.
- `MelonDSSession` remains the only melonDS-specific runtime adapter. Capture orchestration calls its public methods instead of reaching into `_client`.
- No melonDS implementation source is copied, linked, translated, or vendored. Stock melonDS remains an external GPL process/build used only by the CI interoperability harness.
- Do not add a runtime dependency and do not modify dependency declarations in `pyproject.toml`.
- `.ndstrace` uses an independent trace schema version starting at `1`.
- Do not modify `src/nds_disassembly_toolkit/analysis/project/schema.py`, `SCHEMA_VERSION`, `ANALYSIS_MODEL_VERSION`, or existing `.ndsre` tables in Phase 7H2.
- Static symbol/function/annotation names are never copied into `.ndstrace`; static interpretation is recomputed from the current read-only `.ndsre` project at inspect/diff time.
- Preserve Phase 7H1's component-safe overlay behavior. A numerical address never proves which overlapping overlay is resident.
- Every trace capture is finite. API and parser bounds are: step limit `1..100000`, evidence-event limit `1..10000`, memory-region count `0..32`, one region length `1..0x01000000`, total configured memory bytes `<=0x02000000`, timeout `>0`.
- The existing interactive `nds-toolkit runtime step --count` command remains capped at `1..256`; the larger `1..100000` ceiling applies only to persisted `runtime trace capture --steps`.
- Exactly one trace selector is accepted: `--steps`, `--break`, `--watch-read`, `--watch-write`, or `--watch-access`. Break/watch modes require `--events`; step mode rejects `--events`.
- Repeated breakpoint/watchpoint capture must persist the stop as `EVIDENCE`, remove the temporary condition through the existing 7H1 path, single-step exactly once before re-arming, and persist that step as `CONTROL_ADVANCE`.
- `CONTROL_ADVANCE` events are stored and inspectable but excluded from default hit frequencies, function aggregation, and ranking.
- A configured memory region requires both BEFORE and AFTER snapshots before a trace can finalize as complete.
- Capture failure must not damage an existing destination trace: write a sibling temporary SQLite file, validate it, close it, and atomically replace the destination only after success.
- Ranking is a deterministic weighted evidence score, never a probability or ML confidence.
- All reports use deterministic ordering and the established lowercase canonical hexadecimal address rendering.
- Every implementation task follows RED -> minimal GREEN -> focused regression -> commit. Do not batch unrelated stages into one unreviewable commit.
- Final release proof requires full pytest, Ruff, strict mypy, exact-head PR CI including stock-melonDS live trace smoke, and exact post-merge `main` CI.

## File Map

Create:

```text
src/nds_disassembly_toolkit/analysis/runtime/trace_model.py
src/nds_disassembly_toolkit/analysis/runtime/trace_store.py
src/nds_disassembly_toolkit/analysis/runtime/capture.py
src/nds_disassembly_toolkit/analysis/runtime/memory_diff.py
src/nds_disassembly_toolkit/analysis/runtime/trace_diff.py

tests/unit/test_runtime_trace_model.py
tests/unit/test_runtime_trace_store.py
tests/unit/test_runtime_capture.py
tests/unit/test_runtime_memory_diff.py
tests/unit/test_analysis_project_runtime_queries.py
tests/unit/test_runtime_trace_correlation.py
tests/unit/test_runtime_trace_diff.py
tests/unit/test_runtime_trace_ranking.py
tests/integration/test_runtime_trace_workflow.py
```

Modify:

```text
src/nds_disassembly_toolkit/errors.py
src/nds_disassembly_toolkit/analysis/runtime/__init__.py
src/nds_disassembly_toolkit/analysis/runtime/correlation.py
src/nds_disassembly_toolkit/analysis/project/project.py
src/nds_disassembly_toolkit/analysis/runtime_cli.py

tests/unit/test_runtime_exports.py
tests/unit/test_runtime_cli.py

docs/runtime-debugging.md
docs/provenance-and-licenses.md
README.md
.github/smoke/headless_nds.cpp
.github/workflows/ci.yml
```

Delete after the consolidated CI job covers 7H1 + 7H2:

```text
.github/workflows/phase-7h-live-smoke.yml
```

Do not modify:

```text
src/nds_disassembly_toolkit/analysis/runtime/rsp.py
src/nds_disassembly_toolkit/analysis/project/schema.py
pyproject.toml
```

---

### Task 1: Trace Models, Validation, Errors, and Public Exports

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/runtime/trace_model.py`
- Modify: `src/nds_disassembly_toolkit/errors.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/__init__.py`
- Create: `tests/unit/test_runtime_trace_model.py`
- Modify: `tests/unit/test_runtime_exports.py`

**Interfaces:**

Implement these enums/constants exactly:

```python
TRACE_SCHEMA_VERSION = 1

class TraceCaptureMode(StrEnum):
    STEP = "step"
    BREAKPOINT = "breakpoint"
    WATCHPOINT = "watchpoint"

class TraceEventRole(StrEnum):
    EVIDENCE = "evidence"
    CONTROL_ADVANCE = "control_advance"

class MemorySnapshotPhase(StrEnum):
    BEFORE = "before"
    AFTER = "after"

class TraceTermination(StrEnum):
    LIMIT = "limit"
    TARGET_EXIT = "target_exit"
```

Implement these immutable records with the listed fields:

```text
TraceMemoryRegion
  ordinal: int
  address: int
  length: int
  label: str | None = None

TraceCaptureConfig
  cpu: RuntimeCpu
  mode: TraceCaptureMode
  limit: int
  timeout: float
  condition_kind: BreakpointKind | None = None
  condition_address: int | None = None
  condition_length: int | None = None
  memory_regions: tuple[TraceMemoryRegion, ...] = ()
  label: str | None = None
  project_fingerprint: str | None = None
  toolkit_version: str | None = None
  trace_schema_version: int = TRACE_SCHEMA_VERSION

TraceEvent
  ordinal: int
  role: TraceEventRole
  cpu: RuntimeCpu
  pc: int
  cpsr: int
  instruction_set: InstructionSet
  stop: RuntimeStop
  registers: RegisterSnapshot

MemorySnapshot
  region: TraceMemoryRegion
  phase: MemorySnapshotPhase
  data: bytes
  sha256: str

TraceSummary
  trace: Path
  cpu: RuntimeCpu
  capture_mode: TraceCaptureMode
  evidence_events: int
  control_events: int
  memory_regions: int
  terminated_by: TraceTermination
  project_fingerprint: str | None
```

`TraceEvent.from_snapshot(ordinal, role, snapshot)` copies the canonical PC/CPSR/instruction set/stop/register facts from the existing `RuntimeSnapshot`.

`MemorySnapshot.from_bytes(region, phase, data)` requires `len(data) == region.length` and computes lowercase SHA-256 hex itself; callers do not supply an unchecked digest.

`TraceCaptureConfig.__post_init__` enforces all API ceilings, contiguous memory-region ordinals starting at zero, total configured memory bytes, valid condition/mode combinations, non-negative addresses, and a lowercase 64-hex project fingerprint when present. STEP accepts only `condition_* = None`; BREAKPOINT requires `BreakpointKind.CODE`; WATCHPOINT requires READ/WRITE/ACCESS. STEP `limit` uses `1..100000`; BREAKPOINT/WATCHPOINT `limit` uses `1..10000`.

Trace errors:

```python
class RuntimeTraceError(RuntimeAnalysisError):
    """Raised when persisted runtime trace work cannot complete safely."""

class RuntimeTraceFormatError(RuntimeTraceError):
    """Raised when a .ndstrace file violates its persisted format contract."""

class RuntimeTraceMismatchError(RuntimeTraceError):
    """Raised when two known trace targets cannot be compared safely."""
```

- [ ] **Step 1: Write failing model/error/export tests**

```python
def test_step_trace_config_has_independent_large_bound() -> None:
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=100000,
        timeout=5.0,
    )
    assert config.limit == 100000


def test_trace_config_rejects_too_many_breakpoint_hits() -> None:
    with pytest.raises(ValueError, match="event limit"):
        TraceCaptureConfig(
            cpu=RuntimeCpu.ARM9,
            mode=TraceCaptureMode.BREAKPOINT,
            limit=10001,
            timeout=5.0,
            condition_kind=BreakpointKind.CODE,
            condition_address=0x02000000,
            condition_length=4,
        )


def test_memory_snapshot_computes_digest() -> None:
    region = TraceMemoryRegion(0, 0x02100000, 4)
    snapshot = MemorySnapshot.from_bytes(
        region, MemorySnapshotPhase.BEFORE, b"\x00\x01\x02\x03"
    )
    assert snapshot.sha256 == hashlib.sha256(snapshot.data).hexdigest()
```

Also test: control event conversion, negative/overflow addresses, zero memory lengths, >32 regions, >32 MiB aggregate memory, non-contiguous region ordinals, bad fingerprint, wrong condition kind, STEP with condition, WATCHPOINT with CODE, memory byte-length mismatch, summary negative counts, frozen dataclass mutation, and error inheritance.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_trace_model.py tests/unit/test_runtime_exports.py -v
```

Expected: imports/types fail because trace models/errors do not exist.

- [ ] **Step 3: Implement minimum immutable model/error surface**

Keep validation in model constructors so direct Python API consumers receive the same safety guarantees as CLI users. Reuse `RuntimeCpu`, `BreakpointKind`, `RuntimeStop`, `RuntimeSnapshot`, `RegisterSnapshot`, and `InstructionSet`; do not duplicate 7H1 models.

- [ ] **Step 4: Verify GREEN and 7H1 compatibility**

```bash
python -m pytest \
  tests/unit/test_runtime_trace_model.py \
  tests/unit/test_runtime_exports.py \
  tests/unit/test_runtime_model.py \
  tests/unit/test_runtime_melonds.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add \
  src/nds_disassembly_toolkit/errors.py \
  src/nds_disassembly_toolkit/analysis/runtime/trace_model.py \
  src/nds_disassembly_toolkit/analysis/runtime/__init__.py \
  tests/unit/test_runtime_trace_model.py \
  tests/unit/test_runtime_exports.py
git commit -m "Add runtime trace models"
```

---

### Task 2: `.ndstrace` SQLite Schema, Reader/Writer, and Atomic Finalization

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/runtime/trace_store.py`
- Create: `tests/unit/test_runtime_trace_store.py`

**Interfaces:**

`TraceStore` owns an SQLite schema independent of `.ndsre`:

```sql
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE capture_config (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    limit_count INTEGER NOT NULL CHECK(limit_count > 0),
    timeout REAL NOT NULL CHECK(timeout > 0),
    condition_kind TEXT,
    condition_address INTEGER,
    condition_length INTEGER
);

CREATE TABLE events (
    ordinal INTEGER PRIMARY KEY CHECK(ordinal >= 0),
    role TEXT NOT NULL,
    pc INTEGER NOT NULL CHECK(pc >= 0),
    cpsr INTEGER NOT NULL CHECK(cpsr >= 0),
    instruction_set TEXT NOT NULL,
    stop_kind TEXT NOT NULL,
    signal INTEGER,
    stop_address INTEGER,
    raw_stop TEXT NOT NULL,
    registers_json TEXT NOT NULL
);

CREATE TABLE memory_regions (
    id INTEGER PRIMARY KEY,
    ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal >= 0),
    label TEXT,
    base_address INTEGER NOT NULL CHECK(base_address >= 0),
    length INTEGER NOT NULL CHECK(length > 0)
);

CREATE TABLE memory_snapshots (
    region_id INTEGER NOT NULL,
    phase TEXT NOT NULL,
    data BLOB NOT NULL,
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    PRIMARY KEY(region_id, phase),
    FOREIGN KEY(region_id) REFERENCES memory_regions(id) ON DELETE CASCADE
);
```

Required metadata written at creation: `trace_schema_version`, `toolkit_version` (empty string when unavailable), `cpu`, `capture_mode`, `capture_status=incomplete`; optional `label` and `project_fingerprint`. Finalization additionally writes `capture_status=complete`, `evidence_events`, `control_events`, and `terminated_by`. These are runtime facts, not copied static interpretation.

Public methods/properties:

```text
TraceStore.create_atomic(destination: Path, config: TraceCaptureConfig)
  -> context manager yielding writable TraceStore
TraceStore.open(path: Path) -> read-only TraceStore
TraceStore.config -> TraceCaptureConfig
TraceStore.summary -> TraceSummary
TraceStore.append_event(event: TraceEvent) -> None
TraceStore.store_memory_snapshot(snapshot: MemorySnapshot) -> None
TraceStore.events() -> tuple[TraceEvent, ...]
TraceStore.memory_regions() -> tuple[TraceMemoryRegion, ...]
TraceStore.memory_snapshot(region_ordinal, phase) -> MemorySnapshot | None
TraceStore.finalize(summary: TraceSummary) -> None
TraceStore.validate_complete() -> None
TraceStore.close() -> None
```

`create_atomic()` uses `destination.with_suffix(destination.suffix + ".tmp")` as the sibling working database. It removes a stale sibling temp before creating a new one, never removes/replaces the destination before success, and cleans the temp on any exception or context exit without successful finalization.

`finalize()` validates:
- summary trace path/CPU/mode/fingerprint/counts agree with config/stored rows;
- event ordinals are exactly `0..N-1`;
- event CPU agrees with config;
- all configured regions have exactly one BEFORE and one AFTER snapshot;
- persisted snapshot lengths and SHA-256 match their region/data;
- `PRAGMA integrity_check` returns exactly `ok`.

Then it writes complete metadata, commits, closes, and atomically replaces the destination.

Register JSON is canonical:

```python
json.dumps(
    [{"name": name, "value": value} for name, value in event.registers.values],
    sort_keys=True,
    separators=(",", ":"),
)
```

- [ ] **Step 1: Write RED lifecycle/schema tests**

Test creation/reopen, metadata/config/summary round trip, event/register round trip, BLOB snapshot round trip, unknown/future schema rejection, incomplete-status rejection by `open()`, malformed enum/register JSON rejection, and read-only completed traces.

- [ ] **Step 2: Write RED atomic-failure tests**

```python
def test_failed_atomic_trace_preserves_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "capture.ndstrace"
    destination.write_bytes(b"known-good")

    with pytest.raises(RuntimeError, match="capture failed"):
        with TraceStore.create_atomic(destination, _step_config()) as store:
            store.append_event(_event(0))
            raise RuntimeError("capture failed")

    assert destination.read_bytes() == b"known-good"
    assert not destination.with_suffix(".ndstrace.tmp").exists()
```

Also require finalization failure for ordinal gap `0,2`, missing AFTER snapshot, wrong snapshot digest/length, summary count mismatch, or event CPU mismatch.

- [ ] **Step 3: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_trace_store.py -v
```

Expected: import failure for `trace_store`.

- [ ] **Step 4: Implement schema/codec/atomic lifecycle minimally**

Map SQLite/codec/version failures to `RuntimeTraceFormatError` with stable caller-facing messages. `TraceStore.open()` uses SQLite URI `mode=ro`. Do not import `.ndsre` private schema helpers.

- [ ] **Step 5: Verify GREEN**

```bash
python -m pytest \
  tests/unit/test_runtime_trace_store.py \
  tests/unit/test_runtime_trace_model.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add \
  src/nds_disassembly_toolkit/analysis/runtime/trace_store.py \
  tests/unit/test_runtime_trace_store.py
git commit -m "Persist portable runtime traces"
```

---

### Task 3: Read-Only `.ndsre` Runtime Queries and Exact Project Fingerprint

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project/project.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/correlation.py`
- Create: `tests/unit/test_analysis_project_runtime_queries.py`
- Modify: `tests/unit/test_runtime_correlation.py`

**Interfaces:**

Add only these read-only methods to `AnalysisProject`:

```text
functions_containing(
  component: str,
  address: int,
  instruction_set: InstructionSet,
) -> tuple[FunctionCandidate, ...]

xrefs_to_range(
  start_address: int,
  end_address: int,
  *,
  source_component: str | None = None,
) -> tuple[CrossReference, ...]

xrefs_from_function(
  component: str,
  function_address: int,
  instruction_set: InstructionSet,
) -> tuple[CrossReference, ...]
```

`functions_containing()` returns a function when either its exact entry matches or the existing persisted `instructions` table contains an instruction with the requested address/mode for that function. Use `SELECT DISTINCT`, not CFG reconstruction. Preserve multiple matching functions and order by function address then instruction-set value.

`xrefs_to_range()` is half-open `[start_address, end_address)` and rejects `end <= start`. Sort target address, component, source address, kind. `xrefs_from_function()` filters persisted `source_function_address` and `source_instruction_set` and sorts source address, target address, kind.

Add exact fingerprint helper in `analysis/runtime/correlation.py`:

```python
def analysis_project_fingerprint(project: AnalysisProject) -> str:
    metadata = project.metadata
    payload = {
        "analysis_model_version": metadata.analysis_model_version,
        "components": [
            {
                "base_address": item.base_address,
                "name": item.name,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in project.component_identities()
        ],
        "project_format_version": metadata.project_format_version,
        "schema_version": metadata.schema_version,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
```

Do not include `read_only`, toolkit version, timestamps, functions, symbols, annotations, CFGs, data-flow, or other derived analysis.

- [ ] **Step 1: Write RED project-query tests using real `.ndsre` fixtures**

Create a function CFG with instructions at `BASE`, `BASE+4`, `BASE+8`; assert `functions_containing(..., BASE+4, ARM)` returns the entry function even though existing `project.function(..., BASE+4, ARM)` remains `None`. Add two persisted functions that intentionally claim one instruction address and assert both are preserved.

Test `xrefs_to_range(0x02100000, 0x02100010)` boundary inclusion/exclusion and component filter. Test `xrefs_from_function()` excludes xrefs from another function in the same component.

- [ ] **Step 2: Write RED fingerprint tests**

Assert the fingerprint equals a test-computed canonical digest, is unaffected by adding an annotation/derived analysis that leaves component identities unchanged, and changes when a component SHA/base/size/name changes.

- [ ] **Step 3: Verify RED**

```bash
python -m pytest \
  tests/unit/test_analysis_project_runtime_queries.py \
  tests/unit/test_runtime_correlation.py -v
```

Expected: missing methods/helper.

- [ ] **Step 4: Implement SQL queries and fingerprint**

Use existing `function_from_row()` / `xref_from_row()` codecs and `_require_connection()`. Do not add indexes or a schema migration in 7H2.

- [ ] **Step 5: Prove `.ndsre` schema stayed compatible**

```bash
python -m pytest \
  tests/unit/test_analysis_project_lifecycle.py \
  tests/unit/test_analysis_project_records.py \
  tests/unit/test_analysis_project_cfg.py \
  tests/unit/test_analysis_project_runtime_queries.py -v
```

Expected: PASS with `project.metadata.schema_version == 1` and `analysis_model_version == 1`.

- [ ] **Step 6: Commit**

```bash
git add \
  src/nds_disassembly_toolkit/analysis/project/project.py \
  src/nds_disassembly_toolkit/analysis/runtime/correlation.py \
  tests/unit/test_analysis_project_runtime_queries.py \
  tests/unit/test_runtime_correlation.py
git commit -m "Add runtime analysis project queries"
```

---

### Task 4: Bounded Step/Breakpoint/Watchpoint Capture Orchestration

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/runtime/capture.py`
- Create: `tests/unit/test_runtime_capture.py`

**Interfaces:**

Define a private/narrow `RuntimeCaptureSession` protocol containing:

```text
cpu: RuntimeCpu
read_memory(address: int, length: int) -> bytes
step() -> RuntimeSnapshot
run_until_breakpoint(address: int, *, length: int = 4) -> RuntimeSnapshot
run_until_watchpoint(kind: BreakpointKind, address: int, *, length: int = 4) -> RuntimeSnapshot
```

Production `MelonDSSession` already satisfies this protocol.

Public capture entry:

```text
capture_trace(
  session: RuntimeCaptureSession,
  config: TraceCaptureConfig,
  destination: Path,
) -> TraceSummary
```

Algorithm:

```text
open TraceStore.create_atomic(destination, config)
read/store BEFORE for configured regions, in ordinal order
if STEP:
  up to config.limit times:
    snapshot = session.step()
    append EVIDENCE
    if snapshot.stop.kind == EXITED: terminate target_exit
else BREAKPOINT/WATCHPOINT:
  repeat until evidence_count == config.limit:
    snapshot = existing 7H1 run_until_* temporary-condition operation
    if non-exit stop kind is not requested BREAKPOINT/WATCHPOINT: abort
    append EVIDENCE
    if EXITED: terminate target_exit
    if another evidence event is required:
      advance = session.step()
      append CONTROL_ADVANCE
      if advance.stop.kind == EXITED: terminate target_exit
read/store AFTER for configured regions, in ordinal order
build TraceSummary with limit/target_exit termination
finalize store
return summary
```

A target exit is a valid terminal runtime event. If configured AFTER reads fail because the peer no longer permits memory reads post-exit, the complete trace is rejected exactly as designed.

- [ ] **Step 1: Write RED step-capture tests**

Fake session returns deterministic snapshots. Assert three `step()` calls create ordinals `0,1,2`, all `EVIDENCE`, and terminate by `limit`. Add an early `EXITED` snapshot and assert `target_exit` with fewer evidence events.

- [ ] **Step 2: Write RED repeated-breakpoint/watchpoint tests**

```python
assert [(event.ordinal, event.role, event.pc) for event in store.events()] == [
    (0, TraceEventRole.EVIDENCE, 0x02000008),
    (1, TraceEventRole.CONTROL_ADVANCE, 0x0200000C),
    (2, TraceEventRole.EVIDENCE, 0x02000008),
]
```

Assert fake session calls are `run_until_breakpoint`, `step`, `run_until_breakpoint`; for watchpoints assert exact READ/WRITE/ACCESS `BreakpointKind` and length are forwarded. Confirm no advance step after the final requested evidence event.

- [ ] **Step 3: Write RED memory-capture/failure tests**

Require all BEFORE reads before first execution and AFTER reads only after the final stop. If an AFTER read raises `RuntimeConnectionError`, no completed destination is produced and an existing destination remains untouched.

- [ ] **Step 4: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_capture.py -v
```

Expected: import failure for `capture`.

- [ ] **Step 5: Implement capture orchestration minimally**

Do not modify `MelonDSSession` or RSP behavior to make orchestration tests pass. Use `MemorySnapshot.from_bytes()` so trace hashes cannot diverge from actual bytes.

- [ ] **Step 6: Verify GREEN**

```bash
python -m pytest \
  tests/unit/test_runtime_capture.py \
  tests/unit/test_runtime_trace_store.py \
  tests/unit/test_runtime_melonds.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add \
  src/nds_disassembly_toolkit/analysis/runtime/capture.py \
  tests/unit/test_runtime_capture.py
git commit -m "Capture bounded runtime traces"
```

---

### Task 5: Memory BEFORE/AFTER Differential Engine

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/trace_model.py`
- Create: `src/nds_disassembly_toolkit/analysis/runtime/memory_diff.py`
- Create: `tests/unit/test_runtime_memory_diff.py`

**Interfaces:**

Add immutable records:

```text
AlignedMemoryValueChange
  address: int
  width: int                 # only 2 or 4
  before: int
  after: int

MemoryChange
  region_ordinal: int
  address: int
  before: bytes
  after: bytes
  values16: tuple[AlignedMemoryValueChange, ...] = ()
  values32: tuple[AlignedMemoryValueChange, ...] = ()
```

Public functions:

```text
diff_memory_snapshots(before: MemorySnapshot, after: MemorySnapshot)
  -> tuple[MemoryChange, ...]

diff_trace_memory(store: TraceStore)
  -> tuple[MemoryChange, ...]
```

`diff_memory_snapshots()` requires same configured region, BEFORE/AFTER phase ordering, and equal byte length. It emits maximal contiguous changed byte ranges. Aligned interpretations are little-endian 2-byte and 4-byte words whose complete word lies within the configured region and has at least one changed byte, even if the word extends just outside the minimal raw changed range. Deduplicate aligned word addresses and keep ascending order.

- [ ] **Step 1: Write RED contiguous-range tests**

```python
before = bytes.fromhex("0001020304050607")
after  = bytes.fromhex("0001aabb0405cc07")
changes = diff_memory_snapshots(_before(before), _after(after))
assert [(c.address, c.before.hex(), c.after.hex()) for c in changes] == [
    (BASE + 2, "0203", "aabb"),
    (BASE + 6, "06", "cc"),
]
```

- [ ] **Step 2: Write RED alignment/boundary tests**

Assert a single changed byte in an aligned 32-bit word yields the applicable 16-bit and 32-bit convenience values when complete words are inside the region. Assert no 32-bit interpretation is emitted for a final two-byte region tail. Confirm raw before/after bytes remain authoritative.

- [ ] **Step 3: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_memory_diff.py -v
```

Expected: missing models/module.

- [ ] **Step 4: Implement deterministic memory comparison**

One linear pass discovers raw changed spans. A second bounded pass over aligned words overlapping changed bytes produces convenience values. Do not infer signedness, pointers, structures, types, or game semantics.

- [ ] **Step 5: Verify GREEN**

```bash
python -m pytest \
  tests/unit/test_runtime_memory_diff.py \
  tests/unit/test_runtime_trace_store.py \
  tests/unit/test_runtime_capture.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add \
  src/nds_disassembly_toolkit/analysis/runtime/trace_model.py \
  src/nds_disassembly_toolkit/analysis/runtime/memory_diff.py \
  tests/unit/test_runtime_memory_diff.py
git commit -m "Diff runtime memory snapshots"
```

---

### Task 6: Trace Event Static Correlation and Offline Trace Inspection

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/trace_model.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/correlation.py`
- Create: `src/nds_disassembly_toolkit/analysis/runtime/trace_diff.py`
- Create: `tests/unit/test_runtime_trace_correlation.py`

**Interfaces:**

Do not widen the existing Phase 7H1 `RuntimeComponentLocation.function: FunctionCandidate | None`; add trace-specific records:

```text
TraceComponentLocation
  component: str
  functions: tuple[FunctionCandidate, ...] = ()
  symbols: tuple[Symbol, ...] = ()
  annotation: LocationAnnotation | None = None

TraceEventCorrelation
  pc: int
  instruction_set: InstructionSet
  candidates: tuple[TraceComponentLocation, ...]
  ambiguous: bool
  resolved_function: FunctionCandidate | None

TraceAddressHit
  cpu: RuntimeCpu
  pc: int
  instruction_set: InstructionSet
  count: int
  frequency: float

TraceAddressInspection
  hit: TraceAddressHit
  correlation: TraceEventCorrelation | None

TraceMemoryRegionSummary
  region: TraceMemoryRegion
  before_sha256: str
  after_sha256: str
  changed_bytes: int
  changes: tuple[MemoryChange, ...]

TraceInspectionReport
  trace_schema_version: int
  capture_status: str
  config: TraceCaptureConfig
  terminated_by: TraceTermination
  evidence_events: int
  control_events: int
  addresses: tuple[TraceAddressInspection, ...]
  memory_regions: tuple[TraceMemoryRegionSummary, ...]
  ambiguity_count: int
  integrity_ok: bool
```

Add:

```text
correlate_trace_event(project: AnalysisProject, event: TraceEvent)
  -> TraceEventCorrelation

inspect_trace(trace: Path | TraceStore, *, project: AnalysisProject | None = None)
  -> TraceInspectionReport
```

Correlation rules:
- find all persisted components whose runtime ranges contain the PC;
- per component call `functions_containing(component, pc, event.instruction_set)`, `symbols_at(component, pc)`, and `annotation(component, pc)`;
- preserve candidates sorted by component name;
- `resolved_function` is set only when exactly one component candidate exists and exactly one function contains the PC;
- if several components overlap, or one component has multiple possible functions, set `ambiguous=True` and `resolved_function=None`.

Inspection counts only `EVIDENCE` for address frequency; control-event count is separate. Address identity is `(cpu, pc, instruction_set)`. Memory summary uses Task 5 and sums raw changed-byte lengths. Inspection never writes to the trace or project.

- [ ] **Step 1: Write RED correlation tests for PCs inside functions**

Build a real `.ndsre` CFG whose entry is `BASE` and event PC is `BASE+4`; assert `resolved_function` is the entry function. Preserve all existing Phase 7H1 exact snapshot-correlation tests unchanged.

- [ ] **Step 2: Write RED overlay ambiguity tests**

Create `overlay_3` and `overlay_7` with the same base/range and functions covering the same PC. Assert both candidates are present, `ambiguous=True`, and `resolved_function is None`.

- [ ] **Step 3: Write RED inspection tests**

Create a real temporary `.ndstrace` containing a repeated EVIDENCE PC plus one CONTROL_ADVANCE. Assert hit count/frequency uses evidence denominator only, memory changed-byte count is correct, integrity/schema fields are present, project correlation is optional, and neither input file is mutated.

- [ ] **Step 4: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_trace_correlation.py -v
```

Expected: missing trace correlation/inspection records.

- [ ] **Step 5: Implement trace correlation and inspection**

Keep JSON serialization out of core modules; reports retain typed integers/enums/records. Cache correlation by `(pc, instruction_set)` inside one inspection so repeated hits do not repeat project queries.

- [ ] **Step 6: Verify GREEN**

```bash
python -m pytest \
  tests/unit/test_runtime_trace_correlation.py \
  tests/unit/test_runtime_correlation.py \
  tests/unit/test_analysis_project_runtime_queries.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add \
  src/nds_disassembly_toolkit/analysis/runtime/trace_model.py \
  src/nds_disassembly_toolkit/analysis/runtime/correlation.py \
  src/nds_disassembly_toolkit/analysis/runtime/trace_diff.py \
  tests/unit/test_runtime_trace_correlation.py
git commit -m "Correlate and inspect runtime traces"
```

---

### Task 7: Behavioral Differential and Transparent Function Ranking

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/trace_model.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/trace_diff.py`
- Create: `tests/unit/test_runtime_trace_diff.py`
- Create: `tests/unit/test_runtime_trace_ranking.py`

**Interfaces:**

Add immutable records:

```text
TraceAddressDelta
  cpu: RuntimeCpu
  pc: int
  instruction_set: InstructionSet
  baseline_hits: int
  target_hits: int
  baseline_frequency: float
  target_frequency: float
  frequency_delta: float
  classification: str        # baseline_only | target_only | shared

TraceFunctionDelta
  component: str
  address: int
  instruction_set: InstructionSet
  baseline_hits: int
  target_hits: int
  baseline_frequency: float
  target_frequency: float
  classification: str
  dynamic_pcs: tuple[int, ...]
  symbols: tuple[Symbol, ...]
  annotation: LocationAnnotation | None
  condition_hit: bool
  condition_stop_pcs: tuple[int, ...]
  changed_memory_references: tuple[CrossReference, ...]

FunctionRankEvidence
  name: str
  value: float
  weight: float
  contribution: float
  reasons: tuple[str, ...]

RankedFunctionCandidate
  component: str
  address: int
  instruction_set: InstructionSet
  score: float
  evidence: tuple[FunctionRankEvidence, ...]

TraceDiffReport
  baseline_config: TraceCaptureConfig
  target_config: TraceCaptureConfig
  target_identity_verified: bool
  address_deltas: tuple[TraceAddressDelta, ...]
  function_deltas: tuple[TraceFunctionDelta, ...]
  ambiguous_correlations: tuple[TraceEventCorrelation, ...]
  baseline_memory_changes: tuple[MemoryChange, ...]
  target_memory_changes: tuple[MemoryChange, ...]
  rankings: tuple[RankedFunctionCandidate, ...]
```

Primary API:

```text
compare_traces(
  baseline: Path | TraceStore,
  target: Path | TraceStore,
  *,
  project: AnalysisProject | None = None,
) -> TraceDiffReport
```

Fingerprint rule: if both stored fingerprints are non-`None` and differ, raise `RuntimeTraceMismatchError`. Otherwise raw comparison proceeds; `target_identity_verified=True` only when both matching fingerprints are present.

Raw address identity is `(cpu, pc, instruction_set)` and includes only EVIDENCE. Frequency denominator is evidence-event count in each trace. Classification is deterministic baseline-only/target-only/shared.

When a project is available, aggregate only events with an unambiguous `resolved_function`. Function frequency is function evidence hits divided by total trace evidence-event count. `symbols` and `annotation` are queried at the function entry, not copied from trace storage. `condition_hit` is true only when target EVIDENCE with stop kind BREAKPOINT or WATCHPOINT resolves to that function; preserve those stop PCs in ascending `condition_stop_pcs`.

Target memory-reference evidence uses target trace changed ranges and `project.xrefs_to_range()`; include references only when persisted source function address/mode match the function delta. Report/reason wording must say `static reference to changed memory`, never `runtime writer`, unless direct watchpoint condition-hit evidence is separately reported.

Ranking formula is exact:

```text
0.30 * target_exclusive
0.25 * positive_frequency_delta
0.20 * condition_hit
0.15 * changed_memory_reference
0.10 * dynamic_neighbor
```

Feature values:

```text
target_exclusive
  1.0 iff target_hits > 0 and baseline_hits == 0, else 0.0

positive_frequency_delta
  max(0.0, target_frequency - baseline_frequency)

condition_hit
  1.0 iff target breakpoint/watchpoint evidence resolves to this function, else 0.0

changed_memory_reference
  1.0 iff a static project xref from this function targets a target-trace changed range

dynamic_neighbor
  1.0 iff a static CALL relationship connects this function with another
  unambiguous target-exclusive dynamic candidate, else 0.0
```

For `dynamic_neighbor`, use `CrossReferenceKind.CALL`. A forward call target earns evidence only when `(target_address, target_instruction_set)` resolves to exactly one target-exclusive function identity in the current report. Reverse evidence may use `project.xrefs_to(function.address)` filtered to CALL plus persisted source-function identity. Do not credit ambiguous call targets.

Sort rankings by descending score, then component name, function address, instruction-set value. Emit all five `FunctionRankEvidence` entries even when zero. No field/reason/documentation calls score a probability.

- [ ] **Step 1: Write RED raw differential tests**

Baseline EVIDENCE PCs `[A,A,B]`; target `[A,C,C,C]`. Assert exact counts/frequencies (`A: 2/3 -> 1/4`, `B baseline_only`, `C target_only`) and confirm CONTROL_ADVANCE does not affect denominators.

- [ ] **Step 2: Write RED fingerprint mismatch/unverified tests**

Matching fingerprints => verified. Different non-null fingerprints => `RuntimeTraceMismatchError`. Missing on either trace => allowed with `target_identity_verified=False`.

- [ ] **Step 3: Write RED function aggregation/overlay tests**

Use a project where one dynamic PC is inside a normal ARM9 function and another lies in overlapping overlays. Assert only the unambiguous ARM9 function receives aggregate hits/ranking eligibility; ambiguous overlay candidates remain separately reported. Assert symbols/annotation come from the function entry and condition-stop PCs are retained.

- [ ] **Step 4: Write RED ranking feature tests**

Construct one target-exclusive function with target frequency `0.5`, breakpoint condition-hit, changed-memory xref, and dynamic neighbor. Assert:

```python
assert ranked.score == pytest.approx(
    0.30 * 1.0 +
    0.25 * 0.5 +
    0.20 * 1.0 +
    0.15 * 1.0 +
    0.10 * 1.0
)
assert [item.name for item in ranked.evidence] == [
    "target_exclusive",
    "positive_frequency_delta",
    "condition_hit",
    "changed_memory_reference",
    "dynamic_neighbor",
]
```

Also test deterministic tie-breaking, reverse-call dynamic-neighbor evidence, ambiguous call-target exclusion, and no probability terminology.

- [ ] **Step 5: Verify RED**

```bash
python -m pytest \
  tests/unit/test_runtime_trace_diff.py \
  tests/unit/test_runtime_trace_ranking.py -v
```

Expected: missing differential/ranking types/logic.

- [ ] **Step 6: Implement raw -> function -> ranking pipeline**

Build intermediate maps keyed by canonical identities and sort only when constructing immutable reports. Cache `TraceEventCorrelation` by `(pc, instruction_set)` per trace/project comparison.

- [ ] **Step 7: Verify GREEN**

```bash
python -m pytest \
  tests/unit/test_runtime_trace_diff.py \
  tests/unit/test_runtime_trace_ranking.py \
  tests/unit/test_runtime_trace_correlation.py \
  tests/unit/test_runtime_memory_diff.py -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add \
  src/nds_disassembly_toolkit/analysis/runtime/trace_model.py \
  src/nds_disassembly_toolkit/analysis/runtime/trace_diff.py \
  tests/unit/test_runtime_trace_diff.py \
  tests/unit/test_runtime_trace_ranking.py
git commit -m "Compare and rank runtime behavior"
```

---

### Task 8: CLI Capture/Inspect/Diff and End-to-End Integration Test

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/__init__.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime_cli.py`
- Modify: `tests/unit/test_runtime_cli.py`
- Create: `tests/integration/test_runtime_trace_workflow.py`

**Parser contract:**

```text
nds-toolkit runtime trace capture [connection options] SELECTOR --output TRACE
nds-toolkit runtime trace inspect TRACE [--project PROJECT] [--output JSON]
nds-toolkit runtime diff BASELINE TARGET [--project PROJECT] [--output JSON]
```

Capture selectors/options:

```text
--steps N
--break ADDRESS --events N
--watch-read ADDRESS --length N --events N
--watch-write ADDRESS --length N --events N
--watch-access ADDRESS --length N --events N
--memory ADDRESS:LENGTH       repeatable
--project PATH
--label TEXT
--timeout SECONDS
--cpu arm9|arm7
--host HOST
--port PORT
```

`--length` defaults to `4` for breakpoint/watchpoint capture and must be positive. Step mode ignores no condition length because parser/config construction rejects condition-only fields in step mode.

Capture success writes `.ndstrace` to `--output` and always emits deterministic summary JSON to stdout with exactly these top-level keys:

```text
trace
cpu
capture_mode
evidence_events
control_events
memory_regions
terminated_by
project_fingerprint
```

`trace` renders the destination path as supplied/resolved by the command policy; `memory_regions` is the configured region count; `terminated_by` is `limit` or `target_exit`.

Inspect/diff without `--output` write deterministic JSON stdout. With `--output`, reuse the existing `_write_json()` atomic text replacement behavior.

**Critical dispatch refactor:** `runtime trace inspect` and `runtime diff` are offline and must never call `_connect()`. `runtime trace capture` plus the five existing 7H1 live commands use `_connect()`.

Capture with `--project` opens the project read-only, computes only `analysis_project_fingerprint()`, closes it, then connects/captures. It does not persist copied static correlation.

Resolve toolkit version for `TraceCaptureConfig` with `importlib.metadata.version("nds-disassembly-toolkit")`; catch `PackageNotFoundError` and use `None`. `TraceStore` persists that as empty metadata when unavailable.

Memory parser accepts `ADDRESS:LENGTH`, assigns region ordinals in CLI order, and constructs `TraceCaptureConfig` before connecting so invalid bounds fail with exit `2` without touching the debugger.

- [ ] **Step 1: Write RED parser tests**

Assert valid nested commands, selector exclusivity, step/event mismatch, bounds (`100001` steps, `10001` events, 33 regions, oversized total), malformed `ADDRESS:LENGTH`, timeout/length validation, and preservation of old `runtime step --count 257` rejection.

- [ ] **Step 2: Write RED offline-dispatch tests**

Monkeypatch `_connect` to raise if called; run `runtime trace inspect` and `runtime diff` over fixture traces and assert they succeed without connection attempts.

- [ ] **Step 3: Write RED capture CLI behavior test**

Monkeypatch `MelonDSSession.connect` to a focused fake session. Assert destination is a valid SQLite trace, summary stdout has exact keys, project opens read-only for fingerprinting, invalid config fails before connect, and capture `--output` is never treated as a JSON report path.

- [ ] **Step 4: Write RED deterministic inspect/diff JSON tests**

Require canonical lowercase addresses, sorted keys, deterministic arrays, explicit `target_identity_verified`, ambiguity details, memory raw/16/32-bit values, function symbols/annotation, condition-stop PCs, ranking feature values/weights/contributions/reasons, and no probability terminology.

- [ ] **Step 5: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_cli.py -v
```

Expected: parser/dispatch failures for new commands.

- [ ] **Step 6: Implement CLI parser, serializers, and online/offline dispatch**

Refactor `run_runtime_command()` so offline commands return before `_connect()`. Keep raw report-to-JSON conversion in `runtime_cli.py`; core trace modules remain presentation-neutral. Reuse existing `_hex()` and `_write_json()` conventions.

- [ ] **Step 7: Add real-file integration workflow test**

`tests/integration/test_runtime_trace_workflow.py` must:

1. create a real `.ndsre` project fixture with component/function/CFG/xref data;
2. capture two real temporary `.ndstrace` SQLite files through `capture_trace()` using deterministic fake sessions;
3. include memory BEFORE/AFTER change in target;
4. inspect one trace with the project;
5. compare baseline vs target with the project;
6. verify matching fingerprint, target-only function ranking, changed-memory static reference, and no mutation of either input file.

- [ ] **Step 8: Verify Task 8 GREEN gate**

```bash
python -m pytest \
  tests/unit/test_runtime_cli.py \
  tests/integration/test_runtime_trace_workflow.py \
  tests/unit/test_runtime_*.py -v
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add \
  src/nds_disassembly_toolkit/analysis/runtime/__init__.py \
  src/nds_disassembly_toolkit/analysis/runtime_cli.py \
  tests/unit/test_runtime_cli.py \
  tests/integration/test_runtime_trace_workflow.py
git commit -m "Expose runtime trace workflows"
```

---

### Task 9: Documentation, Stock-melonDS Live Regression Gate, and Release Audit

**Files:**
- Modify: `.github/smoke/headless_nds.cpp`
- Modify: `.github/workflows/ci.yml`
- Delete: `.github/workflows/phase-7h-live-smoke.yml`
- Modify: `docs/runtime-debugging.md`
- Modify: `docs/provenance-and-licenses.md`
- Modify: `README.md`
- Test: complete repository

**Live target program:** replace the current simple increment loop with a deterministic ARM9 program that repeatedly writes memory:

```cpp
constexpr u32 base = 0x02000000;
constexpr u32 observed = base + 0x100;
nds->ARM9Write32(base + 0x00, 0xE3A00001); // mov r0,#1
nds->ARM9Write32(base + 0x04, 0xE59F1008); // ldr r1,[pc,#8]
nds->ARM9Write32(base + 0x08, 0xE2800001); // add r0,r0,#1
nds->ARM9Write32(base + 0x0C, 0xE5810000); // str r0,[r1]
nds->ARM9Write32(base + 0x10, 0xEAFFFFFC); // b 0x02000008
nds->ARM9Write32(base + 0x14, observed);   // literal for ldr at +04
nds->ARM9Write32(observed, 0);
```

Keep `args.JIT=std::nullopt`, ARM9 GDB enabled, ARM7 disabled for this harness, and `ARM9BreakOnStartup=true`.

**CI live gate:** retain stock melonDS commit `906e9ebb27da8c6a715cd7abab4abfe8a8d29427` and build flags:

```text
-DENABLE_JIT=OFF
-DENABLE_GDBSTUB=ON
-DENABLE_OGLRENDERER=OFF
-DBUILD_QT_SDL=OFF
```

Extend the existing `phase-7h-live-smoke` job in `.github/workflows/ci.yml`; do not create a second stock-melonDS build job. Preserve old `probe`, `snapshot`, `read-memory`, `run-until`, and interactive `step` assertions, updating expected instruction bytes/registers for the new harness.

Add exact trace smoke runs, restarting target between independent captures:

```bash
nds-toolkit runtime trace capture --cpu arm9 --steps 5 \
  --memory 0x02000100:4 --output /tmp/step.ndstrace

nds-toolkit runtime trace capture --cpu arm9 --break 0x02000008 \
  --events 2 --output /tmp/break.ndstrace

nds-toolkit runtime trace capture --cpu arm9 --watch-write 0x02000100 \
  --length 4 --events 2 --output /tmp/watch.ndstrace

nds-toolkit runtime trace inspect /tmp/step.ndstrace > /tmp/inspect.json
```

Assertions:
- step trace is complete with five EVIDENCE events;
- memory `0x02000100:4` begins at zero and has a non-empty AFTER differential after the store executes;
- repeated breakpoint trace has two EVIDENCE and exactly one CONTROL_ADVANCE between them, proving no immediate-retrigger loop;
- write-watch trace has real WATCHPOINT stop evidence and non-zero stop PC;
- inspect reports changed memory and successful integrity/schema validation.

For live static diff, create a synthetic `.ndsre` project in the workflow through public `AnalysisProject` APIs. Component `arm9` covers the harness range and has deterministic functions at `0x02000008` and `0x0200000c` (exact entries are sufficient for this particular breakpoint comparison). Capture baseline breakpoint `0x0200000c` and target breakpoint `0x02000008`, both with `--events 2 --project /tmp/live.ndsre`, so stored fingerprints match. Then:

```bash
nds-toolkit runtime diff \
  /tmp/baseline.ndstrace \
  /tmp/target.ndstrace \
  --project /tmp/live.ndsre > /tmp/diff.json
```

Assert `target_identity_verified` is true, target `0x02000008` is target-only EVIDENCE, baseline `0x0200000c` is baseline-only EVIDENCE (its target occurrence as CONTROL_ADVANCE is ignored), and the target function receives the expected target-exclusive/condition-hit ranking above non-target evidence.

After the consolidated `ci.yml` live job proves old and new paths, delete stale branch-specific `.github/workflows/phase-7h-live-smoke.yml` so there is one authoritative live regression workflow.

**Documentation:**
- expand `docs/runtime-debugging.md` with `.ndstrace`, capture/inspect/diff examples, bounds, EVIDENCE vs CONTROL_ADVANCE, memory semantics, fingerprint rules, overlay ambiguity, transparent ranking, and failure atomicity;
- replace the stale manual-only live-smoke claim: current CI builds/runs a headless stock melonDS core and exercises exact runtime CLI behavior;
- add runtime tracing/differentials to README capabilities and link `docs/runtime-debugging.md` under workflow documentation;
- update provenance to state Phase 7H1/7H2 use the external standard GDB interface, standard-library SQLite trace persistence, no melonDS source incorporation/runtime Python dependency, and no `.ndsre` schema migration.

- [ ] **Step 1: Update live harness and 7H2 smoke commands/assertions**

Run workflow-equivalent commands locally when the environment supports the stock melonDS build. Unit/integration tests remain mandatory regardless of external build availability.

- [ ] **Step 2: Update docs/provenance and delete stale workflow**

Check every documentation command against the Task 8 parser and keep 7H1 interactive `step --count` limits distinct from 7H2 trace step limits.

- [ ] **Step 3: Run focused runtime/project suite**

```bash
python -m pytest \
  tests/unit/test_runtime_*.py \
  tests/unit/test_analysis_project_*.py \
  tests/integration/test_runtime_trace_workflow.py -v
```

Expected: PASS.

- [ ] **Step 4: Run complete verification gate**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: all tests pass, Ruff clean, strict mypy zero issues.

- [ ] **Step 5: Run scope/schema/provenance audit**

Verify all of these before PR:

```text
- dependency declarations in pyproject.toml are unchanged
- analysis/project/schema.py is unchanged
- SCHEMA_VERSION == 1 and ANALYSIS_MODEL_VERSION == 1
- no melonDS source is copied beneath src/
- no game/Bakugan-specific address, rule, label, or semantic policy exists in toolkit runtime code
- no unbounded trace loop exists
- every repeated break/watch cycle stores CONTROL_ADVANCE and default behavior math excludes it
- completed .ndstrace requires integrity_check=ok and complete configured memory pairs
- offline inspect/diff never open a debugger connection
- static memory xrefs are never described as proven runtime writes
- ranking exposes all feature values, weights, contributions, reasons and never calls score a probability
- docs no longer claim live melonDS is only a manual gate
```

- [ ] **Step 6: Commit final docs/live gate**

```bash
git add \
  .github/smoke/headless_nds.cpp \
  .github/workflows/ci.yml \
  .github/workflows/phase-7h-live-smoke.yml \
  docs/runtime-debugging.md \
  docs/provenance-and-licenses.md \
  README.md
git commit -m "Verify Phase 7H2 runtime tracing"
```

- [ ] **Step 7: Open a non-draft PR and require exact-head CI**

Create the PR with `draft=false` because the current GitHub connector cannot reliably transition a draft PR to ready-for-review. Record exact branch HEAD SHA and do not merge unless both jobs are green for that exact SHA:

```text
verify
phase-7h-live-smoke
```

If branch HEAD moves, re-check the new exact head.

- [ ] **Step 8: Merge with expected-head protection and verify `main` again**

Use squash merge with `expected_head_sha=<verified exact PR head>`. Require a `main` CI run whose head is the exact squash commit and whose `verify` and `phase-7h-live-smoke` jobs both succeed before declaring Phase 7H2 complete.

---

## Definition of Done

Phase 7H2 is complete only when all of the following are true:

1. `.ndstrace` schema version 1 atomically persists/reopens bounded runtime events and configured memory snapshots.
2. Failed captures cannot replace an existing valid trace with partial output.
3. Step, repeated breakpoint, and repeated read/write/access watchpoint captures are finite and tested.
4. Repeated break/watch collection persists auditable CONTROL_ADVANCE events and does not loop on the same armed stop condition.
5. Memory BEFORE/AFTER reports deterministic raw changed spans plus bounded aligned 16/32-bit convenience values.
6. Exact static-project fingerprints follow the approved canonical JSON/SHA-256 contract.
7. `.ndsre` remains schema/model version 1; only approved read-only query helpers were added.
8. Trace PCs inside persisted CFG functions correlate without pretending overlapping overlays are resolved.
9. Offline inspect reports integrity/schema, termination, evidence/control counts, address frequency, memory changes, and optional static correlation.
10. Diff compares only EVIDENCE, normalizes unequal trace lengths, enforces known fingerprint mismatches, and reports unverified identity when fingerprints are absent.
11. Function differential includes dynamic PCs, current symbols/annotation, condition-stop PCs, and changed-memory static references while excluding ambiguous ownership.
12. Function ranking uses exactly the approved weights/features, emits every evidence contribution, and is never labeled a probability.
13. CLI capture/inspect/diff contracts and exit-code boundaries are deterministic and integration-tested; offline commands never connect.
14. The consolidated stock-melonDS CI gate proves multi-step trace, repeated breakpoint/control advance, real watchpoint stop, memory mutation, inspect, and behavior diff/ranking on exact PR head.
15. Full pytest, Ruff, strict mypy, exact-head PR CI, and exact post-merge `main` CI all pass.
