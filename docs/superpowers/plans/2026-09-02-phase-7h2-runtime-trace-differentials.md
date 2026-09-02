# Phase 7H2 Runtime Trace and Behavioral Differentials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded persisted runtime tracing, memory before/after evidence, static-project correlation, trace-vs-trace behavioral differentials, and transparent dynamic function ranking on top of the verified Phase 7H1 melonDS GDB bridge.

**Architecture:** Keep Phase 7H1 `RSPClient` and `MelonDSSession` as the only debugger transport/session path. Add immutable trace records in `analysis/runtime/trace_model.py`, independent SQLite `.ndstrace` persistence in `trace_store.py`, capture orchestration in `capture.py`, memory comparison in `memory_diff.py`, and offline inspection/differential/ranking logic in `trace_diff.py`. Extend `AnalysisProject` only with narrowly scoped read-only queries; do not change `.ndsre` schema version 1. The CLI adds online `runtime trace capture` and offline `runtime trace inspect` / `runtime diff` commands.

**Tech Stack:** Python 3.11+, standard-library `sqlite3`/`hashlib`/`json`, existing immutable analysis/runtime models, existing `MelonDSSession`, argparse, pytest, Ruff, strict mypy, stock melonDS headless GDB smoke harness.

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

Produce immutable `TraceMemoryRegion`, `TraceCaptureConfig`, `TraceEvent`, `MemorySnapshot`, and `TraceSummary`. Later tasks extend `trace_model.py` with differential/correlation records only when their behavior is introduced.

Recommended initial signatures:

```python
@dataclass(frozen=True, slots=True)
class TraceMemoryRegion:
    ordinal: int
    address: int
    length: int
    label: str | None = None

@dataclass(frozen=True, slots=True)
class TraceCaptureConfig:
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

@dataclass(frozen=True, slots=True)
class TraceEvent:
    ordinal: int
    role: TraceEventRole
    cpu: RuntimeCpu
    pc: int
    cpsr: int
    instruction_set: InstructionSet
    stop: RuntimeStop
    registers: RegisterSnapshot

    @classmethod
    def from_snapshot(
        cls, ordinal: int, role: TraceEventRole, snapshot: RuntimeSnapshot
    ) -> TraceEvent: ...
```

`TraceCaptureConfig.__post_init__` enforces all API ceilings, contiguous memory-region ordinals starting at zero, total memory bytes, valid condition/mode combinations, and a lowercase 64-hex project fingerprint when present. STEP accepts only `condition_* = None`; BREAKPOINT requires `BreakpointKind.CODE`; WATCHPOINT requires READ/WRITE/ACCESS.

Trace errors:

```python
class RuntimeTraceError(RuntimeAnalysisError): ...
class RuntimeTraceFormatError(RuntimeTraceError): ...
class RuntimeTraceMismatchError(RuntimeTraceError): ...
```

- [ ] **Step 1: Write failing model/error/export tests**

Include representative assertions:

```python
def test_step_trace_config_has_independent_large_bound() -> None:
    config = TraceCaptureConfig(
        cpu=RuntimeCpu.ARM9,
        mode=TraceCaptureMode.STEP,
        limit=100000,
        timeout=5.0,
    )
    assert config.limit == 100000


def test_trace_config_rejects_too_many_event_hits() -> None:
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


def test_control_event_preserves_runtime_snapshot() -> None:
    event = TraceEvent.from_snapshot(
        1,
        TraceEventRole.CONTROL_ADVANCE,
        _snapshot(pc=0x02000004, stop_kind=StopReasonKind.STEP),
    )
    assert event.role is TraceEventRole.CONTROL_ADVANCE
    assert event.pc == 0x02000004
```

Also test: negative/overflow addresses, zero memory lengths, >32 regions, >32 MiB aggregate memory, non-contiguous region ordinals, bad fingerprint, wrong condition kind, STEP with condition, WATCHPOINT with CODE, frozen dataclass mutation, and error inheritance.

- [ ] **Step 2: Verify RED**

Run:

```bash
python -m pytest tests/unit/test_runtime_trace_model.py tests/unit/test_runtime_exports.py -v
```

Expected: imports/types fail because trace models/errors do not exist.

- [ ] **Step 3: Implement minimum immutable model/error surface**

Keep validation in the model constructors so direct Python API consumers receive the same safety guarantees as CLI users. Reuse `RuntimeCpu`, `BreakpointKind`, `RuntimeStop`, `RuntimeSnapshot`, `RegisterSnapshot`, and `InstructionSet`; do not duplicate those 7H1 models.

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

`TraceStore` owns the independent SQLite trace schema. Use these logical tables and no others unless a schema-version change is explicitly designed later:

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

Metadata keys: `trace_schema_version`, `toolkit_version`, `cpu`, `capture_mode`, `capture_status`, optional `label`, optional `project_fingerprint`. Temporary databases begin with `capture_status=incomplete`; only `finalize()` writes `complete`.

Public shape:

```python
class TraceStore:
    @classmethod
    def create_atomic(
        cls, destination: Path, config: TraceCaptureConfig
    ) -> AbstractContextManager[TraceStore]: ...

    @classmethod
    def open(cls, path: Path) -> TraceStore: ...

    @property
    def config(self) -> TraceCaptureConfig: ...

    def append_event(self, event: TraceEvent) -> None: ...
    def store_memory_snapshot(self, snapshot: MemorySnapshot) -> None: ...
    def events(self) -> tuple[TraceEvent, ...]: ...
    def memory_regions(self) -> tuple[TraceMemoryRegion, ...]: ...
    def memory_snapshot(
        self, region_ordinal: int, phase: MemorySnapshotPhase
    ) -> MemorySnapshot | None: ...
    def finalize(self, summary: TraceSummary) -> None: ...
    def validate_complete(self) -> None: ...
    def close(self) -> None: ...
```

`create_atomic()` returns a context-managed writable store backed by a sibling temporary path. Exiting without successful `finalize()` closes and removes the temporary file. `finalize()` checks contiguous event ordinals from zero, complete BEFORE/AFTER pairs for all configured regions, summary counts against stored roles, runs `PRAGMA integrity_check`, closes the connection, then `Path.replace()`s the requested destination. Existing destination contents are never removed before the replacement point.

Register JSON is canonical:

```python
json.dumps(
    [{"name": name, "value": value} for name, value in event.registers.values],
    sort_keys=True,
    separators=(",", ":"),
)
```

- [ ] **Step 1: Write RED lifecycle/schema tests**

Test creation/reopen, metadata/config round trip, event/register round trip, BLOB snapshot round trip, unknown/future schema rejection, malformed enum/register JSON rejection, and read-only use of completed traces.

- [ ] **Step 2: Write RED atomic-failure tests**

Representative contract:

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

Also require `finalize()` to fail for ordinal gap `0,2`, missing AFTER snapshot, wrong snapshot byte length/hash, or event CPU inconsistent with config.

- [ ] **Step 3: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_trace_store.py -v
```

Expected: import failure for `trace_store`.

- [ ] **Step 4: Implement schema/codec/atomic lifecycle minimally**

Keep trace schema constants private to `trace_store.py` except `TRACE_SCHEMA_VERSION`, which is imported from `trace_model.py`. Map all `sqlite3.Error`/codec failures to `RuntimeTraceFormatError` with stable caller-facing messages. Do not import `.ndsre` private schema helpers.

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

```python
def functions_containing(
    self,
    component: str,
    address: int,
    instruction_set: InstructionSet,
) -> tuple[FunctionCandidate, ...]: ...

def xrefs_to_range(
    self,
    start_address: int,
    end_address: int,
    *,
    source_component: str | None = None,
) -> tuple[CrossReference, ...]: ...

def xrefs_from_function(
    self,
    component: str,
    function_address: int,
    instruction_set: InstructionSet,
) -> tuple[CrossReference, ...]: ...
```

`functions_containing()` returns a function when either its exact entry matches or the existing persisted `instructions` table contains an instruction with the requested address/mode for that function. Use `SELECT DISTINCT`, not CFG reconstruction. Preserve multiple matching functions and order by function address/mode.

`xrefs_to_range()` is half-open `[start_address, end_address)` and rejects `end <= start`. Sort target address, component, source address, kind. `xrefs_from_function()` filters the already persisted `source_function_address` and `source_instruction_set` fields.

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

Do not include `read_only`, toolkit version, timestamps, functions, symbols, annotations, CFGs, or other derived analysis.

- [ ] **Step 1: Write RED project-query tests using real `.ndsre` fixtures**

Create a function CFG with instructions at `BASE`, `BASE+4`, `BASE+8`; assert `functions_containing(..., BASE+4, ARM)` returns the entry function even though `project.function(..., BASE+4, ARM)` remains `None`. Add two persisted functions that intentionally claim one instruction address and assert both are preserved.

Test `xrefs_to_range(0x02100000, 0x02100010)` boundary inclusion/exclusion and component filter. Test `xrefs_from_function()` excludes xrefs from another function in the same component.

- [ ] **Step 2: Write RED fingerprint tests**

Assert the fingerprint equals a test-computed canonical digest, is unaffected by adding an annotation/generated analysis that leaves component identities unchanged, and changes when a component SHA/base/size/name changes.

- [ ] **Step 3: Verify RED**

```bash
python -m pytest \
  tests/unit/test_analysis_project_runtime_queries.py \
  tests/unit/test_runtime_correlation.py -v
```

Expected: missing methods/helper.

- [ ] **Step 4: Implement SQL queries and fingerprint**

Use existing `function_from_row()` / `xref_from_row()` codecs and `_require_connection()`. Do not add indexes or schema migration in this phase; existing `idx_xref_target`, `idx_xref_source`, function keys, and instruction keys are sufficient for the first implementation.

- [ ] **Step 5: Prove `.ndsre` schema stayed byte-contract compatible**

```bash
python -m pytest \
  tests/unit/test_analysis_project_lifecycle.py \
  tests/unit/test_analysis_project_records.py \
  tests/unit/test_analysis_project_cfg.py \
  tests/unit/test_analysis_project_runtime_queries.py -v
```

Expected: PASS with metadata still `AnalysisProjectMetadata(1, 1, 1, ...)`.

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

Use a narrow protocol for tests while production receives `MelonDSSession`:

```python
class RuntimeCaptureSession(Protocol):
    cpu: RuntimeCpu
    def read_memory(self, address: int, length: int) -> bytes: ...
    def step(self) -> RuntimeSnapshot: ...
    def run_until_breakpoint(
        self, address: int, *, length: int = 4
    ) -> RuntimeSnapshot: ...
    def run_until_watchpoint(
        self, kind: BreakpointKind, address: int, *, length: int = 4
    ) -> RuntimeSnapshot: ...
```

Public capture entry:

```python
def capture_trace(
    session: RuntimeCaptureSession,
    config: TraceCaptureConfig,
    destination: Path,
) -> TraceSummary: ...
```

Algorithm:

```text
open TraceStore.create_atomic(destination, config)
read/store BEFORE for configured regions
if STEP:
  up to config.limit times:
    snapshot = session.step()
    append EVIDENCE
    if snapshot.stop.kind == EXITED: terminate target_exit
else BREAKPOINT/WATCHPOINT:
  repeat until evidence_count == config.limit:
    snapshot = existing 7H1 run_until_* temporary condition call
    append EVIDENCE
    if EXITED: terminate target_exit
    if another evidence event is required:
      advance = session.step()
      append CONTROL_ADVANCE
      if advance.stop.kind == EXITED: terminate target_exit
read/store AFTER for configured regions
finalize trace with exact evidence/control counts and termination
return TraceSummary
```

For BREAKPOINT/WATCHPOINT modes, a non-exit stop that is neither the requested semantic breakpoint/watchpoint nor an expected trap condition is not silently labeled evidence; raise `RuntimeTargetStateError` and abort finalization. This prevents an unrelated signal stop from being treated as the requested condition.

- [ ] **Step 1: Write RED step-capture tests**

Fake session returns deterministic snapshots. Assert three `step()` calls create ordinals `0,1,2`, all `EVIDENCE`, and terminate by `limit`. Add early `EXITED` snapshot and assert `target_exit` with fewer evidence events.

- [ ] **Step 2: Write RED repeated-breakpoint/watchpoint tests**

Representative event order:

```python
assert [(event.ordinal, event.role, event.pc) for event in store.events()] == [
    (0, TraceEventRole.EVIDENCE, 0x02000008),
    (1, TraceEventRole.CONTROL_ADVANCE, 0x0200000C),
    (2, TraceEventRole.EVIDENCE, 0x02000008),
]
```

Assert the fake session call sequence is `run_until_breakpoint`, `step`, `run_until_breakpoint`; for watchpoints assert the exact READ/WRITE/ACCESS `BreakpointKind` and length are forwarded. Confirm no advance step after the final requested evidence event.

- [ ] **Step 3: Write RED memory-capture/failure tests**

Require BEFORE reads before the first execution operation and AFTER reads only after the last stop. If an AFTER read raises `RuntimeConnectionError`, no completed destination is produced and an existing destination remains untouched.

- [ ] **Step 4: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_capture.py -v
```

Expected: import failure for `capture`.

- [ ] **Step 5: Implement capture orchestration minimally**

Do not change `MelonDSSession` or RSP behavior to make tests pass. The purpose of this layer is orchestration/composition of the already verified 7H1 semantics.

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

```python
@dataclass(frozen=True, slots=True)
class AlignedMemoryValueChange:
    address: int
    width: int
    before: int
    after: int

@dataclass(frozen=True, slots=True)
class MemoryChange:
    region_ordinal: int
    address: int
    before: bytes
    after: bytes
    values16: tuple[AlignedMemoryValueChange, ...] = ()
    values32: tuple[AlignedMemoryValueChange, ...] = ()
```

Public functions:

```python
def diff_memory_snapshots(
    before: MemorySnapshot,
    after: MemorySnapshot,
) -> tuple[MemoryChange, ...]: ...

def diff_trace_memory(store: TraceStore) -> tuple[MemoryChange, ...]: ...
```

`diff_memory_snapshots()` requires same region/phase pairing and equal byte length. It emits maximal contiguous changed byte ranges. Aligned interpretations are little-endian 2-byte and 4-byte words whose complete word lies within the configured region and has at least one changed byte, even if the aligned word extends just outside the minimal changed range. Deduplicate aligned word addresses and keep ascending order.

- [ ] **Step 1: Write RED contiguous-range tests**

Example:

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

Assert a single changed byte at an aligned 32-bit word produces one 16-bit and one 32-bit convenience interpretation when complete words are inside the region. Assert no 32-bit interpretation is emitted for a final two-byte region tail. Confirm raw `before`/`after` bytes remain authoritative.

- [ ] **Step 3: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_memory_diff.py -v
```

Expected: missing models/module.

- [ ] **Step 4: Implement deterministic memory comparison**

One linear pass discovers changed spans. A second bounded pass over aligned word starts that overlap changed bytes produces convenience values. Do not infer signedness, pointers, structures, types, or game semantics.

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

Do not widen the existing Phase 7H1 `RuntimeComponentLocation.function: FunctionCandidate | None`; add trace-specific records instead:

```python
@dataclass(frozen=True, slots=True)
class TraceComponentLocation:
    component: str
    functions: tuple[FunctionCandidate, ...] = ()
    symbols: tuple[Symbol, ...] = ()
    annotation: LocationAnnotation | None = None

@dataclass(frozen=True, slots=True)
class TraceEventCorrelation:
    pc: int
    instruction_set: InstructionSet
    candidates: tuple[TraceComponentLocation, ...]
    ambiguous: bool
    resolved_function: FunctionCandidate | None
```

Add:

```python
def correlate_trace_event(
    project: AnalysisProject,
    event: TraceEvent,
) -> TraceEventCorrelation: ...
```

Rules:
- find all persisted components whose runtime ranges contain the PC;
- for each component call `functions_containing(component, pc, event.instruction_set)`, `symbols_at(component, pc)`, and `annotation(component, pc)`;
- preserve candidates sorted by component name;
- `resolved_function` is set only when there is exactly one component candidate and exactly one containing function for that component;
- if several components overlap, or one component has multiple possible functions, set `ambiguous=True` and `resolved_function=None`.

In `trace_diff.py`, introduce offline inspection:

```python
@dataclass(frozen=True, slots=True)
class TraceAddressHit:
    cpu: RuntimeCpu
    pc: int
    instruction_set: InstructionSet
    count: int
    frequency: float

@dataclass(frozen=True, slots=True)
class TraceInspectionReport:
    ...

def inspect_trace(
    trace: Path | TraceStore,
    *,
    project: AnalysisProject | None = None,
) -> TraceInspectionReport: ...
```

Inspection counts only `EVIDENCE` for address frequency; reports control-event count separately. Include metadata/config, integrity/schema status, evidence/control counts, stable hit list keyed `(cpu, pc, mode)`, memory-region changed-byte counts from Task 5, optional per-address static correlation, and ambiguity count.

- [ ] **Step 1: Write RED correlation tests for PCs inside functions**

Build a real `.ndsre` CFG whose entry is `BASE` and event PC is `BASE+4`; assert `resolved_function` is the entry function. Preserve current Phase 7H1 exact snapshot-correlation tests unchanged.

- [ ] **Step 2: Write RED overlay ambiguity tests**

Create `overlay_3` and `overlay_7` with the same base/range and functions covering the same PC. Assert both candidates are present and the event is excluded from resolved function ownership.

- [ ] **Step 3: Write RED inspection tests**

Create a real temporary `.ndstrace` containing repeated EVIDENCE PC plus one CONTROL_ADVANCE. Assert hit count/frequency uses evidence denominator only, memory changed-byte count is correct, and project correlation does not mutate either file.

- [ ] **Step 4: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_trace_correlation.py -v
```

Expected: missing trace correlation/inspection records.

- [ ] **Step 5: Implement trace correlation and inspect report**

Keep serialization out of this module; report models store typed integers/enums/records. CLI JSON conversion belongs in Task 8.

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

Add stable records:

```python
@dataclass(frozen=True, slots=True)
class TraceAddressDelta:
    cpu: RuntimeCpu
    pc: int
    instruction_set: InstructionSet
    baseline_hits: int
    target_hits: int
    baseline_frequency: float
    target_frequency: float
    frequency_delta: float
    classification: str  # baseline_only | target_only | shared

@dataclass(frozen=True, slots=True)
class TraceFunctionDelta:
    component: str
    address: int
    instruction_set: InstructionSet
    baseline_hits: int
    target_hits: int
    baseline_frequency: float
    target_frequency: float
    classification: str
    dynamic_pcs: tuple[int, ...]
    condition_hit: bool
    changed_memory_references: tuple[CrossReference, ...]

@dataclass(frozen=True, slots=True)
class FunctionRankEvidence:
    name: str
    value: float
    weight: float
    contribution: float
    reasons: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class RankedFunctionCandidate:
    component: str
    address: int
    instruction_set: InstructionSet
    score: float
    evidence: tuple[FunctionRankEvidence, ...]

@dataclass(frozen=True, slots=True)
class TraceDiffReport:
    target_identity_verified: bool
    address_deltas: tuple[TraceAddressDelta, ...]
    function_deltas: tuple[TraceFunctionDelta, ...]
    ambiguous_correlations: tuple[TraceEventCorrelation, ...]
    baseline_memory_changes: tuple[MemoryChange, ...]
    target_memory_changes: tuple[MemoryChange, ...]
    rankings: tuple[RankedFunctionCandidate, ...]
```

Primary API:

```python
def compare_traces(
    baseline: Path | TraceStore,
    target: Path | TraceStore,
    *,
    project: AnalysisProject | None = None,
) -> TraceDiffReport: ...
```

Fingerprint rule is exact: if both stored fingerprints are non-`None` and differ, raise `RuntimeTraceMismatchError`. Otherwise raw address comparison proceeds; `target_identity_verified=True` only when both matching fingerprints are present.

Raw address identity is `(cpu, pc, instruction_set)` and includes only EVIDENCE events. Frequency denominator is the number of EVIDENCE events in that trace. Classification is deterministic baseline-only/target-only/shared.

When project correlation is available, aggregate only events with an unambiguous `resolved_function`. A function's normalized frequency is its evidence hit count divided by the trace evidence-event count. Ambiguous events remain in raw address deltas but never inflate function counts.

Target memory-reference evidence uses target trace BEFORE/AFTER changed ranges and `project.xrefs_to_range()`; include xrefs only when their persisted `source_function_address/source_instruction_set` match the function delta. Wording/reason strings must say `static reference to changed memory`, never `runtime writer`, unless direct watchpoint evidence supports a stronger runtime condition-hit statement.

Ranking formula is exact:

```text
0.30 * target_exclusive
0.25 * positive_frequency_delta
0.20 * condition_hit
0.15 * changed_memory_reference
0.10 * dynamic_neighbor
```

Feature values:

```python
target_exclusive = 1.0 if target_hits > 0 and baseline_hits == 0 else 0.0
positive_frequency_delta = max(0.0, target_frequency - baseline_frequency)
condition_hit = 1.0 if target BREAKPOINT/WATCHPOINT evidence occurs in function else 0.0
changed_memory_reference = 1.0 if function has a static xref into target changed range else 0.0
dynamic_neighbor = 1.0 if a static CALL relationship connects it to another unambiguous target-exclusive dynamic candidate else 0.0
```

For `dynamic_neighbor`, accept a CALL edge only when the target address/mode resolves to exactly one target-exclusive function identity in the current report. Reverse-neighbor evidence may use `project.xrefs_to(function.address)` filtered to CALL and a persisted source function identity. Do not credit ambiguous call targets.

Sort rankings by descending score, then component name, function address, instruction-set value. Emit every feature even when zero so the score is auditable.

- [ ] **Step 1: Write RED raw differential tests**

Baseline EVIDENCE PCs `[A,A,B]`; target `[A,C,C,C]`. Assert counts and frequencies exactly (`A: 2/3 -> 1/4`, `B baseline_only`, `C target_only`) and confirm CONTROL_ADVANCE does not affect denominators.

- [ ] **Step 2: Write RED fingerprint mismatch/unverified tests**

Matching fingerprints => verified. Different non-null fingerprints => `RuntimeTraceMismatchError`. Missing on either trace => comparison allowed but `target_identity_verified=False`.

- [ ] **Step 3: Write RED function aggregation/overlay tests**

Use a project where one dynamic PC is inside a normal ARM9 function and another PC lies in overlapping overlays. Assert only the ARM9 function receives aggregate hits/ranking eligibility; ambiguous overlay candidates remain separately reported.

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

Also test deterministic tie-breaking and verify no score/reason text calls the result a probability.

- [ ] **Step 5: Verify RED**

```bash
python -m pytest \
  tests/unit/test_runtime_trace_diff.py \
  tests/unit/test_runtime_trace_ranking.py -v
```

Expected: missing differential/ranking types/logic.

- [ ] **Step 6: Implement raw -> function -> ranking pipeline**

Build immutable intermediate maps keyed only by canonical identities; sort only at report construction. Avoid querying static data once per event when the same address repeats: cache `TraceEventCorrelation` by `(pc, instruction_set)` per project/comparison.

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

Capture selectors:

```text
--steps N
--break ADDRESS --events N
--watch-read ADDRESS --length N --events N
--watch-write ADDRESS --length N --events N
--watch-access ADDRESS --length N --events N
```

Other capture options:

```text
--memory ADDRESS:LENGTH   repeatable
--project PATH
--label TEXT
--timeout SECONDS
--cpu arm9|arm7
--host HOST
--port PORT
```

Capture success writes `.ndstrace` to `--output` and always emits one deterministic JSON summary to stdout with exactly these top-level keys:

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

`terminated_by` is `limit` or `target_exit`.

Inspect/diff without `--output` write deterministic JSON stdout. With `--output`, reuse the existing `_write_json()` atomic text replacement behavior.

**Critical dispatch refactor:** `runtime trace inspect` and `runtime diff` are offline and must never call `_connect()`. `runtime trace capture` plus the five existing 7H1 live commands use `_connect()`.

Recommended dispatch skeleton:

```python
def run_runtime_command(arguments: argparse.Namespace) -> int:
    command = arguments.runtime_command
    if command == "trace" and arguments.trace_command == "inspect":
        return _run_trace_inspect(arguments)
    if command == "diff":
        return _run_trace_diff(arguments)
    if command == "trace" and arguments.trace_command == "capture":
        with _connect(arguments) as session:
            return _run_trace_capture(session, arguments)
    with _connect(arguments) as session:
        return _run_existing_live_command(session, arguments)
```

Capture with `--project` opens the project read-only before tracing, computes only `analysis_project_fingerprint()`, closes the project, and stores the digest in config. It does not persist copied static correlation.

Memory parser accepts `ADDRESS:LENGTH`, assigns region ordinals in CLI order, and applies the same model bounds before connecting.

- [ ] **Step 1: Write RED parser tests**

Assert valid nested commands, selector exclusivity, step/event mismatch, bounds (`100001` steps, `10001` events, 33 regions, oversized total), timeout/length validation, and preservation of old `runtime step --count 257` rejection.

- [ ] **Step 2: Write RED offline-dispatch tests**

Monkeypatch `_connect` to raise if called; run `runtime trace inspect` and `runtime diff` over fixture traces and assert they succeed without connection attempts.

- [ ] **Step 3: Write RED capture CLI behavior test**

Monkeypatch `MelonDSSession.connect` to the existing/focused fake session. Assert destination is a valid SQLite trace, summary stdout has exact keys, project opens read-only for fingerprinting, and `--output` is never treated as a JSON report path for capture.

- [ ] **Step 4: Write RED deterministic inspect/diff JSON tests**

Require canonical lowercase addresses, sorted keys, deterministic arrays, explicit `target_identity_verified`, ambiguity details, memory change bytes/16/32-bit values, function evidence, weights/contributions/reasons, and no probability terminology.

- [ ] **Step 5: Verify RED**

```bash
python -m pytest tests/unit/test_runtime_cli.py -v
```

Expected: parser/dispatch failures for new commands.

- [ ] **Step 6: Implement CLI parser, serializers, and online/offline dispatch**

Keep raw report-to-JSON conversion in `runtime_cli.py`; core trace modules remain presentation-neutral. Use existing `_hex()` and `_write_json()` conventions.

- [ ] **Step 7: Add real-file integration workflow test**

`tests/integration/test_runtime_trace_workflow.py` should:

1. create a real `.ndsre` project fixture with component/function/CFG/xref data;
2. capture two real temporary `.ndstrace` SQLite files through `capture_trace()` using deterministic fake sessions;
3. include memory BEFORE/AFTER change in target;
4. inspect one trace with the project;
5. compare baseline vs target with the project;
6. verify fingerprint match, target-only function ranking, changed-memory static reference, and no mutation of either input file.

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
nds->ARM9Write32(base + 0x14, observed);   // literal
nds->ARM9Write32(observed, 0);
```

Keep `args.JIT=std::nullopt`, ARM9 GDB enabled, ARM7 disabled for this harness, and `ARM9BreakOnStartup=true`.

**CI live gate:** retain the current stock melonDS pin `906e9ebb27da8c6a715cd7abab4abfe8a8d29427` and core build flags:

```text
-DENABLE_JIT=OFF
-DENABLE_GDBSTUB=ON
-DENABLE_OGLRENDERER=OFF
-DBUILD_QT_SDL=OFF
```

Extend the existing `phase-7h-live-smoke` job in `.github/workflows/ci.yml`; do not create a second stock-melonDS build job. Preserve the old `probe`, `snapshot`, `read-memory`, `run-until`, and interactive `step` assertions, updating expected instruction bytes/registers for the new harness.

Then add exact CLI smoke runs, restarting the target between independent captures:

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
- step trace is complete with five evidence events;
- `0x02000100:4` has BEFORE zero and a non-empty AFTER differential;
- repeated breakpoint trace has two EVIDENCE events and exactly one CONTROL_ADVANCE between them, proving no immediate-retrigger loop;
- watch trace has real WATCHPOINT stop evidence and a non-zero stop PC;
- inspect reports the changed memory region.

For live static diff, create a small synthetic `.ndsre` project in the workflow via the public Python `AnalysisProject` API. The component covers the harness address range and contains deterministic function/CFG records sufficient for `functions_containing()` to correlate the selected breakpoint PCs. Capture baseline and target traces with the same `--project` so fingerprints match, for example baseline repeated breakpoint at `0x0200000c` and target repeated breakpoint at `0x02000008`. Then:

```bash
nds-toolkit runtime diff \
  /tmp/baseline.ndstrace \
  /tmp/target.ndstrace \
  --project /tmp/live.ndsre > /tmp/diff.json
```

Assert target identity verified and the known target-only function/address ranks above baseline-only/shared evidence.

After the consolidated `ci.yml` live job proves old and new paths, delete the stale branch-specific `.github/workflows/phase-7h-live-smoke.yml` so there is one authoritative live regression workflow.

**Documentation:**
- expand `docs/runtime-debugging.md` with `.ndstrace`, capture/inspect/diff examples, bounds, evidence/control distinction, memory semantics, fingerprint rules, overlay ambiguity, transparent ranking, and failure atomicity;
- replace the stale sentence claiming stock-melonDS validation is manual-only: current CI now builds/runs a headless stock core and exercises the exact CLI;
- add runtime tracing/differentials to README capabilities and link `docs/runtime-debugging.md` in workflow docs;
- update provenance to state Phase 7H1/7H2 use the external standard GDB interface, standard-library SQLite trace persistence, no melonDS source incorporation, no melonDS runtime Python dependency, and no `.ndsre` schema migration.

- [ ] **Step 1: Update live harness and add 7H2 smoke commands/assertions**

Run the workflow-equivalent commands locally when environment permits; regardless, unit/integration tests must cover every assertion independent of the external build.

- [ ] **Step 2: Update user-facing docs/provenance and delete stale workflow**

Check command examples exactly match parser syntax introduced in Task 8.

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
- git diff does not modify pyproject.toml dependency declarations
- git diff does not modify analysis/project/schema.py
- SCHEMA_VERSION == 1 and ANALYSIS_MODEL_VERSION == 1
- no melonDS source is copied beneath src/
- no game/Bakugan-specific address, rule, label, or semantic policy exists in toolkit runtime code
- no unbounded trace loop exists
- every repeated break/watch cycle stores CONTROL_ADVANCE and excludes it from default behavior frequencies
- completed .ndstrace requires valid integrity check and complete configured memory pairs
- offline inspect/diff never open a debugger connection
- ranking output exposes feature values, weights, contributions, and reasons and never calls score a probability
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

Create the PR with `draft=false` because the current GitHub connector cannot reliably transition a draft PR to ready-for-review. Record the exact branch HEAD SHA, and do not merge unless both jobs are green for that exact SHA:

```text
verify
phase-7h-live-smoke
```

If the branch moves, re-check the new exact head before merge.

- [ ] **Step 8: Merge with expected-head protection and verify `main` again**

Use squash merge with `expected_head_sha=<verified exact PR head>`. Then require a `main` CI run whose head is the exact squash commit and whose `verify` and `phase-7h-live-smoke` jobs both succeed before declaring Phase 7H2 complete.

---

## Definition of Done

Phase 7H2 is complete only when all of the following are true:

1. `.ndstrace` schema version 1 can atomically persist/reopen bounded runtime events and configured memory snapshots.
2. Failed captures cannot replace an existing valid trace with partial output.
3. Step, repeated breakpoint, and repeated read/write/access watchpoint captures are finite and tested.
4. Repeated break/watch collection persists auditable CONTROL_ADVANCE events and does not loop on the same armed stop condition.
5. Memory BEFORE/AFTER reports deterministic raw changed spans plus bounded aligned 16/32-bit convenience values.
6. Exact static-project fingerprints follow the approved canonical JSON/SHA-256 contract.
7. `.ndsre` remains schema/model version 1; only the approved read-only query helpers were added.
8. Trace PCs inside persisted CFG functions can be correlated without pretending overlapping overlays are resolved.
9. Offline inspect reports evidence/control counts, address frequency, memory changes, and optional static correlation.
10. Diff compares only EVIDENCE events, normalizes unequal trace lengths, enforces known fingerprint mismatches, and explicitly reports unverified identity when fingerprints are absent.
11. Function aggregation excludes ambiguous ownership and memory-xref wording does not claim a static reference is a proven runtime write.
12. Function ranking uses exactly the approved weights/features, emits every evidence contribution, and is never labeled a probability.
13. CLI capture/inspect/diff contracts and exit-code boundaries are deterministic and integration-tested.
14. The consolidated stock-melonDS CI gate proves multi-step trace, repeated breakpoint/control advance, real watchpoint stop, memory mutation, inspect, and behavior diff/ranking on the exact PR head.
15. Full pytest, Ruff, strict mypy, exact-head PR CI, and exact post-merge `main` CI all pass.
