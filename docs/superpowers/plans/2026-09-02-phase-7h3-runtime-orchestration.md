# Phase 7H3 Runtime Orchestration and Deterministic Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add game-neutral managed emulator orchestration so Nintendo DS runtime experiments can be diagnosed, launched, checkpointed, driven with normalized DS input, guarded by debugger-visible state, resumed after interruption, and executed as deterministic acceptance matrices.

**Architecture:** Keep the existing Phase 7H1/7H2 runtime core intact: `analysis/runtime/rsp.py` remains the only RSP packet transport and existing attach-only commands remain valid. Add a sibling `analysis/orchestration/` package for process/display ownership, emulator backends, checkpoints, predicates, scenarios, evidence, recovery, and matrix execution; add only the minimum runtime extensions needed for DeSmuME dialect handling and standard RSP memory writes. Managed state uses independent versioned JSON files/directories and never changes `.ndsre` or `.ndstrace` schemas.

**Tech Stack:** Python 3.11+, standard-library `subprocess`, `os`, `signal`, `socket`, `json`, `hashlib`, `secrets`, `time`, `pathlib`, existing `RSPClient`/runtime trace APIs, argparse, pytest, Ruff, strict mypy; Linux/X11 uses external `Xvfb` and `xdotool` discovered by `runtime doctor`. No new Python runtime dependency.

**Spec:** `docs/superpowers/specs/2026-09-02-phase-7h3-runtime-orchestration-design.md`

## Global Constraints

- Start from `phase-7h3-runtime-orchestration`, based on verified `main` commit `a19d8eb7c3e65ed2f57bd0c3d47dff6353273cf9`.
- `src/nds_disassembly_toolkit/analysis/runtime/rsp.py` remains the only GDB RSP transport implementation.
- DeSmuME support reuses `RSPClient`; do not add another socket protocol client or shell out to `gdb`.
- Preserve the current `MelonDSSession` initial-ACK behavior and attach-only defaults.
- Do not modify `.ndsre` schema version 1 or `.ndstrace` schema version 1.
- Orchestration persistence is independent JSON schema version 1 for session, checkpoint, scenario, journal/result, and matrix records.
- No new Python runtime dependency and no dependency changes in `pyproject.toml`.
- Linux/X11 is the only managed UI host in Phase 7H3; macOS/Windows drivers remain outside this phase.
- `Xvfb` and `xdotool` are optional external helpers and must be detected before a UI-dependent managed scenario starts.
- Public touch coordinates are Nintendo DS touchscreen coordinates: `x=0..255`, `y=0..191`.
- Public button input uses DS controls, never consumer-supplied host key names.
- Input is sent only to a window positively associated with the owned emulator process.
- Managed launches explicitly construct environment variables; ambient `SDL_VIDEODRIVER=dummy` must not silently win over an interactive X11 launch.
- Managed sessions use unique session directories and dynamically allocated loopback debugger ports.
- Cleanup never signals a process until persisted PID, process-start identity, and executable identity prove ownership on Linux.
- Scenario files are versioned JSON, never arbitrary executable scripts and never shell-command containers.
- All waits use monotonic time, finite timeouts, finite polling intervals, and retain the last observation on failure.
- Memory mutation is explicit, bounded, optionally compare-before guarded, and read-back verified by default.
- A `STARTED` but not `COMPLETED` non-idempotent step is never silently considered complete on resume.
- Every acceptance case restores and verifies the same baseline checkpoint before case-specific mutation/input.
- Failure evidence collection is best-effort and must never replace the original failure as the primary error.
- No Bakugan names, addresses, Gate semantics, archetype labels, or other game-specific policy enters the toolkit.
- Existing `runtime probe`, `snapshot`, `read-memory`, `run-until`, `step`, `trace capture`, `trace inspect`, and `diff` behavior remains backward compatible.
- Every implementation task follows RED -> minimal GREEN -> focused regression -> commit.
- Final proof requires full pytest, Ruff, strict mypy, preserved stock-melonDS live interoperability, new managed-launch/X11 integration coverage, scope audit, expected-head merge protection, and fresh post-merge `main` CI.

## File Map

Create:

```text
src/nds_disassembly_toolkit/analysis/runtime/desmume.py
src/nds_disassembly_toolkit/analysis/orchestration/__init__.py
src/nds_disassembly_toolkit/analysis/orchestration/model.py
src/nds_disassembly_toolkit/analysis/orchestration/backend.py
src/nds_disassembly_toolkit/analysis/orchestration/melonds_backend.py
src/nds_disassembly_toolkit/analysis/orchestration/desmume_backend.py
src/nds_disassembly_toolkit/analysis/orchestration/process.py
src/nds_disassembly_toolkit/analysis/orchestration/host.py
src/nds_disassembly_toolkit/analysis/orchestration/x11.py
src/nds_disassembly_toolkit/analysis/orchestration/input.py
src/nds_disassembly_toolkit/analysis/orchestration/checkpoint.py
src/nds_disassembly_toolkit/analysis/orchestration/predicates.py
src/nds_disassembly_toolkit/analysis/orchestration/scenario.py
src/nds_disassembly_toolkit/analysis/orchestration/acceptance.py
src/nds_disassembly_toolkit/analysis/orchestration/evidence.py
src/nds_disassembly_toolkit/analysis/orchestration/doctor.py

tests/unit/test_orchestration_model.py
tests/unit/test_orchestration_process.py
tests/unit/test_runtime_desmume.py
tests/unit/test_orchestration_backends.py
tests/unit/test_orchestration_doctor.py
tests/unit/test_orchestration_x11.py
tests/unit/test_orchestration_input.py
tests/unit/test_orchestration_checkpoint.py
tests/unit/test_orchestration_predicates.py
tests/unit/test_orchestration_scenario_model.py
tests/unit/test_orchestration_scenario.py
tests/unit/test_orchestration_recovery.py
tests/unit/test_orchestration_acceptance.py
tests/integration/test_runtime_orchestration_workflow.py
```

Modify:

```text
src/nds_disassembly_toolkit/errors.py
src/nds_disassembly_toolkit/analysis/runtime/rsp.py
src/nds_disassembly_toolkit/analysis/runtime/melonds.py
src/nds_disassembly_toolkit/analysis/runtime/__init__.py
src/nds_disassembly_toolkit/analysis/runtime_cli.py

tests/unit/test_runtime_rsp.py
tests/unit/test_runtime_melonds.py
tests/unit/test_runtime_exports.py
tests/unit/test_runtime_cli.py

docs/runtime-debugging.md
docs/provenance-and-licenses.md
README.md
.github/workflows/ci.yml
```

---

## Phase 7H3A — Managed Emulator Lifecycle and Diagnostics

### Task 1: Orchestration models, capabilities, and error boundary

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/__init__.py`
- Modify: `src/nds_disassembly_toolkit/errors.py`
- Test: `tests/unit/test_orchestration_model.py`

**Interfaces:**
- Produces `SESSION_SCHEMA_VERSION = 1`, `CHECKPOINT_SCHEMA_VERSION = 1`, `SCENARIO_SCHEMA_VERSION = 1`, `JOURNAL_SCHEMA_VERSION = 1`, `MATRIX_SCHEMA_VERSION = 1`.
- Produces `EmulatorKind(MELONDS, DESMUME)`, `DebuggerHandshakeMode(INITIAL_ACK, DIRECT)`, `RuntimeLifecycleState`, `EmulatorCapabilities`, `LaunchSpec`, `ProcessIdentity`, `RuntimeSessionRecord`, and `DoctorCheckResult`.
- Produces orchestration errors rooted at `RuntimeOrchestrationError(RuntimeAnalysisError)` with the exact subclasses from the design.

- [ ] **Step 1: Write failing model/error tests.** The test must prove immutable records, enum values, positive debugger port validation, session-id non-empty validation, and the full error inheritance chain.

```python
def test_session_record_requires_valid_loopback_port(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="debugger port"):
        RuntimeSessionRecord(
            schema_version=1,
            session_id="session-a",
            lifecycle=RuntimeLifecycleState.CREATED,
            emulator=EmulatorKind.DESMUME,
            emulator_executable=tmp_path / "desmume",
            emulator_sha256=None,
            emulator_version=None,
            rom_path=tmp_path / "game.nds",
            rom_sha256="0" * 64,
            cpu=RuntimeCpu.ARM9,
            pid=None,
            process_group=None,
            process_start_identity=None,
            debugger_host="127.0.0.1",
            debugger_port=0,
            display=None,
            window_id=None,
            session_root=tmp_path,
            last_completed_step=None,
            last_completed_case=None,
        )
```

- [ ] **Step 2: Run focused tests and verify RED.**

```bash
python -m pytest tests/unit/test_orchestration_model.py -v
```

Expected: import failure because `analysis.orchestration` does not exist.

- [ ] **Step 3: Implement the immutable records and errors.** Use `@dataclass(frozen=True, slots=True)` and `StrEnum`; validate SHA-256 strings as 64 lowercase hex characters and validate ports as `1..65535`.
- [ ] **Step 4: Export the stable orchestration model surface from `analysis/orchestration/__init__.py` and run focused tests.**

```bash
python -m pytest tests/unit/test_orchestration_model.py tests/unit/test_runtime_exports.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add src/nds_disassembly_toolkit/errors.py src/nds_disassembly_toolkit/analysis/orchestration tests/unit/test_orchestration_model.py
git commit -m "feat: define runtime orchestration models"
```

### Task 2: Managed session directory, process ownership, and dynamic port allocation

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/process.py`
- Test: `tests/unit/test_orchestration_process.py`
- Test: `tests/integration/test_runtime_orchestration_workflow.py`

**Interfaces:**
- Produces `create_session(root: Path, *, emulator, executable, rom, cpu, debugger_host="127.0.0.1") -> RuntimeSessionRecord`.
- Produces `load_session(path: Path) -> RuntimeSessionRecord`, `store_session(record) -> None`, `spawn_owned_process(record, launch: LaunchSpec) -> RuntimeSessionRecord`, `process_is_owned(record) -> bool`, `stop_owned_process(record, *, grace_seconds: float = 3.0) -> RuntimeSessionRecord`.
- Produces `allocate_loopback_port(host: str = "127.0.0.1") -> int`.
- Linux start identity is `/proc/<pid>/stat` field 22 plus the resolved `/proc/<pid>/exe` fingerprint; a PID match without those checks is insufficient.

- [ ] **Step 1: Write RED tests** for unique 32-hex session ids, required directory layout, atomic `session.json`, free loopback port allocation, `start_new_session=True`, stdout/stderr redirection, PID-reuse refusal, executable mismatch refusal, graceful process-group termination, and unrelated-process survival.
- [ ] **Step 2: Run the unit contract.**

```bash
python -m pytest tests/unit/test_orchestration_process.py -v
```

Expected: RED for missing process/session operations.

- [ ] **Step 3: Implement atomic session persistence.** Render JSON with `indent=2`, `sort_keys=True`, newline termination; write `session.json.tmp` then `replace()`.
- [ ] **Step 4: Implement process spawning and ownership proof.** Pass `LaunchSpec.argv` directly to `subprocess.Popen`; never use `shell=True`. Create `emulator.stdout.log` and `emulator.stderr.log` under the session root.
- [ ] **Step 5: Implement bounded cleanup.** Send `SIGTERM` to the owned process group, wait up to `grace_seconds`, then `SIGKILL` only if ownership still validates and the group remains alive.
- [ ] **Step 6: Add subprocess integration coverage** with one owned Python sleeper and one unrelated sleeper; stopping the session must terminate only the owned process group.
- [ ] **Step 7: Run focused and integration tests.**

```bash
python -m pytest tests/unit/test_orchestration_process.py tests/integration/test_runtime_orchestration_workflow.py -v
```

Expected: PASS.

- [ ] **Step 8: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/orchestration/process.py tests/unit/test_orchestration_process.py tests/integration/test_runtime_orchestration_workflow.py
git commit -m "feat: own managed emulator processes"
```

### Task 3: Emulator backend protocol and DeSmuME RSP dialect adapter

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/backend.py`
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/melonds_backend.py`
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/desmume_backend.py`
- Create: `src/nds_disassembly_toolkit/analysis/runtime/desmume.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/__init__.py`
- Test: `tests/unit/test_orchestration_backends.py`
- Test: `tests/unit/test_runtime_desmume.py`
- Test: `tests/unit/test_runtime_exports.py`

**Interfaces:**
- `EmulatorBackend` exposes `kind`, `capabilities`, `build_launch_spec()`, `connect_debugger()`, `capture_backend_metadata()`, `locate_battery_save()`, `save_state()`, `load_state()`, and `request_graceful_shutdown()`.
- `MelonDSBackend.connect_debugger()` delegates to existing `MelonDSSession.connect()`.
- `DeSmuMESession.connect()` uses `RSPClient.connect()` then `negotiate()` **without** calling `initial_ack_handshake()`.
- `DeSmuMESession` exposes the same snapshot/read/breakpoint/step/interrupt/close surface used by existing runtime orchestration and reuses the validated ARM register decoding contract; any live register-layout incompatibility is a hard live-gate failure, not silently guessed.

- [ ] **Step 1: Write RED DeSmuME tests** proving direct negotiation, cleanup on negotiation failure, ARM9/ARM7 explicit port handling, snapshot decoding, and reuse of `RSPClient` rather than a second transport.

```python
def test_desmume_connect_skips_initial_ack(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeRSPClient()
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.runtime.desmume.RSPClient.connect",
        lambda host, port, *, timeout=5.0: client,
    )
    DeSmuMESession.connect(cpu=RuntimeCpu.ARM9, port=39001)
    assert ("initial_ack_handshake",) not in client.calls
    assert client.calls[0] == ("negotiate",)
```

- [ ] **Step 2: Run focused tests and verify RED.**

```bash
python -m pytest tests/unit/test_runtime_desmume.py tests/unit/test_orchestration_backends.py -v
```

- [ ] **Step 3: Implement `DeSmuMESession` using the existing `RSPClient`.** Extract only genuinely shared session helpers from `melonds.py` if required; do not create a new packet/framing layer.
- [ ] **Step 4: Implement explicit backend capabilities.** Mark capabilities based on what each managed backend actually supports; unsupported save/input capabilities must be `False`, not optimistic defaults.
- [ ] **Step 5: Add launch specs.** Managed launch specs must explicitly set loopback GDB port, isolated config/save root, ROM path, and display-related environment without shell interpolation.
- [ ] **Step 6: Run runtime regression tests.**

```bash
python -m pytest tests/unit/test_runtime_melonds.py tests/unit/test_runtime_desmume.py tests/unit/test_runtime_rsp.py tests/unit/test_runtime_exports.py -v
```

Expected: PASS, including unchanged melonDS initial-ACK assertions.

- [ ] **Step 7: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/runtime src/nds_disassembly_toolkit/analysis/orchestration/backend.py src/nds_disassembly_toolkit/analysis/orchestration/melonds_backend.py src/nds_disassembly_toolkit/analysis/orchestration/desmume_backend.py tests/unit/test_runtime_desmume.py tests/unit/test_orchestration_backends.py tests/unit/test_runtime_exports.py
git commit -m "feat: add emulator runtime backends"
```

### Task 4: Linux display lease, `runtime doctor`, launch/info/stop CLI, and managed-launch smoke

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/host.py`
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/x11.py`
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/doctor.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime_cli.py`
- Test: `tests/unit/test_orchestration_x11.py`
- Test: `tests/unit/test_orchestration_doctor.py`
- Test: `tests/unit/test_runtime_cli.py`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- `HostAutomationDriver` defines display/window/input/capture operations; Task 4 implements display start/stop and window discovery primitives, while Task 5 completes input methods.
- `X11DisplayLease` owns an Xvfb PID/process identity and `DISPLAY` string.
- `run_doctor(backend, *, rom: Path | None, require: frozenset[str], destructive: bool = False) -> DoctorReport`.
- CLI adds `runtime doctor`, `runtime launch`, `runtime session info`, `runtime session stop`.

- [ ] **Step 1: Write RED X11 tests** proving unique display selection, owned Xvfb cleanup, inherited `SDL_VIDEODRIVER=dummy` removal/override, helper discovery, and no signal to an unowned display process.
- [ ] **Step 2: Write RED doctor/CLI tests.** Basic doctor must not call write-memory/save-state methods. Missing `Xvfb` or `xdotool` must produce a structured failed check before launch when the requested capability requires it.
- [ ] **Step 3: Implement `X11DisplayLease`.** Launch `Xvfb :N -screen 0 1024x768x24 -nolisten tcp` with an owned process group and persist its identity in the session.
- [ ] **Step 4: Implement doctor checks.** Order checks deterministically: executable, version, host helpers, display viability, debugger capability, optional window/input/checkpoint capability. Report every requested check; do not stop at the first ordinary failed capability.
- [ ] **Step 5: Add CLI parser/dispatch.** `runtime launch` requires ROM, emulator, CPU, session-root; `session info/stop` require a session directory. All JSON output uses the existing canonical writer.
- [ ] **Step 6: Add managed melonDS live smoke to CI** without removing the current attach-only 7H1/7H2 smoke. The managed layer must prove unique session root, owned process, dynamic port, debugger readiness, snapshot, and clean stop against the existing deterministic ARM9 target.
- [ ] **Step 7: Add a pinned DeSmuME source/reference setup to CI using upstream `release_0_9_13`.** Build/enable the Linux GDB-capable frontend, launch it under owned Xvfb with a disposable test target, and verify direct RSP negotiation. If this upstream release cannot provide a deterministic capability, record that capability as unsupported and keep the gate limited to behavior the executable genuinely provides.
- [ ] **Step 8: Run Phase 7H3A gate.**

```bash
python -m pytest \
  tests/unit/test_orchestration_model.py \
  tests/unit/test_orchestration_process.py \
  tests/unit/test_runtime_desmume.py \
  tests/unit/test_orchestration_backends.py \
  tests/unit/test_orchestration_x11.py \
  tests/unit/test_orchestration_doctor.py \
  tests/unit/test_runtime_cli.py \
  tests/integration/test_runtime_orchestration_workflow.py -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 9: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/orchestration src/nds_disassembly_toolkit/analysis/runtime_cli.py tests/unit/test_orchestration_x11.py tests/unit/test_orchestration_doctor.py tests/unit/test_runtime_cli.py .github/workflows/ci.yml
git commit -m "feat: manage emulator lifecycle and diagnostics"
```

---

## Phase 7H3B — Checkpoints and Normalized DS Input

### Task 5: DS controls, deterministic layout profiles, and owned-window X11 input

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/orchestration/host.py`
- Modify: `src/nds_disassembly_toolkit/analysis/orchestration/x11.py`
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/input.py`
- Modify: backend files from Task 3
- Test: `tests/unit/test_orchestration_input.py`
- Test: `tests/unit/test_orchestration_x11.py`

**Interfaces:**
- Produces `DSButton`, `DSPoint`, `TouchTap`, `TouchDrag`, `TouchFlick`, `WindowGeometry`, `ScreenViewport`, `ScreenLayoutProfile`.
- `DSPoint` validates `0 <= x <= 255`, `0 <= y <= 191`.
- `map_touch_point(point, viewport) -> tuple[int, int]` maps DS coordinates into the verified lower-screen viewport using integer rounding that keeps both endpoints inside the viewport.
- Backend owns `host_key_for(button: DSButton) -> str`; consumers never supply host keys.

- [ ] **Step 1: Write RED coordinate/control tests.** Cover all 12 DS buttons, invalid coordinates, native 256x192 mapping, 2x scaled mapping, non-zero viewport origin, and deterministic endpoint mapping.

```python
def test_native_touch_mapping_is_identity_inside_lower_viewport() -> None:
    viewport = ScreenViewport(x=0, y=192, width=256, height=192)
    assert map_touch_point(DSPoint(0, 0), viewport) == (0, 192)
    assert map_touch_point(DSPoint(255, 191), viewport) == (255, 383)
```

- [ ] **Step 2: Write RED owned-window tests.** `send_key`, pointer movement, and capture must reject a window whose PID no longer matches the session's owned emulator.
- [ ] **Step 3: Implement models and geometry transform.** Unknown rotation, unsupported separated screens, or inconsistent geometry raises `RuntimeInputError`; do not guess.
- [ ] **Step 4: Implement X11 input using argument arrays.** Use `xdotool key --window`, `mousemove --window`, `mousedown 1`, `mouseup 1`; no shell strings.
- [ ] **Step 5: Implement deterministic backend layout/key profiles** for the supported managed configurations and expose capability failure when a backend cannot guarantee layout/key mapping.
- [ ] **Step 6: Run tests.**

```bash
python -m pytest tests/unit/test_orchestration_input.py tests/unit/test_orchestration_x11.py tests/unit/test_orchestration_backends.py -v
```

- [ ] **Step 7: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/orchestration tests/unit/test_orchestration_input.py tests/unit/test_orchestration_x11.py tests/unit/test_orchestration_backends.py
git commit -m "feat: add normalized Nintendo DS input"
```

### Task 6: Versioned checkpoint bundles and restore verification

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/checkpoint.py`
- Modify: `src/nds_disassembly_toolkit/analysis/orchestration/model.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime_cli.py`
- Test: `tests/unit/test_orchestration_checkpoint.py`
- Test: `tests/unit/test_runtime_cli.py`

**Interfaces:**
- Produces `CheckpointMetadata`, `CheckpointMemoryFingerprint`, `create_checkpoint(context, name, *, verification_regions=()) -> Path`, `validate_checkpoint(path, context) -> CheckpointMetadata`, `restore_checkpoint(context, path, *, predicates=()) -> None`.
- Checkpoint directory contains `checkpoint.json`, opaque `state.bin`, optional `battery-save.bin`, and optional `evidence.json`.
- Exact ROM SHA-256 and emulator-kind match are mandatory before restore.

- [ ] **Step 1: Write RED metadata/hash tests.** Validate wrong ROM, wrong emulator, changed state hash, changed battery-save hash, unsupported schema, and path traversal in checkpoint filenames.
- [ ] **Step 2: Write RED restore tests** using a fake backend: backend `load_state()` returning normally is not success until configured verification predicates pass.
- [ ] **Step 3: Implement atomic checkpoint creation.** Write into a sibling temporary directory, hash every opaque state/save file, write metadata last, then atomically rename the directory.
- [ ] **Step 4: Implement compatibility validation and restore.** Never convert cross-emulator states. Copy isolated battery save only after all compatibility checks pass.
- [ ] **Step 5: Add CLI `runtime checkpoint save` and `runtime checkpoint restore`.** Both operate on an existing managed session directory and return deterministic JSON metadata.
- [ ] **Step 6: Run Phase 7H3B gate.**

```bash
python -m pytest tests/unit/test_orchestration_input.py tests/unit/test_orchestration_x11.py tests/unit/test_orchestration_checkpoint.py tests/unit/test_runtime_cli.py -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 7: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/orchestration/checkpoint.py src/nds_disassembly_toolkit/analysis/orchestration/model.py src/nds_disassembly_toolkit/analysis/runtime_cli.py tests/unit/test_orchestration_checkpoint.py tests/unit/test_runtime_cli.py
git commit -m "feat: add validated runtime checkpoints"
```

---

## Phase 7H3C — Guarded Mutation and Scenario Runner

### Task 7: Standard RSP memory writes through the existing transport

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/rsp.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/melonds.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/desmume.py`
- Test: `tests/unit/test_runtime_rsp.py`
- Test: `tests/unit/test_runtime_melonds.py`
- Test: `tests/unit/test_runtime_desmume.py`

**Interfaces:**
- Adds `RSPClient.write_memory(address: int, data: bytes) -> None` using standard `MADDR,LENGTH:HEX` packets.
- Adds `write_memory()` to runtime session protocols/adapters.
- Writes are chunked to the existing `_MEMORY_CHUNK_SIZE`; empty bytes perform no RSP command.

- [ ] **Step 1: Write RED RSP tests.** Assert exact command payload, chunk splitting, negative-address rejection, peer non-`OK` rejection, and zero-length no-op.

```python
def test_write_memory_uses_standard_rsp_packet() -> None:
    sock = FakeSocket([b"+", _packet("OK")])
    client = RSPClient(sock)
    client.write_memory(0x02000100, b"\x01\xab")
    assert sock.sent[0] == RSPClient._frame("M2000100,2:01ab")
```

- [ ] **Step 2: Run tests and verify RED.**

```bash
python -m pytest tests/unit/test_runtime_rsp.py::test_write_memory_uses_standard_rsp_packet -v
```

- [ ] **Step 3: Implement bounded write support in `RSPClient`; do not alter framing/negotiation code.**
- [ ] **Step 4: Expose session `write_memory()` delegation from melonDS and DeSmuME adapters.**
- [ ] **Step 5: Run runtime regression tests.**

```bash
python -m pytest tests/unit/test_runtime_rsp.py tests/unit/test_runtime_melonds.py tests/unit/test_runtime_desmume.py tests/unit/test_runtime_capture.py -v
```

Expected: PASS; existing trace capture remains unchanged.

- [ ] **Step 6: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/runtime tests/unit/test_runtime_rsp.py tests/unit/test_runtime_melonds.py tests/unit/test_runtime_desmume.py
git commit -m "feat: add bounded runtime memory writes"
```

### Task 8: Generic runtime predicates and guarded memory mutation

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/predicates.py`
- Modify: `src/nds_disassembly_toolkit/analysis/orchestration/model.py`
- Test: `tests/unit/test_orchestration_predicates.py`

**Interfaces:**
- Produces predicate records `ProcessAlive`, `DebuggerReachable`, `WindowReady`, `PcEquals`, `PcInRange`, `RegisterEquals`, `MemoryEquals`, `MemoryMaskedEquals`, `AllOf`, `AnyOf`.
- Produces `PredicateObservation(satisfied: bool, description: str, observed: object)` and `wait_for_predicate(predicate, context, *, timeout, poll_interval, monotonic=time.monotonic, sleep=time.sleep)`.
- Produces `RuntimeMemoryWrite(address, replacement, expected_before=None, verify_after=True)` and `apply_guarded_write(session, write) -> GuardedWriteEvidence`.

- [ ] **Step 1: Write RED predicate tests.** Cover exact PC, PC range endpoints, register missing/value mismatch, memory exact/masked values, `AllOf`, `AnyOf`, timeout with last observation, and finite polling.
- [ ] **Step 2: Write RED guarded-write tests.** Expected-before mismatch must issue zero writes; successful write must read-before/write/read-after; failed read-back raises `RuntimeScenarioError`.
- [ ] **Step 3: Implement predicate evaluation without image/OCR logic.** Reuse `RuntimeSnapshot`, `read_memory`, owned-process checks, and host window verification.
- [ ] **Step 4: Implement monotonic bounded waits.** Error message includes predicate description plus last observed state.
- [ ] **Step 5: Implement guarded mutation and immutable evidence hashes/bytes.**
- [ ] **Step 6: Run focused tests.**

```bash
python -m pytest tests/unit/test_orchestration_predicates.py tests/unit/test_runtime_rsp.py -v
```

- [ ] **Step 7: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/orchestration/model.py src/nds_disassembly_toolkit/analysis/orchestration/predicates.py tests/unit/test_orchestration_predicates.py
git commit -m "feat: add guarded runtime state predicates"
```

### Task 9: Versioned scenario parsing and durable journal

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/scenario.py`
- Modify: `src/nds_disassembly_toolkit/analysis/orchestration/model.py`
- Test: `tests/unit/test_orchestration_scenario_model.py`

**Interfaces:**
- Produces `ScenarioDefinition`, typed scenario step records, `ScenarioJournal`, `JournalStepState(PENDING, STARTED, COMPLETED, FAILED)`, `load_scenario(path)`, `load_journal(path)`, and `store_journal(path, journal)`.
- Supported step types are exactly: `wait`, `button`, `button_sequence`, `touch_tap`, `touch_drag`, `touch_flick`, `memory_write`, `capture_snapshot`, `capture_trace`, `assert`, `checkpoint_save`, `checkpoint_restore`.
- Omitted ids normalize deterministically to `step-0000`, `step-0001`, and so on.

- [ ] **Step 1: Write RED parser tests** using the approved JSON shape from the design. Reject unknown schema versions, unknown step types, arbitrary command/script keys, invalid DS coordinates, invalid hex byte strings, negative/zero timeouts, and duplicate explicit step ids.
- [ ] **Step 2: Write RED journal tests.** Atomic writer must preserve the previous valid journal if replacement fails; `STARTED` and `COMPLETED` must be distinct persisted states.
- [ ] **Step 3: Implement strict JSON parsing into immutable records.** No YAML parser and no generic string interpolation.
- [ ] **Step 4: Implement canonical JSON serialization and atomic journal writes.**
- [ ] **Step 5: Run focused tests.**

```bash
python -m pytest tests/unit/test_orchestration_scenario_model.py -v
```

- [ ] **Step 6: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/orchestration/model.py src/nds_disassembly_toolkit/analysis/orchestration/scenario.py tests/unit/test_orchestration_scenario_model.py
git commit -m "feat: define journaled runtime scenarios"
```

### Task 10: Scenario execution, trace/snapshot steps, failure bundles, and safe resume

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/orchestration/scenario.py`
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/evidence.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime_cli.py`
- Test: `tests/unit/test_orchestration_scenario.py`
- Test: `tests/unit/test_orchestration_recovery.py`
- Test: `tests/unit/test_runtime_cli.py`
- Test: `tests/integration/test_runtime_orchestration_workflow.py`

**Interfaces:**
- Produces `run_scenario(context, definition, *, journal_path) -> ScenarioResult`.
- Uses existing `capture_trace()` for `capture_trace`; no second trace implementation.
- Produces `collect_failure_bundle(context, *, error, step_id, journal) -> Path`.
- Produces `resume_session(session_root, scenario) -> ScenarioResult` that either adopts a proven-owned live process or relaunches/restores the last safe checkpoint anchor.
- CLI adds `runtime scenario run` and `runtime session resume`.

- [ ] **Step 1: Write RED state-aware action tests.** A false precondition must prevent button/touch/memory mutation; a failed postcondition must mark the step failed and stop later steps.
- [ ] **Step 2: Write RED trace/snapshot tests.** `capture_trace` must invoke the existing Phase 7H2 API with a bounded `TraceCaptureConfig`; snapshot evidence must contain canonical register/PC state.
- [ ] **Step 3: Write RED recovery tests.** A journal containing a non-idempotent `STARTED` step must restore the most recent safe checkpoint and replay from that anchor; it must not skip to the next step.
- [ ] **Step 4: Write RED adoption tests.** Live adoption requires process ownership, matching ROM/emulator metadata, expected debugger dialect, and owned window when UI input remains. Failure of any requirement forces checkpoint relaunch or a `RuntimeRecoveryError`.
- [ ] **Step 5: Implement scenario execution order:** precondition wait -> journal `STARTED` -> action -> postcondition wait/assert -> evidence -> journal `COMPLETED`.
- [ ] **Step 6: Implement failure evidence.** Preserve primary exception and collect secondary diagnostics independently: session/journal copy, process state, snapshot/registers when available, configured memory observations, window capture when available, and already-finalized trace paths.
- [ ] **Step 7: Implement safe resume.** Initial checkpoint restore is always an anchor; `checkpoint_save` becomes an anchor only after the checkpoint is fully finalized and the step is `COMPLETED`.
- [ ] **Step 8: Add CLI dispatch and deterministic JSON result.** Validation and capability checks occur before executing input/mutation.
- [ ] **Step 9: Run Phase 7H3C gate.**

```bash
python -m pytest \
  tests/unit/test_orchestration_predicates.py \
  tests/unit/test_orchestration_scenario_model.py \
  tests/unit/test_orchestration_scenario.py \
  tests/unit/test_orchestration_recovery.py \
  tests/unit/test_runtime_cli.py \
  tests/integration/test_runtime_orchestration_workflow.py \
  tests/unit/test_runtime_*.py -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

- [ ] **Step 10: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/orchestration/scenario.py src/nds_disassembly_toolkit/analysis/orchestration/evidence.py src/nds_disassembly_toolkit/analysis/runtime_cli.py tests/unit/test_orchestration_scenario.py tests/unit/test_orchestration_recovery.py tests/unit/test_runtime_cli.py tests/integration/test_runtime_orchestration_workflow.py
git commit -m "feat: run and resume guarded runtime scenarios"
```

---

## Phase 7H3D — Deterministic Acceptance Matrix

### Task 11: Parameterized acceptance cases, baseline isolation, and resumable matrix results

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/orchestration/acceptance.py`
- Modify: `src/nds_disassembly_toolkit/analysis/orchestration/model.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime_cli.py`
- Test: `tests/unit/test_orchestration_acceptance.py`
- Test: `tests/unit/test_runtime_cli.py`
- Test: `tests/integration/test_runtime_orchestration_workflow.py`

**Interfaces:**
- Produces `AcceptanceMatrix`, `AcceptanceCase`, `AcceptanceCaseResult`, `AcceptanceMatrixResult`, `load_matrix(path)`, `run_acceptance_matrix(context_factory, matrix, scenario) -> AcceptanceMatrixResult`.
- Matrix JSON schema version is 1 and references a scenario path plus ordered cases.
- Parameter substitution is typed and explicit: parameter references may occupy byte-value fields, labels, trace output names, and predicate expected values; arbitrary full-document string templating is forbidden.
- Case order is file order and output preserves it.

- [ ] **Step 1: Write RED matrix-parser tests.** Reject duplicate case ids, missing scenario, unknown parameter reference, unsupported schema, and non-object parameter maps.
- [ ] **Step 2: Write RED isolation test.** Make case 1 mutate fake runtime state and fail; prove case 2 receives a fresh verified baseline restore before its first case-specific action.

```python
def test_each_case_restores_verified_baseline() -> None:
    result = run_acceptance_matrix(factory, matrix, scenario)
    assert factory.restore_calls == ["baseline", "baseline"]
    assert [case.status for case in result.cases] == ["failed", "passed"]
```

- [ ] **Step 3: Write RED contamination-block test.** If baseline restore/verification fails after a case, abort remaining cases instead of running them against contaminated state.
- [ ] **Step 4: Write RED resume test.** Completed case results may be reused only when matrix/scenario/checkpoint identities match; an interrupted case restarts from baseline.
- [ ] **Step 5: Implement strict parameter resolution and per-case result directories.** Store resolved parameters, completed steps, assertions, trace references, failure reason, and diagnostic duration.
- [ ] **Step 6: Implement matrix runner.** Restore+verify baseline -> resolve case -> run scenario -> finalize result -> restore+verify baseline before next case.
- [ ] **Step 7: Add `runtime matrix run MATRIX` CLI** with optional `--session-root`/`--output`; render deterministic PASS/FAIL summary plus machine-readable JSON.
- [ ] **Step 8: Extend integration workflow** to run two synthetic cases with different guarded memory values and prove independent evidence artifacts.
- [ ] **Step 9: Run focused gate.**

```bash
python -m pytest tests/unit/test_orchestration_acceptance.py tests/unit/test_runtime_cli.py tests/integration/test_runtime_orchestration_workflow.py -v
```

- [ ] **Step 10: Commit.**

```bash
git add src/nds_disassembly_toolkit/analysis/orchestration/acceptance.py src/nds_disassembly_toolkit/analysis/orchestration/model.py src/nds_disassembly_toolkit/analysis/runtime_cli.py tests/unit/test_orchestration_acceptance.py tests/unit/test_runtime_cli.py tests/integration/test_runtime_orchestration_workflow.py
git commit -m "feat: add deterministic runtime acceptance matrices"
```

### Task 12: Public exports, documentation, live acceptance gate, scope audit, and release verification

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/orchestration/__init__.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/__init__.py`
- Modify: `tests/unit/test_runtime_exports.py`
- Modify: `README.md`
- Modify: `docs/runtime-debugging.md`
- Modify: `docs/provenance-and-licenses.md`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/integration/test_runtime_orchestration_workflow.py`

**Interfaces:**
- Public orchestration API exports the versioned records, backend/session helpers, checkpoint APIs, predicate APIs, scenario APIs, and acceptance APIs required by consumer projects; low-level X11 implementation details remain module-local.
- Existing runtime exports remain backward compatible.

- [ ] **Step 1: Write export regression assertions.** Ensure `DeSmuMESession`, orchestration schema constants, DS input models, checkpoint/scenario/matrix records, and orchestration error classes are importable through documented package boundaries.
- [ ] **Step 2: Update README capability/CLI overview.** Add managed runtime orchestration without describing it as game-aware automation.
- [ ] **Step 3: Rewrite the opening of `docs/runtime-debugging.md`.** Preserve attach-only Phase 7H1/7H2 instructions and add a separate managed Phase 7H3 workflow covering doctor, launch, checkpoint, scenario, resume, matrix, session directories, safety, and failure bundles.
- [ ] **Step 4: Update provenance.** Record DeSmuME as an external GPL interoperability target, pin the live-gate lineage to upstream `TASEmulators/desmume` release tag `release_0_9_13`, and state that no DeSmuME implementation source is copied or linked into the MIT toolkit.
- [ ] **Step 5: Expand CI live gate.** Preserve the pinned stock-melonDS release gate. Add Linux packages/build steps needed for Xvfb/xdotool and the pinned DeSmuME executable, then exercise managed doctor/launch/window/input/checkpoint/scenario/matrix only for capabilities the pinned binaries genuinely expose. Use a synthetic/disposable NDS target; do not depend on a commercial ROM.
- [ ] **Step 6: Add the end-to-end acceptance proof.** The live or subprocess-backed deterministic fixture must demonstrate:

```text
runtime doctor
→ isolated managed session
→ verified checkpoint baseline
→ guarded precondition
→ controlled mutation/input
→ existing .ndstrace evidence
→ postcondition
→ baseline restore
→ second case
→ independent PASS/FAIL artifacts
```

- [ ] **Step 7: Run full local verification.**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: all pass.

- [ ] **Step 8: Run scope audit before PR readiness.** Confirm with repository diff/search that:
  - `pyproject.toml` dependency declarations are unchanged;
  - `.ndsre` schema/model versions are unchanged;
  - `.ndstrace` schema version is unchanged;
  - only one RSP transport exists;
  - no game-specific names/addresses were introduced;
  - no emulator implementation source was vendored;
  - no shell-command scenario execution exists;
  - attach-only runtime tests remain green.

- [ ] **Step 9: Run plan/spec self-consistency audit.** Search the implementation against every Phase 7H3 success criterion and ensure each has at least one automated test or live gate.
- [ ] **Step 10: Commit documentation/release work.**

```bash
git add src/nds_disassembly_toolkit/analysis/orchestration/__init__.py src/nds_disassembly_toolkit/analysis/runtime/__init__.py tests/unit/test_runtime_exports.py README.md docs/runtime-debugging.md docs/provenance-and-licenses.md .github/workflows/ci.yml tests/integration/test_runtime_orchestration_workflow.py
git commit -m "docs: finalize Phase 7H3 runtime orchestration"
```

- [ ] **Step 11: Require exact-head PR verification** for full pytest, Ruff, strict mypy, stock-melonDS live smoke, and managed orchestration live/integration gate. Do not merge a newer unverified head.
- [ ] **Step 12: Squash-merge with expected-head protection, then require a fresh `main` CI run on the exact squash commit.** Phase 7H3 is complete only after that post-merge run is green.

## Plan Self-Review Checklist

Before execution begins, the plan author/executor must verify these statements against the approved design:

- [ ] Every design success criterion maps to Tasks 1–12.
- [ ] Process identity prevents PID-reuse cleanup accidents.
- [ ] Dynamic managed ports do not alter historical attach-only defaults.
- [ ] DeSmuME changes only the emulator session/dialect adapter and reuses `RSPClient`.
- [ ] X11 input requires owned-window verification.
- [ ] DS touch coordinates never expose desktop pixel coordinates to consumers.
- [ ] Checkpoint restore validates ROM/emulator/file identity before mutation.
- [ ] RSP write support is bounded and uses the existing transport.
- [ ] Predicate waits are finite and retain last-observation evidence.
- [ ] Scenario journals distinguish `STARTED` from `COMPLETED`.
- [ ] Resume replays from a safe anchor after ambiguous interruption.
- [ ] Matrix execution restores/verifies baseline before every case.
- [ ] Failure evidence preserves the primary error.
- [ ] No image/OCR state recognition, arbitrary shell scenario step, cross-emulator savestate conversion, or game-specific semantic library is introduced.
- [ ] Final CI retains the stock-melonDS 7H1/7H2 release gate.
