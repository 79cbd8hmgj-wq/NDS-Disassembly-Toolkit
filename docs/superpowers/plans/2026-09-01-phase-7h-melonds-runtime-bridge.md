# Phase 7H melonDS Runtime Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a stock-melonDS-compatible runtime-analysis bridge that connects through GDB RSP, captures typed ARM9/ARM7 debugger state, supports bounded memory/break/watch/step operations, and safely correlates stopped PCs with existing `.ndsre` static-analysis projects.

**Architecture:** Keep GDB RSP framing and transport emulator-neutral in `analysis/runtime/rsp.py`; keep Nintendo DS/melonDS register mapping and session semantics in `analysis/runtime/melonds.py`; keep immutable runtime evidence in `analysis/runtime/model.py`; keep static-project correlation in `analysis/runtime/correlation.py`; expose deterministic JSON through `analysis/runtime_cli.py`. No melonDS implementation code is copied into the MIT toolkit, and Phase 7H1 does not change the Phase 7F SQLite schema.

**Tech Stack:** Python 3.11+, standard-library `socket`, immutable dataclasses/StrEnum, existing `AnalysisProject` API, argparse, pytest, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-09-01-phase-7h-melonds-runtime-bridge-design.md`

## Global Constraints

- Integration is through melonDS's external GDB Remote Serial Protocol behavior only; do not copy, vendor, translate, or derive GPL melonDS implementation code.
- No new runtime dependency and no `pyproject.toml` dependency change.
- Default ARM9 endpoint is `127.0.0.1:3333`; default ARM7 endpoint is `127.0.0.1:3334`; host and port remain overrideable.
- Runtime inspection requires melonDS's GDB stub enabled and JIT disabled; the toolkit does not mutate emulator configuration.
- Phase 7H1 does not persist runtime events and does not change the analysis-project schema.
- Runtime/static correlation must preserve component identity and must never guess one overlay solely from a numerical runtime address.
- CLI output follows Phase 7G deterministic JSON and canonical hexadecimal address conventions.
- Full pytest, Ruff, and strict mypy are mandatory before merge; a manual stock-melonDS smoke test remains a release gate.

---

### Task 1: Runtime models, errors, and public API

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/runtime/__init__.py`
- Create: `src/nds_disassembly_toolkit/analysis/runtime/model.py`
- Modify: `src/nds_disassembly_toolkit/errors.py`
- Test: `tests/unit/test_runtime_model.py`
- Test: `tests/unit/test_runtime_exports.py`

**Interfaces:**
- Produces: `RuntimeCpu`, `StopReasonKind`, `BreakpointKind`, `RegisterSnapshot`, `RuntimeStop`, `RuntimeSnapshot`, `RuntimeLocation`, `RuntimeComponentLocation`.
- Produces errors: `RuntimeAnalysisError`, `RuntimeConnectionError`, `RuntimeProtocolError`, `RuntimeTimeoutError`, `RuntimeTargetStateError`.
- `RuntimeCpu.default_port` returns `3333` for ARM9 and `3334` for ARM7.
- `RegisterSnapshot.value(name: str) -> int | None` provides canonical lookup for `r0`-`r12`, `sp`, `lr`, `pc`, `cpsr`.
- `RuntimeSnapshot.instruction_set` derives `InstructionSet.THUMB` when CPSR bit 5 is set, else `InstructionSet.ARM`.

- [ ] **Step 1: Write the failing model/export tests**

```python
from nds_disassembly_toolkit.analysis import InstructionSet
from nds_disassembly_toolkit.analysis.runtime import (
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)


def test_runtime_cpu_default_ports() -> None:
    assert RuntimeCpu.ARM9.default_port == 3333
    assert RuntimeCpu.ARM7.default_port == 3334


def test_runtime_snapshot_derives_thumb_from_cpsr() -> None:
    registers = RegisterSnapshot.from_mapping({"pc": 0x02000100, "cpsr": 1 << 5})
    snapshot = RuntimeSnapshot(
        cpu=RuntimeCpu.ARM9,
        registers=registers,
        stop=RuntimeStop(StopReasonKind.STEP),
    )
    assert snapshot.pc == 0x02000100
    assert snapshot.instruction_set is InstructionSet.THUMB
```

Also assert the runtime errors subclass `NdsToolkitError` and the public runtime package exports all listed types.

- [ ] **Step 2: Run tests to verify RED**

Run: `pytest tests/unit/test_runtime_model.py tests/unit/test_runtime_exports.py -q`
Expected: collection/import failure because `analysis.runtime` does not exist.

- [ ] **Step 3: Implement the immutable runtime models and error hierarchy**

Use frozen dataclasses/`StrEnum`. Normalize register mappings into a deterministic tuple sorted by canonical ARM register order first (`r0`…`r12`, `sp`, `lr`, `pc`, `cpsr`), followed by any additional names alphabetically. Reject negative register values and duplicate register names.

- [ ] **Step 4: Run Task 1 GREEN gate**

Run: `pytest tests/unit/test_runtime_model.py tests/unit/test_runtime_exports.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/runtime src/nds_disassembly_toolkit/errors.py tests/unit/test_runtime_model.py tests/unit/test_runtime_exports.py
git commit -m "Add runtime analysis models"
```

---

### Task 2: Emulator-neutral GDB RSP transport

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/runtime/rsp.py`
- Test: `tests/unit/test_runtime_rsp.py`

**Interfaces:**
- Consumes: runtime protocol/connection/timeout errors from Task 1.
- Produces: `RSPCapabilities`, `RSPStopReply`, `RSPClient`.
- `RSPClient.connect(host: str, port: int, *, timeout: float = 5.0) -> RSPClient`.
- `RSPClient.negotiate() -> RSPCapabilities` sends `qSupported` and attempts `QStartNoAckMode` only when advertised.
- `RSPClient.command(payload: str) -> str` validates framing/checksum and turns `E..` replies into `RuntimeProtocolError`.
- `RSPClient.read_registers() -> bytes`, `read_memory(address: int, length: int) -> bytes`, `insert_breakpoint(kind: int, address: int, length: int)`, `remove_breakpoint(...)`, `continue_execution() -> RSPStopReply`, `step() -> RSPStopReply`, `interrupt()`, and `detach()`.

- [ ] **Step 1: Write fake-socket RED tests for framing and negotiation**

Cover exact checksum framing (`$qSupported#37`), ACK handling, fragmented receives, checksum rejection, peer `E..`, `qSupported`, and `QStartNoAckMode` transition. The fake socket returns deliberately fragmented packet bytes so receive logic cannot assume one TCP `recv()` equals one RSP packet.

- [ ] **Step 2: Run framing/negotiation tests to verify RED**

Run: `pytest tests/unit/test_runtime_rsp.py -q`
Expected: import failure for `runtime.rsp`.

- [ ] **Step 3: Implement packet transport minimally**

Implement checksum as `sum(payload_bytes) & 0xFF`, `$payload#xx` framing, packet receive state machine, `+`/`-` ACK behavior, bounded payload length, socket timeout translation, and `qSupported` feature parsing into an immutable capability mapping.

- [ ] **Step 4: Add RED command tests**

Add tests for `g`, chunked `mADDR,LEN`, `Z`/`z`, `c`, `s`, `D`, remote interrupt byte `0x03`, normal `Sxx`/`Txx` stop replies, and exit replies. Require invalid hex/malformed stop replies to raise `RuntimeProtocolError`.

- [ ] **Step 5: Implement command helpers and stop parsing**

Memory reads must enforce a client-side chunk ceiling and join exact byte ranges; no response may cause an unbounded allocation. Continue/step must wait for a stop reply and translate socket timeout to `RuntimeTimeoutError` without claiming the target stopped.

- [ ] **Step 6: Run Task 2 GREEN gate**

Run: `pytest tests/unit/test_runtime_rsp.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/runtime/rsp.py tests/unit/test_runtime_rsp.py
git commit -m "Add GDB RSP runtime transport"
```

---

### Task 3: melonDS session adapter

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/runtime/melonds.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/__init__.py`
- Test: `tests/unit/test_runtime_melonds.py`

**Interfaces:**
- Consumes: `RSPClient`, runtime models/errors.
- Produces: `MelonDSSession`.
- `MelonDSSession.connect(cpu: RuntimeCpu, host: str = "127.0.0.1", port: int | None = None, timeout: float = 5.0) -> MelonDSSession`.
- `capabilities`, `snapshot()`, `read_memory()`, `add_breakpoint()`, `remove_breakpoint()`, `continue_execution()`, `step()`, `run_until_breakpoint()`, `run_until_watchpoint()`, `interrupt()`, `close()`.

- [ ] **Step 1: Write RED adapter tests with a fake RSP client**

Require ARM9/ARM7 default ports, connection error translation, deterministic register mapping, CPSR/PC extraction, ARM/Thumb state, memory delegation, breakpoint/watchpoint packet-kind mapping, and context-manager cleanup.

- [ ] **Step 2: Run adapter tests to verify RED**

Run: `pytest tests/unit/test_runtime_melonds.py -q`
Expected: import failure for `runtime.melonds`.

- [ ] **Step 3: Implement register mapping and snapshot capture**

Decode the peer's little-endian 32-bit register blob into the ARM core register order required by the melonDS GDB target: `r0`-`r12`, `sp`, `lr`, `pc`, then status register as `cpsr`; reject too-short/non-word-aligned payloads. Keep this mapping isolated in `melonds.py`, not `rsp.py`.

- [ ] **Step 4: Implement break/watch/continue/step convenience operations**

Map semantic stop conditions to RSP kinds and guarantee temporary breakpoint/watchpoint removal with `try/finally` when the connection remains usable. `run_until_breakpoint(address)` installs one temporary code breakpoint, continues, captures a snapshot, removes it, and returns that snapshot.

- [ ] **Step 5: Run Task 3 GREEN gate**

Run: `pytest tests/unit/test_runtime_melonds.py tests/unit/test_runtime_rsp.py tests/unit/test_runtime_model.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/runtime tests/unit/test_runtime_melonds.py
git commit -m "Add melonDS debugger session adapter"
```

---

### Task 4: Static-project correlation

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/runtime/correlation.py`
- Modify: `src/nds_disassembly_toolkit/analysis/runtime/__init__.py`
- Test: `tests/unit/test_runtime_correlation.py`

**Interfaces:**
- Consumes: `RuntimeSnapshot`, `AnalysisProject.component_identities()`, `AnalysisProject.function()`, `AnalysisProject.symbols_at()`, and `AnalysisProject.annotation()`.
- Produces: `correlate_snapshot(project: AnalysisProject, snapshot: RuntimeSnapshot) -> RuntimeLocation`.

- [ ] **Step 1: Write RED correlation tests**

Construct an analysis project fixture with ARM9 plus two overlays whose stored runtime ranges overlap. Assert exact ARM/Thumb matching, symbols and user annotation inclusion, no match outside all components, and two distinct `RuntimeComponentLocation` candidates for an address covered by both overlays.

- [ ] **Step 2: Run correlation tests to verify RED**

Run: `pytest tests/unit/test_runtime_correlation.py -q`
Expected: import failure for `runtime.correlation`.

- [ ] **Step 3: Implement component-safe correlation**

Filter `component_identities()` by `base_address <= pc < base_address + size`. For each candidate, call `project.function(identity.name, pc, snapshot.instruction_set)`, `project.symbols_at(identity.name, pc)`, and `project.annotation(identity.name, pc)`. Preserve all candidates sorted by component name; do not select one overlay when several contain the address.

- [ ] **Step 4: Run Task 4 GREEN gate**

Run: `pytest tests/unit/test_runtime_correlation.py tests/unit/test_analysis_project_*.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/runtime/correlation.py src/nds_disassembly_toolkit/analysis/runtime/__init__.py tests/unit/test_runtime_correlation.py
git commit -m "Correlate runtime state with analysis projects"
```

---

### Task 5: Runtime CLI and top-level integration

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/runtime_cli.py`
- Modify: `src/nds_disassembly_toolkit/cli.py`
- Test: `tests/unit/test_runtime_cli.py`
- Modify: `tests/unit/test_cli.py`

**Interfaces:**
- Produces top-level `nds-toolkit runtime` with `probe`, `snapshot`, `read-memory`, `run-until`, and `step`.
- Uses `MelonDSSession` only; the CLI must not import `socket` or raw RSP helpers.
- Optional `--project PATH` opens `AnalysisProject` read-only and adds `RuntimeLocation` correlation.

- [ ] **Step 1: Write RED parser/dispatch tests**

Assert parser accepts:

```text
runtime probe --cpu arm9
runtime snapshot --cpu arm7 --host 127.0.0.1 --port 3334 --project game.ndsre
runtime read-memory --cpu arm9 0x02000000 0x100
runtime run-until --cpu arm9 --break 0x02012340
runtime run-until --cpu arm9 --watch-write 0x02100000 --length 4
runtime step --cpu arm9 --count 4
```

Reject missing CPU, mutually conflicting stop conditions, zero/negative lengths, and `step --count` above the explicit 7H1 safety cap of `256`.

- [ ] **Step 2: Run CLI parser tests to verify RED**

Run: `pytest tests/unit/test_runtime_cli.py tests/unit/test_cli.py -q`
Expected: parser failure because `runtime` is not registered.

- [ ] **Step 3: Implement deterministic serializers and commands**

Use the same canonical address format as Phase 7G (`0x` plus at least eight lowercase hex digits). Serialize register names in canonical order, memory bytes as lowercase hex, stop reason as stable enum value, capabilities in sorted order, and correlation candidates in component-name order. `probe` must negotiate and detach without continue/step/reset. `snapshot` must not mutate execution state.

- [ ] **Step 4: Add command behavior/error RED tests**

Monkeypatch `MelonDSSession.connect` to fake sessions and assert command delegation, temporary condition cleanup, project opened read-only, JSON determinism, and existing top-level error mapping: `ValueError -> 2`, runtime `NdsToolkitError -> 4`, filesystem `OSError -> 5`.

- [ ] **Step 5: Implement top-level dispatch**

Register `add_runtime_parser(subparsers)` in `build_parser()` and route `arguments.command == "runtime"` to `run_runtime_command(arguments)` inside the existing exception boundary.

- [ ] **Step 6: Run Task 5 GREEN gate**

Run: `pytest tests/unit/test_runtime_cli.py tests/unit/test_cli.py tests/unit/test_cli_analysis_project.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/runtime_cli.py src/nds_disassembly_toolkit/cli.py tests/unit/test_runtime_cli.py tests/unit/test_cli.py
git commit -m "Add runtime debugger CLI"
```

---

### Task 6: Documentation, provenance, audit, and release gate

**Files:**
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`
- Test: all tests

**Interfaces:**
- Documents stock melonDS setup boundary and exact 7H1 commands.
- Records that melonDS informed interoperability behavior only and no GPL implementation code is vendored.

- [ ] **Step 1: Document the runtime workflow**

Add a Phase 7H section stating: build/run melonDS with GDB stub enabled; disable JIT while debugging; ARM9 defaults to port 3333 and ARM7 to 3334; do not expose classic unauthenticated GDB RSP to untrusted networks. Include `probe`, `snapshot`, `read-memory`, `run-until`, `step`, and `--project` correlation examples.

- [ ] **Step 2: Update provenance boundary**

Record melonDS as GPL-3.0 reference material whose GDB interoperability behavior was studied, while the toolkit's RSP client/runtime models/CLI are independently implemented standard-library Python and no melonDS source is copied or linked into the package.

- [ ] **Step 3: Run exact-head regression gate**

Run:

```bash
pytest -q
ruff check src tests
mypy --strict src/nds_disassembly_toolkit
```

Expected: all pass.

- [ ] **Step 4: Audit scope**

Verify `git diff main...HEAD -- pyproject.toml` is empty; no consumer-specific/game-specific identifiers appear; no `sqlite3` import exists in runtime code; no `capstone` import exists in runtime code; no copied melonDS source/header files are present; project schema files are unchanged.

- [ ] **Step 5: Commit final docs/audit changes**

```bash
git add docs/disassembly-and-analysis.md docs/provenance-and-licenses.md
git commit -m "Document melonDS runtime analysis"
```

- [ ] **Step 6: Open/finalize PR and require exact-head CI**

Open Phase 7H1 PR against `main`, verify the exact head passes Test, Ruff, and strict Mypy, then mark ready and squash-merge with expected-head protection. Require post-merge CI on the exact squash commit.

- [ ] **Step 7: Manual stock-melonDS smoke test release gate**

With GDB stub enabled and JIT disabled, verify `runtime probe`, one stopped `snapshot`, one 64-byte ARM9 `read-memory`, one temporary breakpoint `run-until`, and one `step`. If a live emulator is not available in the execution environment, record this gate explicitly as pending rather than claiming it passed.