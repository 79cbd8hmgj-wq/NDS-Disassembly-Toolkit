# Phase 7B Control-Flow Graphs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build deterministic intraprocedural basic-block CFGs from Phase 7A decoded instructions and function candidates.

**Architecture:** Traverse reachable instructions first, record successor/call/unresolved evidence, then derive basic-block leaders and graph edges in a second pass. Keep Capstone isolated in `analysis/decoder.py`; `analysis/cfg.py` consumes toolkit-owned records only.

**Tech Stack:** Python 3.11, existing Capstone decoder, pytest, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-08-27-phase-7b-control-flow-graphs-design.md`

## Global Constraints

- No Bakugan-specific policy or addresses.
- No new graph-library dependency.
- `analysis/cfg.py` must not import Capstone.
- Calls are recorded but callee bodies are not traversed intraprocedurally.
- Indirect targets are never guessed.
- Runtime address plus ARM/Thumb mode is the control-flow identity.
- Results are deterministic.

---

### Task 1: CFG data model and straight-line recovery

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/cfg.py`
- Create: `tests/unit/test_analysis_cfg.py`

**Interfaces:**
- Produces: `CFGEdgeKind`, `BasicBlock`, `CFGEdge`, `UnresolvedTransfer`, `FunctionControlFlowGraph`
- Produces: `build_function_cfg(component: Component, function: FunctionCandidate) -> FunctionControlFlowGraph`

- [ ] **Step 1: Write failing straight-line and validation tests**

Use a synthetic ARM function with two ordinary instructions followed by `bx lr`. Assert one block contains all three instructions, block size/end are derived correctly, no edges exist, and mismatched component/alignment inputs raise `ValueError`.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_cfg.py -v`
Expected: FAIL because CFG models/module do not exist.

- [ ] **Step 3: Add minimal immutable models and straight-line traversal**

Implement model records and `build_function_cfg` sufficiently to validate the input, decode reachable linear instructions, stop on return/decode failure, and emit one block.

- [ ] **Step 4: Verify GREEN**

Run: `python -m pytest tests/unit/test_analysis_cfg.py -v`
Expected: straight-line/validation tests pass.

---

### Task 2: Branch leaders and deterministic edges

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/cfg.py`
- Modify: `tests/unit/test_analysis_cfg.py`

**Interfaces:**
- Consumes: Phase 7B models from Task 1.
- Produces: direct branch/fallthrough edges and non-overlapping block leaders.

- [ ] **Step 1: Add failing conditional-forward-branch test**

Encode an ARM conditional branch with both a taken target and fallthrough path. Assert three non-overlapping blocks and deterministic `BRANCH`/`FALLTHROUGH` edges.

- [ ] **Step 2: Add failing backward-branch test**

Use a conditional backward branch whose target lies earlier in reachable code. Assert the target becomes a block leader and no two emitted blocks overlap.

- [ ] **Step 3: Verify RED**

Run focused CFG tests and confirm branch cases fail for missing successor/leader logic.

- [ ] **Step 4: Implement instruction-successor traversal and two-pass leader recovery**

Record reachable instructions keyed by `(address, instruction_set)`, local traversal successors, and transfer records. Derive leaders from entry, local branch targets, and fallthrough addresses after conditional branches. Build blocks from sorted reachable instructions, ending before another leader or at a control-flow terminator.

- [ ] **Step 5: Verify GREEN**

Run: `python -m pytest tests/unit/test_analysis_cfg.py -v`
Expected: branch tests pass without overlapping blocks.

---

### Task 3: Calls, external transfers, and unresolved indirect flow

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/cfg.py`
- Modify: `tests/unit/test_analysis_cfg.py`

**Interfaces:**
- Produces: `CALL` edges, external direct `BRANCH` edges, and `UnresolvedTransfer` records.

- [ ] **Step 1: Add failing direct-call test**

Use a caller with a direct `BL`, a return after the call, and a valid callee body elsewhere in the same component. Assert a `CALL` edge targets the callee, a fallthrough block begins after the call, and the callee body is not included among caller CFG blocks.

- [ ] **Step 2: Add failing ARM-to-Thumb call-edge test**

Use ARM immediate `BLX` and assert the call edge target mode is `InstructionSet.THUMB`.

- [ ] **Step 3: Add failing external/indirect transfer tests**

Assert an external direct unconditional branch remains an edge without out-of-bounds decoding, while `bx r0` produces one unresolved branch transfer and stops that path.

- [ ] **Step 4: Implement minimal call/external/unresolved handling**

Calls record edges and enqueue only fallthrough. Direct local branches enqueue their target. Direct external branches record an edge without traversal. Indirect calls/branches create stable unresolved records; indirect calls keep fallthrough, indirect unconditional branches stop.

- [ ] **Step 5: Verify GREEN with all Phase 7A/7B tests**

Run: `python -m pytest tests/unit/test_analysis_cfg.py tests/unit/test_analysis_decoder.py tests/unit/test_analysis_functions.py tests/unit/test_analysis_arm.py -v`
Expected: all pass.

---

### Task 4: Public API, documentation, and integration gate

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`
- Modify: `tests/unit/test_analysis_cfg.py`

**Interfaces:**
- Export `CFGEdgeKind`, `BasicBlock`, `CFGEdge`, `UnresolvedTransfer`, `FunctionControlFlowGraph`, and `build_function_cfg` from `nds_disassembly_toolkit.analysis`.

- [ ] **Step 1: Add failing public-export test**

Import the new models/function through the root analysis package and assert identity with their defining modules.

- [ ] **Step 2: Verify RED**

Run the public-export test and confirm exports are absent.

- [ ] **Step 3: Export API and document Phase 7B**

Document two-pass CFG construction, edge semantics, conservative indirect handling, and angr's reference-only role.

- [ ] **Step 4: Run full quality gates**

Run:
- `python -m pytest -v`
- `python -m ruff check .`
- `python -m mypy src/nds_disassembly_toolkit`

Expected: all pass.

- [ ] **Step 5: Open PR and merge only after exact-head CI**

Create a PR from `phase-7b-control-flow-graphs` to `main`, inspect any failure logs, and squash-merge only after pytest, Ruff, and strict mypy pass on the exact PR head. Verify the resulting `main` push CI.
