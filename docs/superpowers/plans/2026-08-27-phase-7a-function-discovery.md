# Phase 7A Function Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add conservative Capstone-backed ARM/Thumb function discovery for Nintendo DS executable components.

**Architecture:** Keep Capstone isolated behind `analysis/decoder.py`, expose only toolkit-owned immutable models, and implement recursive direct-call discovery in `analysis/functions.py`. Preserve the existing prologue heuristics unchanged and make the new records suitable for Phase 7B CFG construction.

**Tech Stack:** Python 3.11, Capstone Python bindings, pytest, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-08-27-phase-7a-function-discovery-design.md`

## Global Constraints

- No Bakugan-specific profile, address, Gate, or gameplay policy.
- Do not vendor Capstone, angr, or melonDS implementation source.
- Decode only little-endian ARM/Thumb modes relevant to Nintendo DS ARM7/ARM9 code.
- Indirect branch/call targets are never guessed in Phase 7A.
- Existing `arm_function_starts`, `nearest_function_start`, and `function_address_for_reference` behavior remains compatible.
- Results must be deterministic and based on runtime addresses.

---

### Task 1: Capstone decoder boundary

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/decoder.py`
- Create: `tests/unit/test_analysis_decoder.py`

**Interfaces:**
- Produces: `InstructionSet`, `ControlFlowKind`, `DecodedInstruction`
- Produces: `decode_instruction(data: bytes, *, address: int, instruction_set: InstructionSet) -> DecodedInstruction | None`

- [ ] **Step 1: Write the failing decoder tests**

Add synthetic tests that assert an ARM `BL` resolves its absolute target, an ordinary ARM instruction is classified as ordinary, and ARM/Thumb alignment is validated.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python -m pytest tests/unit/test_analysis_decoder.py -v`
Expected: FAIL because the decoder/models do not exist yet.

- [ ] **Step 3: Add the runtime dependency and minimal models**

Set `dependencies = ["capstone>=5,<7"]` and add string enums/dataclasses for instruction set, control-flow kind, and decoded instruction metadata.

- [ ] **Step 4: Implement the minimal decoder**

Use `Cs(CS_ARCH_ARM, CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)` or Thumb equivalent with `detail = True`. Determine semantic kind from Capstone groups; extract a direct target only when the first branch/call operand is an immediate. For `BLX` immediate, set the target instruction set to the opposite mode; ordinary `BL` keeps the current mode.

- [ ] **Step 5: Run decoder tests and existing ARM heuristic tests**

Run: `python -m pytest tests/unit/test_analysis_decoder.py tests/unit/test_analysis_arm.py -v`
Expected: PASS.

---

### Task 2: Recursive direct-call function discovery

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/functions.py`
- Create: `tests/unit/test_analysis_functions.py`

**Interfaces:**
- Produces: `FunctionSeed(address: int, instruction_set: InstructionSet, source: str = "explicit")`
- Produces: `FunctionCandidate(component: str, address: int, offset: int, instruction_set: InstructionSet, confidence: str, evidence: tuple[str, ...])`
- Produces: `FunctionDiscoveryResult(functions: tuple[FunctionCandidate, ...], unresolved_calls: tuple[int, ...], decode_failures: tuple[int, ...])`
- Produces: `discover_functions(component: Component, *, seeds: Sequence[FunctionSeed]) -> FunctionDiscoveryResult`

- [ ] **Step 1: Write failing discovery tests**

Cover one ARM caller discovering one ARM callee, duplicate explicit/call evidence merging into one candidate, an out-of-component call remaining unresolved, ARM-to-Thumb `BLX` interworking, and seed alignment rejection.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python -m pytest tests/unit/test_analysis_functions.py -v`
Expected: FAIL because the function discovery API does not exist.

- [ ] **Step 3: Implement deterministic worklist discovery**

Validate and normalize seeds first. For each unprocessed `(address, instruction_set)` key, create/merge evidence, linearly decode from that entry, enqueue same-component direct call targets, record external direct calls as unresolved, and stop the path on return, unconditional branch, decode failure, or component end. Do not follow indirect targets.

- [ ] **Step 4: Run focused analysis tests**

Run: `python -m pytest tests/unit/test_analysis_functions.py tests/unit/test_analysis_decoder.py tests/unit/test_analysis_arm.py -v`
Expected: PASS.

---

### Task 3: Public API, provenance, and full verification

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`

**Interfaces:**
- Export the Phase 7A models and `discover_functions` from `nds_disassembly_toolkit.analysis`.

- [ ] **Step 1: Add a failing public-API assertion**

Extend a focused test to import `discover_functions`, `FunctionSeed`, and `InstructionSet` from `nds_disassembly_toolkit.analysis`.

- [ ] **Step 2: Run it and verify RED**

Run the focused test and confirm the root analysis package does not yet export the new API.

- [ ] **Step 3: Export the API and update documentation**

Document function discovery as conservative direct-call recovery, record Capstone as a permissive runtime dependency/reference, and state that angr/melonDS remain reference/integration sources rather than vendored code.

- [ ] **Step 4: Run all quality gates**

Run:
- `python -m pytest -v`
- `python -m ruff check .`
- `python -m mypy src/nds_disassembly_toolkit`

Expected: all pass.

- [ ] **Step 5: Open a Phase 7A pull request**

Create a PR from `phase-7a-function-discovery` to `main`, verify the exact-head GitHub Actions run, and merge only after pytest, Ruff, and strict mypy succeed.
