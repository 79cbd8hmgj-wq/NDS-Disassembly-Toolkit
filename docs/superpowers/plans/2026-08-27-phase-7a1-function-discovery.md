# Phase 7A1 Function Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add typed ARM/Thumb decoding and conservative recursive function discovery to the generic NDS analysis package.

**Architecture:** Keep Capstone behind a toolkit-owned decoder adapter so no public model exposes Capstone types. Function discovery consumes `DecodedInstruction` records and uses a deterministic recursive-descent worklist seeded by explicit entry points/direct calls; existing prologue scanners remain compatibility evidence helpers.

**Tech Stack:** Python 3.11+, Capstone 5.0.9 stable, pytest, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-08-27-phase-7a1-function-discovery-design.md`

## Global Constraints

- The toolkit remains game-neutral and MIT licensed.
- Capstone may be a direct BSD-licensed dependency; angr is reference only; melonDS GPL code must not be copied.
- Preserve existing `analysis.arm` helper behavior.
- Public analysis models must not expose Capstone classes/constants.
- ARM starts are 4-byte aligned; Thumb starts are 2-byte aligned.
- Results must be deterministic.

---

### Task 1: Decoder contract and real Capstone adapter

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/decoder.py`
- Create: `tests/unit/test_analysis_decoder.py`

**Interfaces:**
- Produces: `ExecutionMode`, `ControlFlowKind`, `DecodedInstruction`, `InstructionDecoder`, `CapstoneArmDecoder.decode_one(...)`.

- [ ] **Step 1: Write failing decoder tests**

Use real machine bytes and assert toolkit-facing semantics rather than Capstone internals:

```python
def test_decodes_arm_direct_call_target() -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, bytes.fromhex("000000EB"))
    decoded = CapstoneArmDecoder().decode_one(component, 0x02000000, ExecutionMode.ARM)
    assert decoded is not None
    assert decoded.flow is ControlFlowKind.CALL
    assert decoded.target == 0x02000008
    assert decoded.target_mode is ExecutionMode.ARM


def test_decodes_thumb_bx_lr_as_return() -> None:
    component = Component("overlay", Path("overlay.bin"), 0x02200000, bytes.fromhex("7047"))
    decoded = CapstoneArmDecoder().decode_one(component, 0x02200000, ExecutionMode.THUMB)
    assert decoded is not None
    assert decoded.flow is ControlFlowKind.RETURN
```

Add a BLX-immediate case using ARM bytes `00 00 00 FB`; assert the target mode is Thumb.

- [ ] **Step 2: Commit the red tests and verify CI fails for the missing API**

Expected failure: import/attribute errors for the new decoder/model types.

- [ ] **Step 3: Add Capstone and implement the minimal adapter**

Set:

```toml
dependencies = ["capstone>=5.0.9,<6"]
```

Implement immutable enums/dataclass models and a decoder protocol. `CapstoneArmDecoder` owns ARM and Thumb engines with details enabled and translates calls, branches, returns, direct targets, target mode, and conditional state into `DecodedInstruction`.

- [ ] **Step 4: Verify decoder tests pass**

Run targeted pytest, Ruff, and strict mypy.

- [ ] **Step 5: Commit the green implementation**

Commit message: `feat: add Capstone ARM Thumb decoder`.

---

### Task 2: Recursive function discovery

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/functions.py`
- Create: `tests/unit/test_function_discovery.py`

**Interfaces:**
- Consumes: `InstructionDecoder.decode_one(...)`, `DecodedInstruction`.
- Produces: `FunctionSeed`, `FunctionCandidate`, `FunctionDiscoveryResult`, `discover_functions(...)`.

- [ ] **Step 1: Write failing discovery tests**

Construct a small ARM component where the first instruction is an encoded `BL` to an in-component callee, followed by `bx lr`; the callee also returns. Assert both the explicit entry point and callee are discovered, and the callee evidence contains `direct-call`.

Add tests proving:

```python
assert [fn.address for fn in result.functions] == sorted(fn.address for fn in result.functions)
```

and that an unconditional direct `B` target is followed but not promoted to a new function candidate.

- [ ] **Step 2: Commit red tests and verify expected failure**

Expected failure: the discovery models/functions do not yet exist.

- [ ] **Step 3: Implement minimal deterministic worklist discovery**

Validate seed bounds/alignment. Track function candidates separately from path work. Process reachable `(address, mode)` states; promote only direct call targets to function candidates. Merge evidence/confidence for repeated discoveries. Report unresolved indirect unconditional transfers.

- [ ] **Step 4: Run targeted and full tests**

Run the discovery tests, all unit tests, then the full suite.

- [ ] **Step 5: Commit**

Commit message: `feat: discover ARM Thumb functions recursively`.

---

### Task 3: Compatibility prologue seeds and public exports

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/arm.py`
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `tests/unit/test_analysis_arm.py`

**Interfaces:**
- Produces: `arm_prologue_seeds(component: Component) -> tuple[FunctionSeed, ...]`.

- [ ] **Step 1: Add failing compatibility test**

Extend the existing ARM fixture and assert prologue matches convert to medium-confidence ARM seeds while the old tuple-returning helpers remain byte-for-byte compatible.

- [ ] **Step 2: Verify failure**

Expected failure: `arm_prologue_seeds` is missing.

- [ ] **Step 3: Implement adapter and exports**

Create seeds from `arm_function_starts(component)` with evidence `arm-prologue` and confidence `medium`. Re-export the new decoder/discovery API from `analysis.__init__`.

- [ ] **Step 4: Verify compatibility and full suite**

Run existing analysis tests plus the complete suite.

- [ ] **Step 5: Commit**

Commit message: `feat: bridge ARM prologue evidence into discovery`.

---

### Task 4: Provenance, user documentation, and final verification

**Files:**
- Modify: `docs/provenance-and-licenses.md`
- Modify: `docs/disassembly-and-analysis.md`

**Interfaces:**
- Documents Capstone as a direct BSD dependency and angr/melonDS as reference-only sources.

- [ ] **Step 1: Update provenance**

Record Capstone stable/direct dependency status, angr reference-only status, and melonDS GPL reference/integration-only boundary.

- [ ] **Step 2: Document the Python analysis API**

Add a Phase 7A section showing explicit `FunctionSeed` creation and `discover_functions(...)` use. State that CFG/xrefs/data flow are future phases.

- [ ] **Step 3: Run final gates**

Run:

```bash
pytest
ruff check .
mypy src
```

Expected: all pass with no warnings/errors.

- [ ] **Step 4: Open PR and require exact-head CI success before merge**

PR title: `Phase 7A1: add ARM Thumb function discovery core`.