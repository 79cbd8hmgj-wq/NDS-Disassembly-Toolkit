# Phase 7C Cross-References Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic code/data cross-references, indexed source/target queries, and a direct-call graph view.

**Architecture:** Normalize Phase 7B semantic CFG edges and existing pointer records into toolkit-owned immutable xref records in `analysis/xrefs.py`. Do not re-decode instructions or introduce symbol semantics.

**Tech Stack:** Python 3.11, existing analysis models, pytest, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-08-27-phase-7c-cross-references-design.md`

## Global Constraints

- No Bakugan-specific policy or addresses.
- `analysis/xrefs.py` must not import Capstone.
- Fallthrough CFG edges are not cross-references.
- Indirect targets are never invented.
- Pointer xrefs do not invent ARM/Thumb mode or source-function ownership.
- Results and queries are deterministic.

---

### Task 1: Normalize code and data references

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/xrefs.py`
- Create: `tests/unit/test_analysis_xrefs.py`

**Interfaces:**
- Produces: `CrossReferenceKind`, `CrossReference`
- Produces: `build_code_xrefs(cfgs: Sequence[FunctionControlFlowGraph]) -> tuple[CrossReference, ...]`
- Produces: `build_data_xrefs(references: Sequence[PointerReference]) -> tuple[CrossReference, ...]`

- [ ] **Step 1: Write failing normalization tests**

Cover call/branch conversion, fallthrough exclusion, ARM-to-Thumb target mode, pointer conversion, and duplicate de-duplication.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_xrefs.py -v`
Expected: FAIL because xref models/module do not exist.

- [ ] **Step 3: Implement minimal immutable models and normalizers**

Use structural de-duplication and stable sorting. Preserve source function only for CFG-derived references.

- [ ] **Step 4: Verify GREEN**

Run the focused xref tests and confirm normalization cases pass.

---

### Task 2: Indexed queries and direct-call graph

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Modify: `src/nds_disassembly_toolkit/analysis/xrefs.py`
- Modify: `tests/unit/test_analysis_xrefs.py`

**Interfaces:**
- Produces: `CrossReferenceIndex`
- Produces: `build_xref_index(cfgs: Sequence[FunctionControlFlowGraph], *, pointer_references: Sequence[PointerReference] = ()) -> CrossReferenceIndex`
- Produces: `CallGraphEdge`
- Produces: `build_call_graph(index: CrossReferenceIndex) -> tuple[CallGraphEdge, ...]`

- [ ] **Step 1: Add failing query/call-graph tests**

Assert stable `to_address()` and `from_address()` results, optional kind filtering, and direct-call graph extraction including external call targets.

- [ ] **Step 2: Verify RED**

Run focused xref tests and confirm query/call-graph APIs are absent.

- [ ] **Step 3: Implement minimal index and derived call graph**

Keep the public index immutable; filter its canonical sorted tuple for queries. De-duplicate call-graph edges structurally.

- [ ] **Step 4: Verify GREEN**

Run all xref tests plus Phase 7A/7B analysis tests.

---

### Task 3: Public API, docs, and integration

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`
- Modify: `tests/unit/test_analysis_xrefs.py`

**Interfaces:**
- Export all Phase 7C models/builders from `nds_disassembly_toolkit.analysis`.

- [ ] **Step 1: Add failing public-export test**

Assert root-package identities for xref models and builders.

- [ ] **Step 2: Verify RED**

Confirm the new API is not exported yet.

- [ ] **Step 3: Export and document Phase 7C**

Document semantic xrefs, query behavior, call graph derivation, and the unchanged angr reference-only boundary.

- [ ] **Step 4: Run full quality gates**

Run full pytest, Ruff, and strict mypy through repository CI.

- [ ] **Step 5: Open PR and merge only after exact-head CI**

Squash-merge only after every gate passes, then verify push CI on `main`.
