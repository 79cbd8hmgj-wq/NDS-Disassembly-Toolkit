# Phase 7D Symbol Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic component-aware symbol recovery from functions, CFG branch targets, strings, and explicit naming candidates.

**Architecture:** Build one immutable symbol table in `analysis/symbols.py` from existing toolkit-owned records. Resolve and merge evidence by `(component, address)`; never infer component ownership from overlapping runtime ranges.

**Tech Stack:** Python 3.11, existing analysis models, pytest, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-08-27-phase-7d-symbol-recovery-design.md`

## Global Constraints

- No Bakugan-specific policy or addresses.
- Do not re-decode instructions.
- Symbol identity is `(component, address)`, never address alone.
- Never guess component ownership for external targets.
- Generated names are structural only: `func_`, `loc_`, `str_`.
- Existing `SymbolCandidate` names have naming precedence over generated names.
- Results and evidence ordering are deterministic.

---

### Task 1: Symbol models and function/string recovery

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/symbols.py`
- Create: `tests/unit/test_analysis_symbols.py`

**Interfaces:**
- Produces: `SymbolKind`, `Symbol`, `SymbolTable`
- Produces: `build_symbol_table(*, functions: Sequence[FunctionCandidate] = (), strings: Sequence[StringRecord] = (), cfgs: Sequence[FunctionControlFlowGraph] = (), candidates: Sequence[SymbolCandidate] = (), components: Sequence[Component] = ()) -> SymbolTable`

- [ ] **Step 1: Write failing function/string tests**

Cover generated function and string symbols, component-aware same-address symbols, and address/name/component queries.

- [ ] **Step 2: Verify RED**

Run focused tests; expect failure because symbol models/module do not exist.

- [ ] **Step 3: Implement immutable models and minimal builder**

Generate function/string evidence and canonical table ordering. Keep query APIs tuple-returning.

- [ ] **Step 4: Verify GREEN**

Run focused tests and existing Phase 7A analysis tests.

---

### Task 2: Branch labels, explicit names, and evidence merging

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/symbols.py`
- Modify: `tests/unit/test_analysis_symbols.py`

**Interfaces:**
- Extends `build_symbol_table()` with CFG local-branch and `SymbolCandidate` evidence.

- [ ] **Step 1: Write failing merge/branch tests**

Cover local branch labels, external branch exclusion, explicit name override at a function address, explicit-only named symbols, strongest confidence selection, and stable evidence union.

- [ ] **Step 2: Verify RED**

Run focused tests and confirm the minimal builder does not yet satisfy them.

- [ ] **Step 3: Implement merge precedence**

Accumulate internal evidence per `(component, address)`, choose structural kind/function mode, apply explicit naming priority, and generate names only when no explicit name exists.

- [ ] **Step 4: Verify GREEN**

Run all symbol tests plus Phase 7A–7C analysis tests.

---

### Task 3: Component validation, public API, docs, and integration

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/symbols.py`
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`
- Modify: `tests/unit/test_analysis_symbols.py`

**Interfaces:**
- Export `Symbol`, `SymbolKind`, `SymbolTable`, `build_symbol_table` from `nds_disassembly_toolkit.analysis`.

- [ ] **Step 1: Add failing validation/public API tests**

Reject duplicate component names, records outside known components, inconsistent explicit candidate offsets, and empty explicit names. Assert root-package exports.

- [ ] **Step 2: Verify RED**

Confirm validation/export behavior is absent.

- [ ] **Step 3: Implement validation and exports**

Validate by component name only; overlapping runtime ranges remain valid and distinct.

- [ ] **Step 4: Update documentation/provenance**

Document component-aware symbols, auto-name precedence, and that Phase 7D is toolkit-owned logic with no new third-party code/dependency.

- [ ] **Step 5: Run full quality gates**

Run full pytest, Ruff, and strict mypy through repository CI.

- [ ] **Step 6: Open PR and merge only after exact-head CI**

Squash-merge only after every gate passes, then verify push CI on `main`.
