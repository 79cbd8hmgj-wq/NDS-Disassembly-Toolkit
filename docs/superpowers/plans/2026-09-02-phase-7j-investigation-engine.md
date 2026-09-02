# Phase 7J Investigation/Prioritization Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only evidence-fusion engine and `project investigate` CLI that ranks persisted functions by static and runtime relevance and explains every score contribution.

**Architecture:** Create a focused `analysis/investigation/` package. It consumes public `AnalysisProject`, runtime `compare_traces()`, typed CFG semantics, and `decompile_function()` APIs; it does not query SQLite directly or duplicate decoding/runtime/decompilation logic. Static evidence is collected first, one-hop CALL neighbors are added second, runtime scores are fused third, then deterministic ranking/truncation occurs before optional pseudo-C rendering.

**Tech Stack:** Python 3.11+, dataclasses/enums, existing SQLite-backed `AnalysisProject`, existing `.ndstrace` runtime APIs, pytest, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-09-02-phase-7j-investigation-engine-design.md`

## Global Constraints

- `.ndsre` and `.ndstrace` access is read-only for Phase 7J.
- No new runtime dependency.
- No `.ndsre` schema migration.
- No second decoder, CFG engine, runtime correlator, trace-diff engine, or decompiler.
- Function identity is `(component, runtime_address, instruction_set)`.
- Constant matching uses typed `InstructionOperand` values only; never parse display operand strings.
- Call-neighbor propagation is exactly one hop and never recursively propagates neighbor-only evidence.
- Ranking is deterministic: `(-score, component, address, instruction_set.value)`.
- CLI `--top` range is `1..250`; default is `25`.
- Final gate is full pytest + Ruff + strict mypy + existing stock-melonDS live CI.

---

### Task 1: Investigation models and request validation

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/investigation/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/investigation/__init__.py`
- Modify: `src/nds_disassembly_toolkit/errors.py`
- Test: `tests/unit/test_analysis_investigation_model.py`

**Interfaces:**
- Produces `InvestigationEvidenceKind`, `InvestigationRequest`, `InvestigationEvidence`, `InvestigationCandidate`, `InvestigationReport`, and `InvestigationError`.
- `InvestigationRequest.validate()` enforces selectors, trace pairing, and top bound.

- [ ] **Step 1: Write failing model/validation tests** covering immutable records, missing-selector rejection, one-sided trace rejection, and top bounds.
- [ ] **Step 2: Run the focused tests and verify RED** because `analysis.investigation` does not exist.
- [ ] **Step 3: Implement the minimal records and validation.** Fixed evidence weights are declared by the service, not user-configurable request data.
- [ ] **Step 4: Run focused tests and the existing analysis model tests; verify GREEN.**
- [ ] **Step 5: Commit** with `feat: define investigation ranking models`.

### Task 2: Static evidence collection

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/investigation/service.py`
- Test: `tests/unit/test_analysis_investigation_static.py`

**Interfaces:**
- Produces `investigate_project(project: AnalysisProject, request: InvestigationRequest) -> InvestigationReport`.
- Internal candidate key is `tuple[str, int, InstructionSet]`.

- [ ] **Step 1: Write failing tests** for text→string→xref, annotation text, ARM/Thumb typed-immediate constant matches, requested address xrefs, component restriction, repeated-evidence dedupe, overlay-safe identities, and deterministic direct-evidence ordering.
- [ ] **Step 2: Run focused tests and verify RED** for missing `investigate_project` behavior.
- [ ] **Step 3: Implement static collection.** Iterate `project.functions()`, load persisted CFGs only when constants are requested, use `project.strings()`, `project.annotations()`, `project.xrefs_to()`, `project.xrefs_from_function()`, `project.symbols_at()`, and `project.functions_containing()`; never use private project connection state.
- [ ] **Step 4: Run focused tests + project persistence tests and verify GREEN.**
- [ ] **Step 5: Commit** with `feat: collect static investigation evidence`.

### Task 3: One-hop call neighbors and runtime fusion

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/investigation/service.py`
- Test: `tests/unit/test_analysis_investigation_ranking.py`

**Interfaces:**
- Uses existing `compare_traces(baseline, target, project=project)`.
- Fixed weights: runtime `0.35`, text `0.25`, constant `0.20`, address xref `0.15`, call neighbor `0.05`.

- [ ] **Step 1: Write failing tests** for caller propagation, callee propagation, no recursive neighbor diffusion, overlapping/ambiguous target refusal, runtime score fusion, score capping, transparent reason preservation, and deterministic tie-breaking.
- [ ] **Step 2: Run focused tests and verify RED.**
- [ ] **Step 3: Implement one-hop CALL expansion** using only direct non-neighbor candidate keys and persisted call xrefs. Resolve callee target address+mode only when exactly one persisted function matches.
- [ ] **Step 4: Fuse existing runtime rankings** by candidate identity, copy runtime reason text, normalize score with `min(1.0, max(0.0, runtime_score))`, calculate contributions, omit zero-score candidates, and sort deterministically.
- [ ] **Step 5: Run focused tests plus Phase 7H2 trace-ranking tests; verify GREEN.**
- [ ] **Step 6: Commit** with `feat: fuse runtime and call evidence`.

### Task 4: Candidate naming and pseudo-C previews

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/investigation/service.py`
- Modify: `src/nds_disassembly_toolkit/analysis/investigation/model.py`
- Test: `tests/unit/test_analysis_investigation_pseudoc.py`

**Interfaces:**
- Display name precedence: annotation `name_override` → first generated entry symbol whose kind is function/named → `sub_XXXXXXXX`.
- Optional pseudo-C uses existing `decompile_function()` only after deterministic ranking and `top` truncation.

- [ ] **Step 1: Write failing tests** for display-name precedence, `top` truncation before decompilation, pseudo-C attached to selected candidates only, and per-candidate decompiler failure captured as `pseudo_c_error` without aborting the report.
- [ ] **Step 2: Run focused tests and verify RED.**
- [ ] **Step 3: Implement naming/pseudo-C enrichment** without changing score or candidate order.
- [ ] **Step 4: Run focused tests plus Phase 7I decompiler-service tests; verify GREEN.**
- [ ] **Step 5: Commit** with `feat: enrich investigation results with pseudo-c`.

### Task 5: Public exports and project CLI

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `src/nds_disassembly_toolkit/analysis/project_cli.py`
- Test: `tests/unit/test_analysis_investigation_exports.py`
- Test: `tests/unit/test_analysis_project_cli_investigate.py`

**Interfaces:**
- CLI: `nds-toolkit project investigate PROJECT`.
- Options: `--text`, repeatable `--constant`, repeatable `--address`, `--component`, `--baseline`, `--target`, `--top`, `--decompile`, `--json`, `--output`.

- [ ] **Step 1: Write failing export and parser/dispatch tests.** Validate malformed integer selectors, empty request, trace pairing, and top bounds before opening project/traces.
- [ ] **Step 2: Run focused tests and verify RED.**
- [ ] **Step 3: Export the Phase 7J API** from `analysis` and add `project investigate` parser wiring following existing project CLI conventions.
- [ ] **Step 4: Implement dispatch:** open project read-only, build `InvestigationRequest`, call service, render concise human output or canonical JSON, and reuse atomic output writing.
- [ ] **Step 5: Add JSON snapshot assertions** for canonical hex formatting, evidence contributions/reasons, annotation/symbol context, and optional pseudo-C.
- [ ] **Step 6: Run project CLI tests + full focused Phase 7J suite; verify GREEN.**
- [ ] **Step 7: Commit** with `feat: expose project investigation cli`.

### Task 6: Integration, documentation, and final verification

**Files:**
- Modify: `README.md`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`
- Test: `tests/integration/test_investigation_workflow.py`

**Interfaces:**
- End-to-end flow: synthetic `.ndsre` + optional `.ndstrace` → investigation report → deterministic ranked candidate → optional pseudo-C.

- [ ] **Step 1: Write the integration test first** using only public project/runtime/investigation APIs.
- [ ] **Step 2: Run it and verify RED** for any missing final public integration behavior.
- [ ] **Step 3: Make only the minimal integration fixes required, then verify GREEN.**
- [ ] **Step 4: Document** selector semantics, weights, overlay identity, runtime trace pairing, read-only behavior, pseudo-C enrichment, and examples.
- [ ] **Step 5: Update provenance** to state Phase 7J is original evidence-fusion logic built on toolkit-owned analysis outputs and does not incorporate third-party ranking/decompiler implementation.
- [ ] **Step 6: Run full verification:** `pytest`, `ruff check .`, and strict `mypy src`; require existing stock-melonDS live CI on the exact head.
- [ ] **Step 7: Audit the branch diff** against Phase 7I main: no `pyproject.toml` dependency change, no `.ndsre` schema change, no runtime RSP changes, no decoder duplication, no game-specific material, no SQLite access in `analysis/investigation/`.
- [ ] **Step 8: Update PR description, require mergeable/head-stable state, squash-merge with expected-head protection, then require fresh post-merge `main` CI.**
