# Phase 7L Type, Pointer, and Structure Recovery Implementation Plan

> **Execution mode:** RED → minimal GREEN → focused regression → full quality gate → commit.
> Keep the Phase 7I/7K public decompiler contract stable.

**Goal:** Recover conservative pointer and structure information from Phase 7K SSA and memory
accesses, then use that evidence to produce typed pseudo-C without alias guessing.

**Base:** `48ba7d420f15c4be606aabdc9b79f24a2c6059dd`

**Branch:** `phase-7l-type-structure-recovery`

**Design:** `docs/superpowers/specs/2026-09-06-phase-7l-type-structure-recovery-design.md`

## Global constraints

- no new decoder;
- no direct Capstone use outside `analysis/decoder.py`;
- no `.ndsre` schema migration;
- no new runtime dependency;
- no Ghidra/Retypd/RetDec/Miasm/LLVM implementation reuse;
- no general memory SSA;
- no pointer alias guesses;
- no game-specific names or policies;
- preserve component/address/mode identity;
- deterministic algorithms and synthetic names only;
- calls/memory/unknown statements remain side effects;
- unresolved type evidence must widen/fallback, never guess;
- final gate: pytest + Ruff + strict mypy + melonDS + DeSmuME.

## Expected file map

Create:

```text
src/nds_disassembly_toolkit/analysis/decompiler/type_model.py
src/nds_disassembly_toolkit/analysis/decompiler/access_paths.py
src/nds_disassembly_toolkit/analysis/decompiler/structure_recovery.py
src/nds_disassembly_toolkit/analysis/decompiler/type_propagation.py

tests/unit/test_analysis_decompiler_type_model.py
tests/unit/test_analysis_decompiler_access_paths.py
tests/unit/test_analysis_decompiler_structure_recovery.py
tests/unit/test_analysis_decompiler_typed_render.py
tests/unit/test_analysis_decompiler_type_propagation.py
```

Modify only as demonstrated by tests:

```text
src/nds_disassembly_toolkit/analysis/decompiler/model.py
src/nds_disassembly_toolkit/analysis/decompiler/lower.py
src/nds_disassembly_toolkit/analysis/decompiler/render.py
src/nds_disassembly_toolkit/analysis/decompiler/service.py
docs/disassembly-and-analysis.md
docs/provenance-and-licenses.md
README.md
```

Do not modify without a blocker:

```text
src/nds_disassembly_toolkit/analysis/decoder.py
src/nds_disassembly_toolkit/analysis/project/schema.py
src/nds_disassembly_toolkit/analysis/runtime/
src/nds_disassembly_toolkit/analysis/orchestration/
pyproject.toml
```

---

## Task 1 — Type/evidence models and access-path normalization

### RED

Create `test_analysis_decompiler_type_model.py` and
`test_analysis_decompiler_access_paths.py`.

Type contracts:

- integer widths limited to 1/2/4;
- signedness explicit: unknown/unsigned/signed;
- pointer type cannot have an empty component;
- struct fields are deterministic by offset;
- duplicate offset fields rejected;
- overlapping incompatible fields rejected;
- empty structure names rejected;
- evidence preserves source references.

Access-path contracts:

- `base + 0x18` -> root base, offset 0x18;
- `(base + 4) + 8` -> offset 12;
- `base - 4` -> negative offset;
- `base + index * 4 + 0x10` -> root/index/scale/offset;
- two independent index terms -> unresolved;
- arbitrary constant address has no variable root;
- exact SSA references retain value identity;
- undefined SSA reference is unresolved.

### GREEN

Implement immutable models in `type_model.py`.

Implement a pure normalizer in `access_paths.py` over Phase 7K SSA expressions. It must not
inspect rendered text.

Commit after focused tests + full pytest/Ruff/mypy.

---

## Task 2 — Field-access evidence collection

### RED

Extend access-path/structure tests for:

- memory read with root+offset;
- memory write with root+offset;
- width 1/2/4;
- source provenance;
- negative offset excluded from field evidence;
- scaled-index access recorded separately from direct field evidence;
- unresolved address remains absent rather than guessed.

### GREEN

Add immutable `FieldAccessEvidence` records:

```text
root
offset
width
read/write
index
scale
source
```

Collector walks SSA statements/expressions deterministically.

No layout inference yet.

---

## Task 3 — Local pointer roots and structure candidates

### RED

Required cases:

- two fields on one argument produce one candidate;
- repeated same field merges evidence;
- compatible read/write merges;
- incompatible same-offset widths conflict;
- overlapping fields conflict;
- copied SSA values resolve to same canonical root;
- PHI with one unique root resolves;
- PHI with conflicting roots does not unify;
- two different parameters with same offsets remain separate;
- deterministic synthetic name and field names.

### GREEN

Implement `StructureCandidate`, `RecoveredStructField`, and local root canonicalization.

Initial emission threshold:

- >=2 distinct fields; or
- same field from >=2 source sites; or
- explicit interprocedural support flag.

Conflicted candidates remain available diagnostically but are not applied to pseudo-C.

---

## Task 4 — Scalar/pointer type environment

### RED

Cases:

- dereference proves pointer-like root;
- access width proves scalar field width;
- signed compare adds signed evidence;
- unsigned compare adds unsigned evidence;
- conflicting signedness becomes unknown;
- address facts retain component only when proven;
- naked constant does not become a pointer.

### GREEN

Implement a deterministic local type environment keyed by SSA/root identity.

Do not add full Retypd-style subtype solving.

---

## Task 5 — Typed source-like IR and renderer

### RED

Add `test_analysis_decompiler_typed_render.py`.

Required output behavior:

- unresolved access remains `*(uint32_t *)(arg0 + 0x18)`;
- qualified candidate renders `arg0->field_18`;
- writes render `arg0->field_18 = value;`;
- emitted struct fields use access widths;
- typed argument renders `struct struct_name *arg0`;
- no unused struct declaration;
- raw fallback remains deterministic;
- no SSA suffixes leak.

### GREEN

Add `FieldAddressExpression` to source-like IR.

Extend lowering/annotation stage and renderer only enough to consume recovered type environment.

Existing `MemoryReadExpression` / `MemoryWriteStatement` remain effect model.

---

## Task 6 — Interprocedural type propagation

### RED

Cases:

- caller unique root -> direct callee argument;
- same recovered candidate unifies across direct call;
- transitive A→B→C fixed point;
- conflicting candidates do not merge unsafely;
- ambiguous overlay target does not propagate;
- caller/callee same numeric address in different components remains separate;
- deterministic cap/non-convergence warning.

### GREEN

Implement bounded project-level propagation over persisted direct call identities and local
recovery results.

No persistence change.

---

## Task 7 — Service integration

### RED

Representative end-to-end decompile tests should show:

- Phase 7K cleanup still occurs;
- type recovery runs after SSA simplification;
- field syntax appears only with threshold-satisfying evidence;
- ARM and Thumb;
- read-only project behavior;
- deterministic text and JSON compatibility;
- no project write.

### GREEN

Integrate:

```text
lift
→ SSA
→ ValueFacts
→ simplify
→ local type/structure recovery
→ optional interprocedural refinement
→ typed lowering/annotation
→ existing structure
→ render
```

---

## Task 8 — Documentation/provenance/release

Update README, static-analysis docs, and provenance.

Record external reference boundary:

- Ghidra: Apache-2.0 architecture/reference;
- Retypd/BTI implementations: GPL-family reference only;
- structure-recovery papers: algorithmic literature reference only;
- no copied/ported implementation source.

Audit:

- no dependency change;
- no schema change;
- no decoder change;
- no runtime/orchestration change;
- no game coupling;
- no third-party vendoring.

Final exact-head gate:

```text
pytest
ruff check
strict mypy
stock melonDS live smoke
managed DeSmuME live smoke
```

Then ready PR, squash with expected-head protection, and require fresh post-merge `main` CI.
