# Phase 3: Generic Disassembly and Analysis Core

**Status:** Contract tests first; implementation pending.

## Goal

Migrate the proven Nintendo DS executable/disassembly and binary-analysis primitives from `Bakugan-DS-` into the standalone toolkit while preserving their behavior and keeping Bakugan-specific inference and reference catalogs in the game repository.

## Reuse rule

Reuse existing tested algorithms unless a change is required to remove game coupling or to expose a stable generic API. Do not rewrite working logic for style.

## Toolkit scope

- Nitro module-parameter discovery and parsing.
- Overlay layout/load relationship reporting.
- Labelled byte rendering for flat executable components.
- GNU ARM objdump command construction and execution.
- Deterministic unified disassembly diffs.
- Generic component/address models.
- ARM function-start heuristics.
- ASCII string extraction/filtering and little-endian pointer-reference scanning.
- Generic scaled-byte numeric row scanning and clustering.
- Generic component analysis/report generation.
- CLI integration for generic disassembly operations and component analysis.

## Explicitly left in Bakugan

- Bakugan/Gate/Ability CSV import and catalog schema.
- Bakugan-specific keywords and G-Power naming.
- `gp_pickup2` / `gp_down` inference.
- `Candidate_GPEffect_*` symbol naming.
- B6RE addresses, hashes, overlay IDs, and verified game-specific metadata.
- Bakugan Ghidra symbol artifacts and reference-ROM assertions.

## Safety and correctness invariants

- Analysis is read-only unless writing a requested report/output file.
- Runtime addresses and component-relative offsets remain explicit and distinct.
- Component names must be unique within a report.
- Pointer scans use little-endian 32-bit addresses.
- External objdump failures become expected toolkit errors with diagnostic output.
- Label requests outside a component are rejected.
- Reports are deterministic and written atomically.
- No ROMs, extracted assets, or game-specific proprietary data are committed.
