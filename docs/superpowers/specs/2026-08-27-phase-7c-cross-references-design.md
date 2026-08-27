# Phase 7C Cross-References and Call Graphs Design

## Status

Approved continuation of the Phase 7 analysis roadmap on 2026-08-27.

## Goal

Build a deterministic cross-reference layer over the Phase 7A/7B analysis records so callers can answer who references an address, what an address references, and what direct calls leave a function without re-decoding executable bytes.

## Scope

Phase 7C includes:

- normalized code xrefs from Phase 7B `CALL` and `BRANCH` edges;
- normalized data xrefs from existing `PointerReference` records;
- immutable xref records preserving source component/function/callsite and ARM/Thumb mode when known;
- deterministic source/target query indexing;
- a derived direct-call graph edge view;
- public API exports and documentation.

Phase 7C does not include:

- symbol naming or symbol databases;
- string semantic inference;
- indirect-target guessing;
- jump-table recovery;
- data-flow analysis;
- persistent on-disk analysis databases;
- CLI query commands.

Those remain Phase 7D and later concerns.

## Architecture

Create `analysis/xrefs.py`. It consumes toolkit-owned `FunctionControlFlowGraph`, `CFGEdge`, and `PointerReference` records only; it does not import Capstone.

Add toolkit-owned models in `analysis/model.py`:

- `CrossReferenceKind`: `CALL`, `BRANCH`, `DATA_POINTER`;
- `CrossReference`;
- `CallGraphEdge`;
- `CrossReferenceIndex`.

A code xref uses the CFG edge's source instruction as `source_address`, records the owning function address, and preserves target instruction-set metadata. Fallthrough edges are deliberately excluded because they are CFG topology rather than semantic cross-references.

A data-pointer xref uses the pointer field's runtime address as `source_address`, has no source function or instruction-set metadata, and targets the referenced runtime address.

`CrossReferenceIndex` stores one deterministic tuple and provides filtered tuple-returning queries rather than mutable maps in its public API. Internal lookup maps may be added later if profiling shows they are necessary.

## Call graph

`build_call_graph()` derives one `CallGraphEdge` per direct call xref. Each edge records caller component, caller function address, callsite address, target runtime address, and target instruction set. It does not require the callee to be locally discovered or to belong to the same component.

## Determinism

All xrefs and call-graph edges are de-duplicated and sorted by stable structural keys. Query results retain that stable order.

## Error handling

No input record is mutated. Empty sequences are valid and produce empty outputs. Phase 7C trusts typed Phase 7A/7B records and does not invent missing source-function or target-mode information for pointer references.

## Testing

Required cases:

1. branch/call CFG edges become code xrefs while fallthrough is excluded;
2. ARM-to-Thumb call target mode survives normalization;
3. `PointerReference` becomes a data-pointer xref;
4. duplicate inputs de-duplicate deterministically;
5. target/source queries return stable filtered tuples;
6. direct-call graph contains only call xrefs and retains external targets;
7. public exports are available from `nds_disassembly_toolkit.analysis`.

## Compatibility

Phase 7C does not alter Phase 7A function discovery or Phase 7B CFG behavior. Phase 7D symbol recovery should annotate or consume these xrefs rather than creating a separate reference model.
