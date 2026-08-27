# Phase 7A Function Discovery Design

## Status

Approved continuation of the post-migration Phase 7 analysis roadmap on 2026-08-27.

## Goal

Add a conservative, reusable function-discovery core for Nintendo DS ARM9/ARM7 executable components. The new layer must decode ARM and Thumb instructions semantically, recover functions from explicit seeds and direct calls, preserve evidence for every discovery, and remain generic rather than game-specific.

## Scope

Phase 7A includes:

- a Capstone-backed ARM/Thumb decoder abstraction;
- typed instruction-set and decoded-instruction models;
- explicit function seeds with source/evidence metadata;
- recursive discovery of statically resolvable direct call targets;
- ARM/Thumb interworking for direct BL/BLX targets;
- conservative fallthrough through ordinary instructions and conditional branches;
- termination at returns, unconditional direct branches, decode failure, or component boundaries;
- compatibility with the existing `arm_function_starts`, `nearest_function_start`, and `function_address_for_reference` helpers;
- deterministic results suitable for later CFG, xref, symbol, and analysis-database phases.

Phase 7A does not include:

- indirect-call target recovery;
- jump-table recovery;
- full basic-block/CFG persistence;
- global xref databases;
- data-flow analysis;
- emulator integration;
- decompilation.

Those remain Phase 7B and later concerns.

## Architecture

### Decoder boundary

Create `analysis/decoder.py` as the only module that imports Capstone. It exposes toolkit-owned immutable records rather than leaking Capstone objects into public APIs. This keeps the analysis model stable if the backend changes later.

The decoder supports Nintendo DS-relevant little-endian ARM and Thumb modes. It records address, size, bytes, mnemonic, operand text, semantic control-flow kind, direct target when statically resolvable, and target instruction set when a direct interworking instruction determines it.

### Function discovery

Create `analysis/functions.py` for worklist-based discovery. `discover_functions()` receives a `Component` plus explicit `FunctionSeed` values. It decodes each seed linearly, records direct call targets as new seeds, and stops each path conservatively when control flow becomes non-local or unknowable.

A direct call within the same component becomes a discovered function. Targets outside the component are retained as call evidence but are not emitted as component-local functions. Duplicate seeds merge evidence deterministically.

### Existing heuristics

`analysis/arm.py` remains intact. Its ARM prologue scan is a heuristic and is not promoted to authoritative function discovery. A caller may explicitly convert heuristic results into seeds later; Phase 7A keeps that distinction visible to avoid treating arbitrary data as code.

### Public models

Extend `analysis/model.py` with:

- `InstructionSet`: `ARM` or `THUMB`;
- `ControlFlowKind`: ordinary, call, branch, return;
- `DecodedInstruction`;
- `FunctionSeed`;
- `FunctionCandidate`;
- `FunctionDiscoveryResult`.

Addresses are runtime addresses. `FunctionCandidate.offset` remains component-relative for interoperability with the existing analysis package.

## Dependency policy

Add Capstone as a normal runtime dependency. Use only the stable Python API shared by Capstone 5/6-era bindings (`Cs`, ARM/Thumb modes, instruction groups, operands, and detail mode). Do not vendor Capstone code.

Capstone is permissively licensed; provenance documentation should identify it as a runtime dependency/reference. angr and melonDS remain reference sources in Phase 7A and are not runtime dependencies.

## Error handling

- Invalid or misaligned seeds raise `ValueError` before discovery starts.
- Decode failure terminates only the affected path and is recorded as evidence; it does not crash discovery of unrelated seeds.
- Indirect branches/calls are not guessed.
- Component boundary checks are mandatory before decoding or enqueuing local targets.

## Determinism

Results are sorted by `(address, instruction_set)` and evidence strings are stable and de-duplicated. Discovery must not depend on set iteration order.

## Testing

Use synthetic ARM/Thumb byte sequences so tests prove exact behavior without depending on a copyrighted ROM.

Required cases:

1. decoder classifies an ARM `BL` and resolves its absolute direct target;
2. discovery follows an ARM direct call and emits both caller and callee once;
3. duplicate call/explicit evidence merges rather than duplicating functions;
4. out-of-component direct targets are not emitted as local functions;
5. ARM-to-Thumb direct interworking records the correct target mode;
6. invalid alignment is rejected;
7. all legacy ARM heuristic tests remain unchanged and passing.

## Compatibility and future phases

No Bakugan-specific profile, address, Gate, or gameplay policy belongs in this feature. Phase 7B should consume the decoder and function-discovery records to construct basic blocks and CFG edges rather than re-decoding instructions through a separate backend.
