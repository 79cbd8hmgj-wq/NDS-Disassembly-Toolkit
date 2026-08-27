# Phase 7B Control-Flow Graphs Design

## Status

Continuation of the approved Phase 7 analysis roadmap after Phase 7A merged and passed `main` CI on 2026-08-27.

## Goal

Build deterministic basic-block control-flow graphs from the Phase 7A ARM/Thumb decoder and function records without introducing a second decoder, game-specific assumptions, or a heavyweight graph dependency.

## Scope

Phase 7B includes:

- immutable basic-block, edge, unresolved-transfer, and function-CFG models;
- reachable instruction traversal from a `FunctionCandidate` entry point;
- direct unconditional and conditional branch successors;
- call-site edges plus normal fallthrough after calls;
- ARM/Thumb mode preservation on every node and edge;
- unresolved indirect transfers and decode failures;
- basic-block leader recovery after instruction traversal, including backward branches;
- deterministic block and edge ordering;
- public analysis-package exports and documentation.

Phase 7B does not include:

- indirect branch/call target recovery;
- jump-table recovery;
- tail-call classification;
- no-return function inference;
- interprocedural call graphs;
- data/code xrefs;
- data-flow analysis;
- persistent analysis databases;
- emulator integration;
- decompilation.

## Architecture

### Single decoder authority

`analysis/decoder.py` remains the only Capstone boundary. `analysis/cfg.py` consumes `DecodedInstruction` values produced by `decode_instruction()` and must not import Capstone directly.

### Two-pass recovery

CFG construction uses two conceptual passes.

First, traverse reachable instructions from the selected function entry. Record instruction-level local successors, direct call edges, external direct transfers, unresolved indirect transfers, and decode failures. Calls do not enqueue their callee as intraprocedural execution; their fallthrough instruction remains reachable.

Second, derive basic-block leaders from the reachable instruction graph. Leaders include the function entry, local branch targets, and reachable fallthrough addresses after calls or conditional branches. Group sequential instructions until another leader or a control-flow terminator is reached. This avoids mutable block splitting when a backward branch later identifies an address inside an already traversed sequence.

### Control-flow semantics

- Ordinary instruction: continue to the next instruction when it remains inside the component.
- Direct call: record a `CALL` edge to its target, then continue to the next instruction.
- Indirect call: record an unresolved transfer, then continue to the next instruction.
- Conditional direct branch: record `BRANCH` to the target and `FALLTHROUGH` to the next instruction; traverse both local successors.
- Conditional indirect branch: record an unresolved transfer and preserve the fallthrough path.
- Unconditional direct branch: record `BRANCH` to the target and traverse the target only when local.
- Unconditional indirect branch: record an unresolved transfer and stop that path.
- Return: no successor.
- Decode failure: record the address and stop that path.

A direct target outside the component remains an edge but is not traversed. This preserves useful evidence for later tail-call/xref analysis.

### Public models

Extend `analysis/model.py` with:

- `CFGEdgeKind`: `FALLTHROUGH`, `BRANCH`, `CALL`;
- `BasicBlock` with component, runtime start, relative offset, instruction set, and decoded instructions;
- `CFGEdge` with source block address, source instruction address, target runtime address, target mode, and kind;
- `UnresolvedTransfer` with source instruction metadata and control-flow kind;
- `FunctionControlFlowGraph` with the originating function candidate, blocks, edges, unresolved transfers, and decode failures.

`BasicBlock.size` and `BasicBlock.end_address` are derived from its instruction tuple. No `networkx` dependency is added; later consumers can adapt these stable records to visualization/query libraries.

## Validation

`build_function_cfg(component, function)` rejects a function whose component name does not match, whose entry is outside the component, or whose entry alignment conflicts with its instruction set.

CFG traversal never decodes outside component bounds. Local direct branch targets must satisfy the target instruction-set alignment before being traversed; otherwise the transfer remains unresolved.

## Determinism

Blocks sort by `(address, instruction_set)`. Edges sort by source block, source instruction, edge kind, target address, and target mode. Unresolved transfers and decode failures are similarly stable and de-duplicated.

## Testing

Synthetic ARM/Thumb fixtures must cover:

1. a straight-line function produces one basic block and no edges;
2. a conditional forward branch produces branch/fallthrough blocks and deterministic edges;
3. a backward branch creates a leader inside earlier linear code rather than overlapping blocks;
4. a direct call creates a `CALL` edge and a separate fallthrough block but does not traverse the callee;
5. an external unconditional branch is retained as an edge without decoding outside the component;
6. an indirect branch is reported unresolved;
7. ARM-to-Thumb call edge preserves target mode;
8. invalid function/component inputs are rejected;
9. all Phase 7A tests remain passing.

## Reference boundary

The supplied angr source informed the separation between durable CFG node/edge models and recovery machinery, and its explicit handling of ARM/Thumb decoding mode reinforced the need to carry mode on CFG identities. No angr implementation source is copied, imported, or required at runtime.

## Future phases

Phase 7C should consume `FunctionControlFlowGraph` and Phase 7A discovery output to build code/call xrefs and call graphs. It should not re-decode instructions or invent a parallel basic-block representation.
