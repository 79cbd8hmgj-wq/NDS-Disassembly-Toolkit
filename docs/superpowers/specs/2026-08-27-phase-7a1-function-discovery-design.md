# Phase 7A1 Function Discovery Core Design

## Goal

Add the first program-analysis layer above the toolkit's existing byte scanners: typed ARM/Thumb instruction decoding and conservative recursive function discovery for Nintendo DS executable components.

## Scope

Phase 7A1 will:

- use Capstone as the instruction-decoding backend;
- model ARM and Thumb execution modes explicitly;
- decode one instruction at a runtime address with control-flow metadata;
- accept explicit function seeds such as ARM9/ARM7 entry points or known overlay entry points;
- follow reachable direct control flow inside a component;
- promote in-component direct call targets to function candidates;
- propagate ARM/Thumb mode through direct BLX targets;
- stop paths at returns and unresolved indirect unconditional transfers;
- retain the existing ARM prologue helpers as compatibility/evidence helpers;
- attach confidence and evidence to every discovered function;
- remain game-neutral.

Phase 7A1 will not yet build persistent basic-block graphs, xref databases, data-flow facts, symbol databases, emulator traces, or pseudo-C. Those belong to later Phase 7 slices.

## Dependency policy

The runtime dependency is the current stable Capstone 5 line. The adapter will use API surface shared with the uploaded Capstone `next` source so a later Capstone 6 migration does not require redesigning toolkit-facing models.

angr is architectural reference material only for this slice. melonDS remains reference/integration material only and no GPL implementation is copied into the MIT toolkit.

## Architecture

### `analysis/model.py`

Add immutable, serializable analysis-domain types:

- `ExecutionMode`: `ARM` or `THUMB`.
- `ControlFlowKind`: `FALLTHROUGH`, `CALL`, `BRANCH`, `RETURN`, `INDIRECT_BRANCH`.
- `DecodedInstruction`: runtime address, size, mode, mnemonic, operand text, control-flow kind, optional direct target, optional target mode, and conditional flag.
- `FunctionSeed`: runtime address, execution mode, evidence string, confidence string.
- `FunctionCandidate`: component name, runtime address, file offset, execution mode, confidence, and deduplicated evidence.
- `FunctionDiscoveryResult`: discovered functions plus addresses of unresolved indirect transfers.

The public model must not expose Capstone classes or numeric Capstone constants.

### `analysis/decoder.py`

Add `CapstoneArmDecoder`, which owns one ARM and one Thumb Capstone engine with detailed decoding enabled. It exposes:

```python
def decode_one(component: Component, address: int, mode: ExecutionMode) -> DecodedInstruction | None
```

The adapter is responsible for translating Capstone-specific details into toolkit models. Direct immediate branch/call targets are normalized to runtime addresses. `BLX` immediate targets switch execution mode. Return recognition covers the common Nintendo DS forms needed for conservative recursive descent, including `bx lr` and `pop {..., pc}`.

Invalid or undecodable bytes return `None`; caller-visible Capstone exceptions are not part of the toolkit API.

### `analysis/functions.py`

Add:

```python
def discover_functions(
    component: Component,
    seeds: Iterable[FunctionSeed],
    *,
    decoder: InstructionDecoder | None = None,
) -> FunctionDiscoveryResult
```

Discovery uses a deterministic worklist. Each explicit seed becomes a function candidate. While scanning reachable instructions for a candidate:

- fallthrough continues at the next instruction;
- conditional direct branches enqueue both the branch target and fallthrough path;
- unconditional direct branches enqueue only their target when it remains inside the component;
- direct calls enqueue their fallthrough path and promote in-component targets to function seeds;
- direct BLX calls carry the target execution mode supplied by the decoder;
- returns stop the current path;
- unresolved indirect unconditional branches stop the current path and are reported;
- decoding outside the component or undecodable bytes stops that path.

Addresses are visited per `(address, mode)` so ARM and Thumb interpretations remain distinct. Results are sorted deterministically.

### Compatibility helpers

`analysis/arm.py` keeps `arm_function_starts`, `nearest_function_start`, and `function_address_for_reference` unchanged. A small helper converts prologue matches into medium-confidence `FunctionSeed` values so existing heuristic evidence can feed the new engine without being treated as authoritative.

## Confidence policy

Phase 7A1 uses simple explicit confidence strings compatible with the existing analysis models:

- `high`: explicit entry point or direct call target reached from analyzed code;
- `medium`: legacy ARM prologue heuristic.

When the same function is found repeatedly, evidence is unioned and the strongest confidence wins.

## Error handling

Public discovery rejects seeds outside the component and misaligned seeds for their selected mode. ARM starts must be 4-byte aligned; Thumb starts must be 2-byte aligned. Invalid inputs raise `ValueError` with component/address context.

Capstone decode failures terminate only the affected path; they do not abort analysis of other functions.

## Testing

Tests use real Capstone decoding, not mocks, for representative ARM/Thumb instructions. Unit coverage includes:

- ARM direct call decoding;
- Thumb return decoding;
- BLX mode propagation;
- recursive discovery of an in-component direct callee;
- branch reachability without incorrectly promoting branch targets to functions;
- deterministic evidence merging;
- unresolved indirect transfer reporting;
- seed bounds/alignment validation;
- compatibility of the pre-existing prologue helpers.

The final branch must pass the full pytest suite, Ruff, and strict mypy.