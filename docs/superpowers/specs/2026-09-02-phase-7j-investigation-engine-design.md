# Phase 7J Investigation/Prioritization Engine Design

## Goal

Phase 7J turns the existing static-analysis project, runtime differential evidence, annotations, symbols, strings, constants, call relationships, and pseudo-C into one deterministic investigation workflow that answers a practical reverse-engineering question:

> Which functions should I inspect next, and why?

The phase is an evidence-fusion and prioritization layer. It does not add a second decoder, a second CFG/data-flow engine, a new persistence schema, or new runtime transport.

## Architectural boundary

Phase 7J is read-only with respect to `.ndsre` and `.ndstrace` data. It consumes the public `AnalysisProject`, runtime trace-differential, and decompiler services already delivered by Phases 7F through 7I.

The new subsystem lives under `analysis/investigation/` and owns only:

- investigation selectors;
- evidence normalization;
- per-function score contributions;
- one-hop call-neighbor propagation;
- deterministic ranking/explanations;
- optional pseudo-C previews for the ranked output.

Existing subsystems remain authoritative for their own data:

- `AnalysisProject` owns persisted functions, CFGs, xrefs, strings, symbols, annotations, and data-flow records;
- runtime tracing owns `.ndstrace` capture, inspection, behavioral diffing, and runtime-specific function ranking;
- the decompiler owns pseudo-C generation.

No Phase 7J code parses assembly operand strings or reaches into SQLite tables directly.

## Investigation input

The public request model is `InvestigationRequest`.

It supports these independent selectors:

- `text`: case-insensitive substring matched against persisted strings and user-authored annotation name/comment/tags;
- `constants`: exact integer values matched against typed immediate operands in persisted CFG instructions;
- `addresses`: exact target addresses matched through persisted cross-references;
- optional `component`: restrict candidate functions and static evidence sources to one component;
- optional `baseline_trace` + `target_trace`: must be supplied together and add runtime differential evidence;
- `top`: positive bounded result count;
- `include_pseudo_c`: render pseudo-C only for functions that survive ranking/truncation.

At least one of `text`, `constants`, `addresses`, or the trace pair is required. A request with no evidence selectors is rejected rather than silently producing arbitrary complexity-based rankings.

The request does not accept game-specific concepts such as G-Power, HP, encounter IDs, or overlay names beyond the generic component selector.

## Function identity

Every candidate is identified by:

`(component, runtime_address, instruction_set)`

This preserves the overlay-aware identity established in Phase 7D. Numerical address equality never merges functions from different components.

## Static evidence collection

### Text evidence

For a text query, the collector searches:

1. persisted `StringRecord.text` values;
2. persisted `LocationAnnotation.name_override`;
3. persisted `LocationAnnotation.comment`;
4. persisted annotation tags.

A matched string contributes to functions with an xref to that string's address. A matched annotation directly contributes when the annotated address is a persisted function entry. For annotations on non-entry addresses, containing functions are resolved through persisted instruction ownership when possible.

Generated symbol names are used as candidate display names and explanation context. Exact generated names are not treated as free-text evidence unless they are attached to a location reached by another selector; this avoids requiring a broad new symbol-enumeration API in Phase 7J.

### Constant evidence

Constants are recovered only from typed `InstructionOperand` records already persisted inside CFG instructions.

A constant matches when an operand has `OperandKind.IMMEDIATE` and the exact signed integer payload equals the requested value. The engine never parses `DecodedInstruction.operands` display text.

Each function receives at most one contribution per requested constant, regardless of how many instructions repeat the same value. Explanations retain the deterministic sorted instruction addresses that established the match.

### Address/xref evidence

Requested addresses are matched with `AnalysisProject.xrefs_to()`. References with persisted source-function identity contribute to that function. References without a source-function identity remain visible only as unresolved evidence and do not create a guessed function.

## Runtime differential evidence

When both trace paths are present, Phase 7J calls the existing runtime differential API with the same read-only `AnalysisProject`.

The Phase 7H2 runtime score is normalized into the range `[0, 1]` and becomes one investigation feature. Phase 7J does not reimplement runtime event correlation, memory-diff detection, target-only classification, condition-stop logic, or trace fingerprint validation.

Runtime reasons are copied into the investigation evidence in deterministic order so the final report can explain whether a candidate was target-exclusive, changed-frequency, condition-hit, memory-related, or a runtime dynamic neighbor.

## Evidence model and scoring

The model contains:

- `InvestigationEvidenceKind`
- `InvestigationEvidence`
- `InvestigationCandidate`
- `InvestigationReport`

Each evidence item stores:

- kind;
- normalized value in `[0, 1]`;
- fixed weight;
- contribution (`value * weight`);
- deterministic reason strings;
- optional supporting addresses.

Phase 7J uses fixed transparent weights:

| Feature | Weight |
| --- | ---: |
| runtime differential | 0.35 |
| matching string/text evidence | 0.25 |
| matching constant | 0.20 |
| requested-address xref | 0.15 |
| one-hop call neighbor | 0.05 |

Weights sum to `1.00`. Static features are binary per candidate after deduplication. Runtime differential uses the existing normalized runtime score, capped to `[0, 1]` defensively.

A candidate's score is the sum of contributions. Candidates with score `0` are omitted.

Sort order is exactly:

1. descending score;
2. component;
3. address;
4. instruction-set value.

This makes repeated runs byte-for-byte stable given the same project and traces.

## Call-neighbor propagation

After direct evidence is collected, Phase 7J performs one deterministic call-graph expansion.

A candidate receives the `call_neighbor` feature when either:

- it directly calls a function with non-neighbor evidence; or
- it is directly called by a function with non-neighbor evidence.

Only persisted `CrossReferenceKind.CALL` edges qualify. Propagation is exactly one hop and never recursively feeds from neighbor-only candidates. This keeps ranking explainable and prevents score diffusion through large SDK call graphs.

Ambiguous call targets caused by overlapping component address ranges are not guessed. A callee relationship is accepted only when exactly one persisted function identity matches target address + instruction set.

## Names and pseudo-C

Each ranked candidate includes:

- persisted function identity;
- generated symbols at the function entry;
- user annotation at the function entry;
- a deterministic display name using annotation override first, then the first generated function/name symbol, then `sub_XXXXXXXX`;
- evidence list;
- total score.

If `include_pseudo_c` is true, pseudo-C is generated with the existing `decompile_function()` service only after ranking and `top` truncation. Decompiler failure for one candidate does not discard the ranking; the candidate records a `pseudo_c_error` string and continues.

Pseudo-C is therefore presentation/context evidence, not a hidden score source. Phase 7J never decompiles every function merely to rank it.

## Public API

The primary service is:

```python
investigate_project(
    project: AnalysisProject,
    request: InvestigationRequest,
) -> InvestigationReport
```

The service never closes the supplied project and never mutates it.

The subsystem is exported from `nds_disassembly_toolkit.analysis`.

## CLI

Phase 7J adds:

```text
nds-toolkit project investigate PROJECT [selectors]
```

Selectors:

- `--text TEXT`
- repeatable `--constant VALUE`
- repeatable `--address ADDRESS`
- `--component NAME`
- `--baseline TRACE --target TRACE`
- `--top N` (default `25`, maximum `250`)
- `--decompile`
- `--json`
- existing atomic `--output PATH`

`--constant` and `--address` accept the same integer syntax as existing project/runtime CLI address parsing, including `0x` hexadecimal.

The command opens `.ndsre` read-only. Offline investigation with no traces never connects to melonDS. When traces are supplied, both paths are required and are read offline through the existing trace store.

Human output is a concise ranked list with score, function identity/name, and indented reasons. JSON output is canonical and includes request metadata, evidence contributions, symbols/annotation summary, and optional pseudo-C.

## Errors

Invalid request combinations raise `InvestigationError`, a toolkit error type mapped by the CLI through the existing analysis-project error path.

Examples:

- no selector supplied;
- only one trace of the required pair supplied;
- `top <= 0` or `top > 250`;
- malformed integer selector;
- requested component absent from the project.

Existing `RuntimeTraceMismatchError`, `RuntimeTraceFormatError`, `DecompilerError`, and `AnalysisProjectError` remain authoritative and are not hidden.

## Testing

The TDD suite must cover:

- overlay-safe candidate identity;
- text → string → xref → function ranking;
- annotation text evidence;
- typed-immediate constant matching in ARM and Thumb CFGs;
- address/xref matching;
- deduplication of repeated static evidence;
- one-hop caller and callee propagation without recursive diffusion;
- ambiguous overlapping call targets are not guessed;
- runtime differential score fusion through the existing Phase 7H2 API;
- deterministic score/evidence ordering and tie-breaking;
- pseudo-C generated only for truncated top candidates;
- pseudo-C failure retained as candidate context rather than aborting ranking;
- CLI validation before project/trace work;
- canonical JSON and atomic `--output`;
- read-only project behavior;
- no melonDS connection for offline investigation.

The final full gate remains pytest + Ruff + strict mypy + existing stock-melonDS live interoperability CI.

## Explicitly deferred

Phase 7J does not add:

- structure/type inference;
- function similarity/signature databases;
- angr/symbolic execution;
- semantic ROM-to-ROM diffing;
- multi-hop probabilistic call-graph propagation;
- machine-learned ranking weights;
- persistence of investigation reports;
- a GUI.

Those remain later acceleration phases. Phase 7J's job is to make the evidence already recovered by 7A–7I immediately actionable and explainable.