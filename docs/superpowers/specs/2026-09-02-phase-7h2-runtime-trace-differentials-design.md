# Phase 7H2 runtime trace and behavioral differential design

Date: 2026-09-02
Status: approved direction; formalized for implementation review
Base: `main` at `61372597461ad119d4787c6ac34356d2f73c39bd`

## Purpose

Phase 7H2 turns the verified Phase 7H1 melonDS debugger bridge into a bounded dynamic-evidence system for reverse engineering. The goal is to answer questions such as "what code executed when I attacked?", "what memory changed when this value changed?", and "which functions are most strongly associated with behavior B instead of behavior A?" using reproducible runtime captures rather than broad manual inspection.

Phase 7H2 must remain game-neutral. It records emulator-observed facts, correlates them with the existing static `AnalysisProject` when available, and produces transparent differential/ranking evidence. It must not add game-specific addresses, labels, rules, or semantic guesses to the toolkit.

## Scope classification

This is architectural. It adds a persisted runtime-trace format, bounded capture engine, memory-differential engine, trace-comparison engine, dynamic/static correlation, ranking logic, CLI commands, and live interoperability verification on top of the Phase 7H1 runtime session.

## Preconditions and inherited guarantees

Phase 7H1 is merged and verified on `main` at `61372597461ad119d4787c6ac34356d2f73c39bd`.

Phase 7H2 inherits these 7H1 boundaries:

- melonDS integration stays behind the external GDB Remote Serial Protocol interface;
- no melonDS implementation code is copied or vendored into the toolkit;
- ARM9 and ARM7 remain independent runtime targets;
- JIT must be disabled while using the melonDS GDB stub;
- the toolkit does not reset the target or mutate game memory on connect;
- runtime/static correlation remains component-safe and never guesses overlay ownership from a numerical address alone;
- the Phase 7H1 RSP transport remains the only debugger transport implementation.

Phase 7H2 builds on `MelonDSSession`; it does not create a second RSP client or bypass the validated session abstraction.

## Approaches considered

### 1. Portable SQLite `.ndstrace` files — selected

Each capture is stored as one independent SQLite file. This provides indexed queries, transactional writes, compact binary memory snapshots, schema versioning, and portability without changing the stable `.ndsre` static-analysis project schema.

### 2. Runtime tables inside `analysis.sqlite`

This would make joins convenient, but it couples potentially large and short-lived runtime captures to long-lived static projects, forces an immediate `.ndsre` schema migration, and risks stale duplicated runtime/static interpretations. Rejected for 7H2.

### 3. JSON/JSONL trace bundles

This is easy to inspect manually but is weaker for binary memory snapshots, indexed comparisons, transactional finalization, and large event sets. It remains suitable as an export/report format, not the primary persistence format.

## Core design decisions

1. **Runtime facts and static interpretation remain separate.** `.ndstrace` stores observed PCs, stops, registers, memory bytes, capture configuration, and provenance. It does not persist copied function names or symbols from `.ndsre`.
2. **`.ndsre` schema version 1 remains unchanged throughout 7H2.** Static correlation occurs at report time through the existing public `AnalysisProject` API.
3. **All captures are bounded.** Every capture has a finite event/step limit and timeout. The CLI never starts an unbounded instruction trace.
4. **Incomplete captures do not become valid final trace files.** Capture writes to a sibling temporary SQLite file, validates/finalizes it, then atomically replaces the requested destination.
5. **Control operations are auditable.** A repeated breakpoint/watchpoint capture may require an advancing single-step after a hit. Such steps are stored as control events and excluded from behavioral hit counts by default instead of being silently hidden.
6. **Ranking is transparent.** Every score exposes its feature values and evidence. No ML or opaque confidence score is introduced in 7H2.
7. **Overlay ambiguity is preserved.** Ambiguous component/function candidates are reported, not collapsed. Ambiguous hits are excluded from function ranking by default so one runtime address cannot artificially credit several overlays.

## Package architecture

Extend the existing runtime package:

```text
src/nds_disassembly_toolkit/analysis/runtime/
├── __init__.py
├── model.py                # existing 7H1 runtime records
├── rsp.py                  # existing 7H1 RSP transport
├── melonds.py              # existing 7H1 session adapter
├── trace_model.py          # trace-owned immutable records
├── trace_store.py          # .ndstrace SQLite persistence
├── capture.py              # bounded capture orchestration
├── memory_diff.py          # before/after memory comparison
└── trace_diff.py           # trace comparison, correlation, ranking
```

CLI integration remains in:

```text
src/nds_disassembly_toolkit/analysis/runtime_cli.py
src/nds_disassembly_toolkit/cli.py
```

No new runtime dependency is required; persistence uses Python's standard-library `sqlite3`.

## Runtime trace model

### Capture modes

```text
TraceCaptureMode
├── STEP
├── BREAKPOINT
└── WATCHPOINT
```

### Event roles

```text
TraceEventRole
├── EVIDENCE
└── CONTROL_ADVANCE
```

`EVIDENCE` events contribute to hit-frequency and behavioral differential calculations.

`CONTROL_ADVANCE` records a debugger single-step performed only to move the target away from a just-hit stop condition before the next repeated capture cycle. Control events remain persisted and inspectable but are excluded from behavioral counts unless a future explicit option requests them.

### Public records

Initial toolkit-owned records:

```text
TraceCaptureConfig
TraceMemoryRegion
TraceEvent
TraceSummary
MemorySnapshot
MemoryChange
TraceAddressDelta
TraceFunctionDelta
TraceDiffReport
FunctionRankEvidence
RankedFunctionCandidate
```

All records are immutable and deterministic in ordering.

### `TraceCaptureConfig`

Contains at minimum:

- CPU;
- capture mode;
- event/step limit;
- debugger timeout;
- breakpoint/watchpoint kind, address, and length when applicable;
- ordered memory regions;
- optional user label;
- optional static-project fingerprint;
- toolkit version;
- trace schema version.

Capture configuration is persisted before runtime collection begins in the temporary database.

### `TraceEvent`

Each event contains:

- zero-based ordinal;
- event role;
- CPU;
- PC;
- CPSR;
- derived ARM/Thumb instruction-set identity;
- normalized runtime stop kind;
- optional signal;
- optional stop address;
- raw stop payload for protocol-level auditability;
- complete canonical register mapping.

The first 7H2 implementation captures registers for every persisted event. If event volume later proves this too expensive, register sampling may become configurable in a later phase; 7H2 does not prematurely add that policy surface.

## `.ndstrace` persistence format

Trace schema version starts at `1` and is independent of the `.ndsre` schema version.

A `.ndstrace` is an SQLite database with the following logical tables.

### `metadata`

Key/value metadata including:

- `trace_schema_version`;
- `toolkit_version`;
- `cpu`;
- `capture_mode`;
- `capture_status`;
- optional label;
- optional static-project fingerprint.

Only finalized files may contain `capture_status=complete`.

### `capture_config`

Single-row normalized capture configuration:

- limit;
- timeout;
- stop-condition kind/address/length when present.

### `events`

One row per persisted event:

- ordinal primary key;
- role;
- PC;
- CPSR;
- instruction set;
- stop kind;
- signal;
- stop address;
- raw stop payload;
- deterministic JSON register mapping.

Addresses are stored as non-negative SQLite integers. CLI/report JSON emits established canonical lowercase hexadecimal strings.

### `memory_regions`

Ordered configured regions:

- region id;
- ordinal;
- optional label;
- base address;
- positive length.

Overlapping regions are allowed because the user may deliberately request them; output preserves configured order.

### `memory_snapshots`

One `BEFORE` and one `AFTER` snapshot per configured region for a successful capture:

- region id;
- phase;
- bytes as SQLite `BLOB`;
- SHA-256 of the bytes.

The initial 7H2 schema does not persist memory at every trace event. Event-by-event memory sampling is explicitly deferred because it multiplies trace size and is not needed for the first behavior-differential workflow.

## Atomic trace creation

`TraceStore.create_atomic(destination, ...)` uses a sibling temporary path in the destination directory.

Successful finalization requires:

1. capture orchestration returns normally;
2. event ordinals are contiguous from zero;
3. configured memory regions have complete BEFORE/AFTER pairs;
4. metadata is updated to `capture_status=complete`;
5. SQLite transaction commits;
6. database integrity check succeeds;
7. connection closes cleanly;
8. the temporary file atomically replaces the requested destination.

On any failure before replacement, the temporary trace is removed and an existing valid destination remains untouched.

7H2 does not add a `--keep-partial` option. Partial-capture recovery can be designed later if real investigations show it is valuable.

## Bounded capture engine

### Step capture

Example:

```bash
nds-toolkit runtime trace capture \
  --cpu arm9 \
  --steps 2000 \
  --output attack.ndstrace
```

The collector performs exactly the requested maximum number of `MelonDSSession.step()` operations unless the target exits or a runtime error occurs first.

Each successful step produces one `EVIDENCE` event.

A target exit is a valid terminal runtime event and completes the trace early. A timeout, connection failure, or protocol failure aborts finalization.

### Repeated breakpoint capture

Example:

```bash
nds-toolkit runtime trace capture \
  --cpu arm9 \
  --break 0x02012340 \
  --events 100 \
  --output attack.ndstrace
```

Each evidence cycle uses the validated 7H1 temporary-breakpoint operation:

1. install the temporary breakpoint;
2. continue until stop;
3. capture the resulting breakpoint snapshot as `EVIDENCE`;
4. remove the breakpoint through the existing 7H1 cleanup path;
5. if another event is required and the target has not exited, perform exactly one single-step while the breakpoint is absent;
6. persist that step as `CONTROL_ADVANCE`;
7. repeat.

The explicit advance step prevents an immediate re-hit at the same stopped instruction. It is never silently counted as target behavior.

### Repeated watchpoint capture

Example:

```bash
nds-toolkit runtime trace capture \
  --cpu arm9 \
  --watch-write 0x02100000 \
  --length 4 \
  --events 100 \
  --output power-write.ndstrace
```

Read, write, and access watchpoint forms mirror the 7H1 semantic watchpoint kinds. The capture loop follows the same evidence/advance pattern as repeated breakpoints so immediate retrigger behavior is bounded and auditable.

The toolkit must not claim a stronger read-vs-write distinction than melonDS actually reports through its debugger interface.

### Capture limits

Parser and API validation enforce finite limits.

Initial hard bounds:

- `--steps`: `1..100000`;
- `--events`: `1..10000`;
- number of memory regions: `0..32`;
- one memory region length: `1..0x01000000` bytes;
- total configured memory bytes: at most `0x02000000` bytes;
- timeout must be positive.

These are safety/resource ceilings, not performance promises. Smaller captures remain the recommended investigation workflow.

Exactly one capture selector is accepted: `--steps`, `--break`, `--watch-read`, `--watch-write`, or `--watch-access`.

Breakpoint/watchpoint modes require `--events`. Step mode rejects `--events`.

## Memory before/after evidence

Memory regions are configured with repeatable CLI arguments:

```bash
nds-toolkit runtime trace capture \
  --cpu arm9 \
  --steps 500 \
  --memory 0x02100000:0x1000 \
  --memory 0x02200000:0x400 \
  --output attack.ndstrace
```

For every configured region:

1. read BEFORE bytes while the target is stopped before the first capture operation;
2. execute the bounded capture;
3. read AFTER bytes after the final stop/exit state when memory remains readable;
4. persist both snapshots;
5. compute changes during reporting rather than duplicating derived diff rows inside the trace.

A successful trace with configured memory regions requires complete BEFORE and AFTER snapshots. If the target exits in a state where the peer no longer allows the required AFTER read, capture fails finalization rather than producing a misleading complete memory differential.

### Memory differential algorithm

`memory_diff.py` compares equal-sized BEFORE/AFTER snapshots and returns deterministic contiguous changed byte ranges.

For each range, reports additionally expose aligned interpretations only when the complete interpreted word lies within the configured region and at least one byte in that word changed:

- little-endian 16-bit old/new values at 2-byte aligned addresses;
- little-endian 32-bit old/new values at 4-byte aligned addresses.

These interpretations are convenience views only. Raw byte ranges remain authoritative.

No datatype or structure semantics are inferred in 7H2.

## Static-project fingerprint

When capture is given `--project game.ndsre`, the toolkit computes a stable SHA-256 fingerprint using only existing public `AnalysisProject` data.

The canonical fingerprint document is:

```json
{
  "analysis_model_version": 1,
  "components": [
    {
      "base_address": 33554432,
      "name": "arm9",
      "sha256": "...64 lowercase hex characters...",
      "size": 123456
    }
  ],
  "project_format_version": 1,
  "schema_version": 1
}
```

The actual values come from `project.metadata` and `project.component_identities()`. Components are ordered by component name, matching the public project API contract. The document is encoded as UTF-8 JSON with `sort_keys=True`, `separators=(",", ":")`, and no trailing newline. The lowercase hexadecimal SHA-256 digest of those exact bytes is the stored project fingerprint.

The fingerprint deliberately excludes toolkit version, analysis timestamps, generated symbols, annotations, functions, CFG/data-flow records, and other derived analysis so improving static analysis does not make an unchanged target build appear to be a different runtime target.

Rules:

- if both traces have fingerprints and they differ, `runtime diff` rejects the comparison as a target mismatch;
- if one or both fingerprints are absent, raw-address comparison is allowed, but the report explicitly marks target identity as unverified;
- a project supplied at report time is correlated independently and does not rewrite the stored trace.

## Static correlation

Trace capture works without `.ndsre`.

When a project is supplied to `runtime trace inspect` or `runtime diff`, correlation uses only the existing read-only `AnalysisProject` API.

For each runtime evidence PC:

1. use the stored ARM/Thumb instruction-set identity;
2. find every persisted component whose runtime range contains the PC;
3. independently query exact function/symbol/annotation evidence for each component candidate;
4. preserve all candidates in deterministic component-name order.

### Ambiguous overlay policy

If exactly one component/function identity can be established, the event may contribute to that function's dynamic hit count.

If several overlapping components remain possible, the report records all candidates with `ambiguous=true`. Such an event contributes to raw-address statistics but is excluded from function ranking by default.

This avoids artificially crediting the same runtime event to multiple inactive overlays.

7H2 may later add proven overlay residency evidence, but it must not infer residency solely from an overlapping address.

## Trace inspection

Add:

```bash
nds-toolkit runtime trace inspect attack.ndstrace
nds-toolkit runtime trace inspect attack.ndstrace --project game.ndsre
```

Output includes:

- trace metadata and capture configuration;
- evidence/control event counts;
- ordered evidence PCs and hit frequencies;
- memory-region summaries and changed byte counts;
- optional static function/symbol/component correlation;
- ambiguity counts;
- trace integrity/schema information.

The command never mutates the trace or project.

## Behavioral differential engine

Primary comparison:

```bash
nds-toolkit runtime diff \
  idle.ndstrace \
  attack.ndstrace \
  --project game.ndsre
```

The first trace is the baseline; the second is the target behavior.

### Raw-address differential

For each `(cpu, pc, instruction_set)` identity observed as an `EVIDENCE` event, compute:

- baseline hit count;
- target hit count;
- baseline evidence-event frequency;
- target evidence-event frequency;
- signed frequency delta `target_frequency - baseline_frequency`;
- whether the address is baseline-only, target-only, or shared.

Frequency normalization makes comparisons meaningful when traces contain different numbers of evidence events.

Control events never contribute to these frequencies.

### Function differential

When static correlation is available and unambiguous, aggregate raw evidence addresses by `(component, function_address, instruction_set)`.

For each function report:

- baseline and target hit counts;
- normalized frequencies;
- target-only/baseline-only/shared classification;
- participating dynamic PCs;
- relevant symbols/annotations;
- whether any evidence stop PC corresponds to a configured breakpoint/watchpoint hit;
- static xrefs from the function into changed memory ranges when available.

Ambiguous overlay candidates are listed separately and do not inflate aggregate function counts.

## Memory-to-code correlation

When the target trace contains changed memory regions and a project is supplied, the report checks persisted static xrefs whose target addresses fall inside changed ranges.

This is evidence that a function statically references a changed address, not proof that the observed runtime write came from that particular xref.

The report wording and ranking evidence must preserve that distinction.

Watchpoint stop PCs provide stronger direct runtime evidence: when a watchpoint event stops at PC X, the unambiguously correlated function containing X is marked as a runtime condition-hit function.

## Transparent function ranking

Ranking applies only to unambiguously correlated functions with at least one target-trace evidence hit.

Initial score is a deterministic weighted sum in `[0, 1]`:

```text
0.30 * target_exclusive
0.25 * positive_frequency_delta
0.20 * condition_hit
0.15 * changed_memory_reference
0.10 * dynamic_neighbor
```

Feature definitions:

### `target_exclusive`

`1.0` when the function has target hits and zero baseline hits; otherwise `0.0`.

### `positive_frequency_delta`

`max(0, target_frequency - baseline_frequency)`, already bounded to `[0, 1]`.

### `condition_hit`

`1.0` when an evidence breakpoint/watchpoint stop PC in the target trace unambiguously correlates to the function; otherwise `0.0`.

### `changed_memory_reference`

`1.0` when the static project contains an xref from the function to an address inside a target-trace changed memory range; otherwise `0.0`.

This means "static reference to changed memory," not "proven runtime writer."

### `dynamic_neighbor`

`1.0` when the static project shows a call relationship between the function and another unambiguously correlated target-exclusive dynamic candidate; otherwise `0.0`.

The report emits every raw feature value, weight, and textual evidence item. Equal scores use deterministic tie-breaking by component name, function address, then instruction-set identity.

No score is labeled as a probability.

## CLI contract

### Capture

```text
nds-toolkit runtime trace capture [connection options] CAPTURE_SELECTOR --output TRACE
```

Supported selectors:

```text
--steps N
--break ADDRESS --events N
--watch-read ADDRESS --length N --events N
--watch-write ADDRESS --length N --events N
--watch-access ADDRESS --length N --events N
```

Additional options:

```text
--memory ADDRESS:LENGTH       repeatable
--project PATH                optional fingerprint/correlation source
--label TEXT                  optional user label
--timeout SECONDS             inherited runtime timeout semantics
```

On success, capture always writes the authoritative `.ndstrace` to the path passed through `--output` and prints one deterministic JSON summary to stdout with these top-level fields:

```text
trace
cpu
capture_mode
evidence_events
control_events
memory_regions
terminated_by
project_fingerprint
```

`terminated_by` is one of `limit` or `target_exit`. Capture does not use a second JSON output-file option because `--output` is reserved for the trace database.

### Inspect

```text
nds-toolkit runtime trace inspect TRACE [--project PROJECT] [--output JSON]
```

Without `--output`, deterministic JSON is written to stdout. With `--output`, the established atomic JSON replacement behavior is used.

### Diff

```text
nds-toolkit runtime diff BASELINE TARGET [--project PROJECT] [--output JSON]
```

Without `--output`, deterministic JSON is written to stdout. With `--output`, the established atomic JSON replacement behavior is used.

## Error model

Use the existing runtime/project exception hierarchy wherever possible.

Add trace-specific toolkit exceptions only when they represent a distinct caller-visible boundary, for example:

```text
RuntimeTraceError
RuntimeTraceFormatError
RuntimeTraceMismatchError
```

CLI mapping remains consistent with established toolkit behavior:

- invalid user input: exit `2`;
- expected toolkit/runtime/trace failure: exit `4`;
- filesystem failure: exit `5`.

### Capture failures

The following abort final trace creation:

- connection failure;
- runtime timeout;
- malformed debugger response;
- failed temporary breakpoint/watchpoint cleanup when the connection is still usable;
- incomplete configured memory snapshot pair;
- SQLite write/integrity failure.

A target exit is not itself an error when no required post-exit memory read remains. The exit event terminates capture early and the summary records why the requested maximum was not reached.

## Determinism

All report arrays have explicit stable sort orders.

Canonical identities:

```text
runtime address: (cpu, pc, instruction_set)
static function: (component_name, function_address, instruction_set)
memory region: configured ordinal
trace event: ordinal
```

Canonical JSON uses sorted object keys and established lowercase hexadecimal rendering.

SQLite internal byte-for-byte reproducibility is not a contract. Logical records and reports are deterministic.

## Testing strategy

### Unit tests

Cover:

- trace record validation and immutability;
- `.ndstrace` schema creation/version rejection;
- atomic finalization and failure cleanup;
- event ordinal validation;
- memory region bounds and overlap behavior;
- BEFORE/AFTER requirements;
- byte-range memory diffing;
- aligned 16/32-bit interpretations;
- capture selector validation;
- step capture event ordering;
- repeated breakpoint control-advance behavior;
- repeated watchpoint control-advance behavior;
- target-exit handling;
- exact project fingerprint canonicalization;
- trace fingerprint matching/mismatch rules;
- raw-address frequency normalization;
- function aggregation;
- overlay ambiguity exclusion from ranking;
- changed-memory xref correlation;
- ranking feature calculation, weights, and deterministic tie-breaking;
- CLI JSON and error-code behavior.

Mock/fake session objects are used for deterministic orchestration tests. RSP packet behavior remains covered by 7H1 tests rather than duplicated in 7H2.

### Integration tests

Use real temporary `.ndstrace` SQLite files and existing static-project fixtures to verify complete capture → inspect → diff workflows, including ambiguous overlays and project fingerprint behavior.

### Live melonDS gate

Extend the existing stock-melonDS CI smoke harness rather than creating a separate emulator fork or transport.

The 7H2 live gate must prove on an exact branch head:

1. stock melonDS core builds with GDB enabled and JIT disabled;
2. a bounded multi-step trace creates a valid `.ndstrace`;
3. a repeated breakpoint trace records evidence and control-advance events without immediate-retrigger looping;
4. a watchpoint trace captures a real stop PC;
5. a configured memory region produces complete BEFORE/AFTER snapshots and a non-empty differential when the harness mutates that region through executed target code;
6. `runtime trace inspect` succeeds;
7. a baseline-vs-target `runtime diff` succeeds and ranks the known target-only harness function/address above baseline-only/shared evidence.

The live smoke remains a release gate for 7H2, not an optional manual note.

## Staging

### Phase 7H2A — trace model and persistence

- immutable trace records;
- `.ndstrace` schema version 1;
- reader/writer/integrity validation;
- atomic finalization;
- no live capture yet.

### Phase 7H2B — bounded capture

- step capture;
- repeated breakpoint capture;
- repeated watchpoint capture;
- explicit control-advance events;
- parser/API bounds.

### Phase 7H2C — memory evidence

- configured BEFORE/AFTER regions;
- memory differential engine;
- deterministic changed-range reporting.

### Phase 7H2D — project correlation

- exact project fingerprinting;
- trace inspection with static correlation;
- conservative overlay ambiguity handling;
- changed-memory xref lookup.

### Phase 7H2E — behavioral differential

- raw-address baseline/target comparison;
- normalized frequencies;
- unambiguous function aggregation;
- memory-difference integration.

### Phase 7H2F — dynamic function ranking

- transparent weighted ranking;
- condition-hit evidence;
- changed-memory-reference evidence;
- dynamic-neighbor evidence;
- deterministic evidence explanations.

### Phase 7H2G — CLI, documentation, and live gate

- final command/docs polish;
- exact-head full pytest/Ruff/strict-mypy gate;
- exact-head stock-melonDS live trace/differential gate;
- post-merge `main` verification.

## Explicit non-goals

Phase 7H2 does not add:

- unbounded full-system instruction tracing;
- a custom or patched melonDS fork;
- melonDS as a runtime Python dependency;
- runtime tables inside `.ndsre`;
- automatic overlay residency inference without direct evidence;
- automatic structure/type inference;
- symbolic execution or angr integration;
- decompiled/pseudo-C output;
- game-specific addresses or semantics;
- debugger REPL/TUI/GUI;
- memory writes/patching;
- opaque ML-based ranking.

## Success criteria

Phase 7H2 is complete when all of the following are true:

1. a user can create a bounded step, repeated-breakpoint, or repeated-watchpoint `.ndstrace` against the verified 7H1 melonDS session;
2. configured memory regions produce trustworthy BEFORE/AFTER evidence;
3. traces can be inspected without a static project and correlated conservatively with one when supplied;
4. two traces can be compared as baseline vs target behavior with normalized raw-address and function-level evidence;
5. target-relevant unambiguous functions receive transparent deterministic rankings with explicit evidence;
6. overlapping overlays are never silently guessed or double-counted;
7. `.ndsre` schema version 1 remains unchanged;
8. no new runtime dependency or copied melonDS implementation code is introduced;
9. full pytest/Ruff/strict-mypy verification passes on the exact integration head;
10. the stock-melonDS live capture/differential smoke passes on the exact integration head and again on post-merge `main`.
