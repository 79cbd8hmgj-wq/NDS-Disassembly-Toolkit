# Runtime debugging, trace analysis, and managed orchestration

Phase 7H provides a game-neutral runtime-analysis layer for Nintendo DS targets exposed through emulator GDB Remote Serial Protocol (RSP) debugger interfaces.

- **Phase 7H1** provides bounded attach-only inspection: probe, snapshots, memory reads, temporary break/watch conditions, and single-step.
- **Phase 7H2** adds bounded persisted `.ndstrace` capture, BEFORE/AFTER memory evidence, read-only `.ndsre` correlation, trace inspection, behavioral differentials, and transparent function ranking.
- **Phase 7H3** adds a separate managed orchestration path: owned emulator processes, isolated session directories, dynamic loopback ports, validated checkpoints, finite runtime predicates, guarded memory writes, normalized Nintendo DS input records, durable scenarios/safe resume, failure evidence, and deterministic acceptance matrices.

The existing Phase 7H1/7H2 commands remain attach-only and backward compatible. They do not launch or reset an emulator. Phase 7H3 commands are explicitly managed commands and never infer game-specific meaning.

## Managed Phase 7H3 workflow

A typical managed workflow is:

```text
runtime doctor
→ runtime launch
→ runtime checkpoint save/restore
→ runtime scenario run
→ runtime session resume when recovery is safe
→ runtime matrix run for repeated isolated cases
→ runtime session stop
```

Examples:

```bash
nds-toolkit runtime doctor --emulator desmume
nds-toolkit runtime launch GAME.nds \
  --emulator desmume \
  --cpu arm9 \
  --session-root runtime

nds-toolkit runtime checkpoint save runtime/SESSION baseline
nds-toolkit runtime scenario run runtime/SESSION scenario.json
nds-toolkit runtime session resume runtime/SESSION scenario.json
nds-toolkit runtime matrix run matrix.json --session-root runtime/SESSION
nds-toolkit runtime session stop runtime/SESSION
```

Managed sessions own their process identity, debugger endpoint, logs, checkpoints, traces, case results, journal, and failure directory. Cleanup re-proves PID/start-time/executable/process-group ownership before signaling a process. Debugger ports default to loopback and are dynamically allocated for managed sessions.

Scenario JSON is versioned and intentionally constrained. It supports finite waits, Nintendo DS button/touch actions, guarded memory writes, snapshot/trace capture, assertions, and checkpoint save/restore. It does **not** support arbitrary shell commands or image/OCR state recognition. Input/mutation actions may declare generic runtime preconditions and postconditions, and all waits are finite.

A step journal distinguishes `PENDING`, `STARTED`, `COMPLETED`, and `FAILED`. If execution is interrupted after a non-idempotent step starts, resume restores the latest safe checkpoint anchor and replays from that boundary rather than assuming the partially executed action is safe to repeat in place.

Acceptance matrices apply typed case parameters to explicit scenario fields, restore the same verified baseline before each case, preserve deterministic case order, and persist resumable result identities. A failed case cannot contaminate the next case; a baseline restore failure aborts remaining cases.

When a managed scenario fails, the toolkit attempts a bounded best-effort failure bundle under the session `failure/` directory. Evidence collection is secondary: it never replaces the primary scenario exception.


## melonDS setup

Before using `nds-toolkit runtime`:

1. launch the melonDS build you intend to debug;
2. enable its GDB debugger stub for the CPU you want to inspect;
3. configure the stub port to match the toolkit connection;
4. disable JIT for reproducible debugger behavior;
5. start or pause the title at the state you want to inspect.

Toolkit defaults:

| CPU | Default port |
| --- | ---: |
| ARM9 | `3333` |
| ARM7 | `3334` |

The default host is `127.0.0.1`. Classic GDB RSP has no authentication or transport encryption, so do not expose a debugger stub directly to an untrusted network.

All online runtime commands accept `--timeout`; the default is five seconds. JSON-producing commands support atomic `--output` writes.

## Interactive Phase 7H1 commands

Probe the debugger without advancing the target:

```bash
nds-toolkit runtime probe --cpu arm9
```

Capture the current registers/PC/CPSR:

```bash
nds-toolkit runtime snapshot --cpu arm9
```

Read bounded memory:

```bash
nds-toolkit runtime read-memory --cpu arm9 0x02000000 0x100
```

Continue to a temporary code breakpoint:

```bash
nds-toolkit runtime run-until --cpu arm9 --break 0x02012340
```

Single-step one or more instructions:

```bash
nds-toolkit runtime step --cpu arm9 --count 4
```

Interactive `runtime step --count` is deliberately limited to `1..256`.

### Optional static-project correlation

Commands that support `--project` open the `.ndsre` project read-only:

```bash
nds-toolkit runtime snapshot --cpu arm9 --project game.ndsre
```

Correlation preserves component identity. If several overlays cover the same numerical runtime address, the toolkit reports all matching candidates in deterministic order rather than guessing which overlay is resident.

## Persisted Phase 7H2 traces

A `.ndstrace` is an independent SQLite trace file. It is not stored inside `.ndsre` and does not change the static-project schema.

### Step trace

```bash
nds-toolkit runtime trace capture \
  --cpu arm9 \
  --steps 2000 \
  --output attack.ndstrace
```

Trace-only step captures allow `1..100000` steps. This larger bound does not change the interactive 7H1 `step --count` limit.

### Repeated breakpoint trace

```bash
nds-toolkit runtime trace capture \
  --cpu arm9 \
  --break 0x02012340 \
  --events 100 \
  --output attack-breaks.ndstrace
```

Repeated break/watch captures persist two event roles:

- `EVIDENCE`: the requested breakpoint/watchpoint stop;
- `CONTROL_ADVANCE`: one debugger single-step performed with the temporary condition removed before re-arming it.

`CONTROL_ADVANCE` is inspectable but excluded from default hit frequencies and function ranking.

### Watchpoint trace selectors

The toolkit implements standard RSP read/write/access watchpoint packet mapping and the same bounded repeated-capture orchestration:

```bash
nds-toolkit runtime trace capture \
  --cpu arm9 \
  --watch-write 0x02100000 \
  --length 4 \
  --events 20 \
  --output writes.ndstrace
```

`--watch-read` and `--watch-access` are also accepted.

#### Stock melonDS watchpoint limitation

The stock melonDS commit used by the repository live gate, `906e9ebb27da8c6a715cd7abab4abfe8a8d29427`, accepts the standard `Z2`/`Z3`/`Z4` watchpoint packets and stores watchpoint definitions, but its CPU execution path does not invoke the GDB stub's `CheckWatchpt` hook. Consequently that stock build does **not** emit real watchpoint stops even though insertion returns `OK`.

This is an external emulator limitation, not synthesized away by the toolkit. Phase 7H therefore verifies:

- watchpoint packet mapping, removal, cleanup, and stop normalization in the runtime/RSP tests;
- repeated read/write/access watchpoint `EVIDENCE → CONTROL_ADVANCE → EVIDENCE` orchestration with deterministic session fixtures;
- real stock-melonDS execution for probe, snapshot, memory, stepping, repeated code breakpoints, persisted traces, memory mutation, static correlation, and trace differential/ranking.

If a future melonDS build wires watchpoint checks into execution, the existing online watchpoint commands can use those real stops without changing the `.ndstrace` model.

## Memory BEFORE/AFTER evidence

Configure up to 32 regions with repeatable `--memory ADDRESS:LENGTH` arguments:

```bash
nds-toolkit runtime trace capture \
  --cpu arm9 \
  --steps 500 \
  --memory 0x02100000:0x1000 \
  --memory 0x02200000:0x400 \
  --output attack.ndstrace
```

For each region the collector reads BEFORE bytes, performs the bounded capture, then reads AFTER bytes. A trace with configured memory regions is finalized only when both snapshots exist.

Inspection reports authoritative contiguous changed byte spans plus aligned little-endian 16-bit and 32-bit convenience values where valid. Phase 7H2 does not infer structures or datatypes from those bytes.

Safety bounds:

- step trace limit: `1..100000`;
- breakpoint/watchpoint evidence limit: `1..10000`;
- memory regions: `0..32`;
- one region: `1..0x01000000` bytes;
- total configured memory: at most `0x02000000` bytes;
- timeout: positive.

Exactly one capture selector is accepted: `--steps`, `--break`, `--watch-read`, `--watch-write`, or `--watch-access`. Break/watch modes require `--events`; step mode rejects `--events`.

## Atomic trace creation

Capture writes a sibling temporary SQLite database first. A complete destination is replaced only after event/snapshot validation, SQLite integrity checking, final metadata commit, and clean close.

If capture fails because of timeout, connection loss, protocol error, incomplete memory evidence, or validation failure:

- the temporary trace is removed;
- an existing destination remains untouched;
- no incomplete trace is presented as valid.

## Static-project fingerprint

Supplying `--project` during capture stores a deterministic SHA-256 identity derived from public `.ndsre` metadata and component identities:

```bash
nds-toolkit runtime trace capture \
  --cpu arm9 \
  --steps 500 \
  --project game.ndsre \
  --output attack.ndstrace
```

The fingerprint identifies the static target components, not generated analysis state. It excludes timestamps, annotations, symbols, functions, and toolkit version.

When comparing traces:

- two present but different fingerprints are rejected as a target mismatch;
- equal fingerprints verify target identity;
- if either fingerprint is absent, raw-address comparison is allowed but reported as unverified.

## Inspect a trace

Inspection is offline; it does not connect to melonDS:

```bash
nds-toolkit runtime trace inspect attack.ndstrace
```

With static correlation:

```bash
nds-toolkit runtime trace inspect attack.ndstrace --project game.ndsre
```

Inspection reports capture metadata, evidence/control counts, event records, memory changes, static function/symbol/annotation correlation, and ambiguity where overlapping components cannot be resolved.

## Behavioral trace differential and ranking

Compare a baseline behavior with a target behavior:

```bash
nds-toolkit runtime diff \
  idle.ndstrace \
  attack.ndstrace \
  --project game.ndsre
```

The report identifies baseline-only, target-only, and shared runtime addresses/functions, memory-change differences, and a deterministic ranking of target-associated functions.

Ranking is a transparent weighted evidence score, **not** a probability or machine-learning confidence. Each ranked candidate exposes the feature values that contributed to its score.

This supports workflows such as:

```text
idle trace
   versus
attack trace
   ↓
unique runtime PCs/functions
   +
memory-change evidence
   +
static xrefs/symbols
   ↓
ranked investigation candidates
```

## RSP and register behavior

The runtime transport is a toolkit-owned standard-library TCP RSP client. It handles framing/checksums, fragmented receives, ACK/no-ACK mode, `qSupported`, register reads, chunked memory reads, `Z`/`z` temporary conditions, continue, single-step, interrupt, detach, stop replies, target exits, and explicit runtime error boundaries.

melonDS-specific register ordering remains confined to `MelonDSSession`. The observed 39-word register dump is decoded as:

```text
r0-r12, sp, lr, pc, cpsr,
sp_usr, lr_usr,
r8_fiq-r12_fiq, sp_fiq, lr_fiq,
sp_irq, lr_irq,
sp_svc, lr_svc,
sp_abt, lr_abt,
sp_und, lr_und,
spsr_fiq, spsr_irq, spsr_svc, spsr_abt, spsr_und
```

Each word is little-endian 32-bit. Truncated or non-word-aligned register payloads are rejected.

## Error/output contract

Runtime commands use the toolkit's established top-level exit codes:

- invalid user input: `2`;
- expected toolkit/runtime failure: `4`;
- filesystem failure: `5`.

Successful report JSON is deterministic and canonical hexadecimal addresses use lowercase forms such as `0x02012340`.

## Verification status

The consolidated CI workflow builds the pinned stock melonDS core headlessly with GDB enabled and JIT disabled, then executes the real toolkit CLI against a deterministic ARM9 writer target. The live gate covers:

- probe;
- snapshot/register state;
- memory reads;
- temporary code breakpoint;
- single-step;
- bounded persisted step traces;
- actual BEFORE/AFTER memory mutation;
- repeated breakpoint capture with `CONTROL_ADVANCE`;
- `.ndstrace` inspection;
- static-project fingerprints;
- trace-vs-trace differential classification;
- deterministic function ranking.

Python verification additionally covers `.ndstrace` schema/atomicity, read/write/access watchpoint orchestration, RSP watchpoint packets and cleanup, correlation/overlay ambiguity, memory differentials, CLI parsing/JSON, mismatch handling, and end-to-end offline workflows.

No melonDS implementation source is copied, linked, translated, or vendored into the MIT toolkit; melonDS remains an external GPL process/build used for interoperability verification.
