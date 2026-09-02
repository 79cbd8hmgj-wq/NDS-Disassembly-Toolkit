# Phase 7H melonDS runtime bridge design

Date: 2026-09-01
Status: approved direction; formalized for implementation review
Base: `main` at `50cede2494cbdcfe064b2efc84d172c1031f6851`

## Purpose

Phase 7H adds dynamic reverse-engineering evidence without coupling the MIT toolkit to melonDS implementation code. The toolkit will connect to melonDS through the emulator's existing GDB Remote Serial Protocol (RSP) stub, collect deterministic CPU/memory/stop evidence, and correlate live runtime addresses with the persistent static-analysis project created in Phases 7F-7G.

The immediate goal is to turn questions such as "what code executes or what memory changes when this gameplay action occurs?" into targeted, reproducible investigations rather than broad manual disassembly searches.

## Scope classification

This is architectural. It adds a new runtime-analysis subsystem, a debugger transport boundary, public runtime models, CLI commands, and a bridge between emulator state and the existing static project model.

## Source and licensing boundary

melonDS is GPL-3.0. Phase 7H must not copy, vendor, translate, or derive implementation code from melonDS into this MIT toolkit.

The integration uses only the external behavior of melonDS's GDB remote interface. The uploaded melonDS source was inspected to verify the public interoperability surface and default configuration, not as implementation material.

Known interoperability facts used by the design:

- melonDS can build with its GDB stub enabled;
- ARM9 and ARM7 use independent GDB endpoints;
- current defaults are ARM9 port `3333` and ARM7 port `3334`;
- the GDB stub supports register access, memory access, continue, single-step, breakpoints, watchpoints, detach, reset/remote commands, and capability negotiation;
- melonDS documents that its GDB stub cannot be used together with its JIT recompiler, so runtime-analysis documentation must require JIT to be disabled while attached.

The toolkit implementation is an independent Python RSP client using the standard library only.

## Approaches considered

1. **External GDB RSP client — selected.** Use melonDS's existing debugger socket interface. This keeps repository licensing clean, requires no custom emulator fork, works with stock GDB-enabled melonDS builds, and gives immediate access to registers, memory, breakpoints, watchpoints, stepping, and stop reasons.
2. **Patch melonDS to emit a custom trace stream.** This could eventually produce richer high-volume traces, but it would create a maintained emulator fork and a GPL distribution boundary before the basic debugger workflow is proven.
3. **Drive an external `gdb` process and parse its text/MI output.** This avoids writing RSP framing but adds an external executable dependency, platform/version differences, and a second presentation protocol. It is unnecessary for the subset of RSP melonDS already exposes.

Phase 7H starts with approach 1. A later optional melonDS instrumentation adapter may be added only if RSP throughput becomes a demonstrated blocker for large traces.

## Staging

### Phase 7H1 — live debugger bridge

Deliver a stable toolkit-owned runtime API and CLI over melonDS GDB RSP:

- connection/capability negotiation;
- ARM9/ARM7 endpoint selection;
- register snapshots;
- memory reads;
- hardware breakpoint insertion/removal;
- watchpoint insertion/removal;
- continue until next stop;
- single-step;
- deterministic stop-reason parsing;
- runtime snapshot records;
- static-project correlation for the stopped program counter;
- no analysis-project schema change.

### Phase 7H2 — trace capture and behavioral differentials

Build on 7H1 after it is stable:

- bounded execution trace capture;
- repeated breakpoint/step sampling where practical;
- watchpoint event capture;
- memory-region before/after snapshots;
- trace-session persistence;
- static function/symbol/xref correlation;
- behavior-to-behavior differential reports;
- function ranking from dynamic evidence;
- project schema evolution only when the runtime record shape is proven.

The 7H1/7H2 split deliberately avoids committing a persistent runtime schema before the live transport and event model are validated.

## Package architecture

Add a new package:

```text
src/nds_disassembly_toolkit/analysis/runtime/
├── __init__.py
├── model.py
├── rsp.py
└── melonds.py
```

Add CLI integration in:

```text
src/nds_disassembly_toolkit/analysis/runtime_cli.py
src/nds_disassembly_toolkit/cli.py
```

### `runtime.model`

Own immutable emulator-neutral models. Initial public types:

```text
RuntimeCpu
├── ARM9
└── ARM7

StopReasonKind
├── BREAKPOINT
├── WATCHPOINT
├── STEP
├── INTERRUPT
├── SIGNAL
├── EXITED
└── UNKNOWN

RegisterSnapshot
RuntimeStop
RuntimeSnapshot
RuntimeLocation
```

`RegisterSnapshot` stores canonical toolkit register names and integer values, including at minimum `r0`-`r12`, `sp`, `lr`, `pc`, and `cpsr`. Additional banked registers returned by the peer may be retained without making callers parse RSP register numbers.

`RuntimeSnapshot` contains CPU, stopped PC, instruction-set state derived from CPSR T-bit, complete register snapshot, optional sampled memory regions, and the stop reason that produced the snapshot.

`RuntimeLocation` is the result of correlating a runtime PC with a Phase 7F project. It may contain exact persisted function, generated symbols, user annotation, and component candidates. Overlay ownership must never be guessed solely from a numerical runtime address.

### `runtime.rsp`

Own a small standards-based GDB RSP client. It is emulator-neutral and depends only on Python standard-library networking.

Responsibilities:

- packet checksum generation/validation;
- `$payload#checksum` framing;
- escaping/unescaping where required;
- ACK/NAK handling;
- optional transition to no-ack mode when advertised;
- bounded socket reads and timeouts;
- capability negotiation via `qSupported`;
- command/response error parsing;
- register read (`g` and, when useful, `p`);
- memory read (`m`);
- breakpoint/watchpoint insertion/removal (`Z`/`z`);
- continue/step (`c`, `s`, or negotiated `vCont`);
- detach (`D`);
- asynchronous stop reply parsing;
- remote interrupt using the RSP break byte when supported by the peer.

The transport must not know about `.ndsre`, components, symbols, ARM/Thumb semantics, or melonDS defaults.

### `runtime.melonds`

Own the emulator-specific adapter while still using only documented/observed protocol behavior.

Public shape:

```python
session = MelonDSSession.connect(
    cpu=RuntimeCpu.ARM9,
    host="127.0.0.1",
    port=3333,
)

snapshot = session.snapshot()
data = session.read_memory(0x02000000, 64)
stop = session.run_until_breakpoint(0x02012340)
snapshot = session.step()
session.close()
```

Defaults:

- ARM9: `127.0.0.1:3333`
- ARM7: `127.0.0.1:3334`

Ports and host are always overrideable.

The adapter maps peer register ordering into toolkit register names and converts raw stop replies into `RuntimeStop`. Unsupported peer behavior produces explicit toolkit runtime errors rather than silent fallbacks.

## Session and target-state rules

A live runtime command assumes melonDS's GDB stub is enabled and JIT is disabled.

Commands that inspect registers or memory require the target to be stopped. The client must not pretend a running target produced a coherent snapshot.

Commands that continue or step wait for a stop reply or timeout. Timeout does not imply the target stopped; the error must preserve that distinction.

Temporary breakpoints/watchpoints installed by a one-shot convenience operation are removed in a `finally` path whenever the connection remains usable.

The toolkit does not automatically reset or mutate game memory on connect.

## Breakpoints and watchpoints

Expose semantic helpers rather than raw RSP type numbers:

```text
breakpoint(address, length)
watch_read(address, length)
watch_write(address, length)
watch_access(address, length)
```

The melonDS adapter may map these onto the peer's supported GDB breakpoint/watchpoint packets. Because melonDS currently treats watchpoint read/write/access categories conservatively, toolkit documentation must not claim stronger read-vs-write distinction than the peer actually reports.

## Static-project correlation

7H1 performs correlation without altering the Phase 7F database schema.

Given a stopped PC and optional project path:

1. infer ARM/Thumb from CPSR;
2. query exact functions using `(component, address, instruction_set)` only when a component is known;
3. otherwise query project components whose registered runtime range contains the PC and return all candidates;
4. for each candidate component, query exact function/symbol/annotation evidence;
5. never collapse overlapping overlays into one answer by address alone.

A runtime address may therefore legitimately correlate to multiple inactive/possible overlay components. 7H2 may use overlay-load evidence to reduce that ambiguity, but 7H1 must report it explicitly.

## CLI contract

Add a top-level family:

```text
nds-toolkit runtime <subcommand> ...
```

All successful commands emit deterministic JSON using the established Phase 7G canonical-hex conventions.

### `runtime probe`

```bash
nds-toolkit runtime probe --cpu arm9
nds-toolkit runtime probe --cpu arm7 --host 127.0.0.1 --port 3334
```

Connects, negotiates capabilities, reports peer/runtime CPU and supported features, then detaches without changing target execution state.

### `runtime snapshot`

```bash
nds-toolkit runtime snapshot --cpu arm9
nds-toolkit runtime snapshot --cpu arm9 --project game.ndsre
```

Returns registers, PC, CPSR, inferred ARM/Thumb mode, stop state, and optional project correlation.

### `runtime read-memory`

```bash
nds-toolkit runtime read-memory --cpu arm9 0x02000000 0x100
```

Returns address, length, and bytes as deterministic hexadecimal data. Reads larger than one peer packet are chunked by the toolkit.

### `runtime run-until`

```bash
nds-toolkit runtime run-until --cpu arm9 --break 0x02012340
nds-toolkit runtime run-until --cpu arm9 --watch-write 0x02100000 --length 4
```

Installs a temporary breakpoint or watchpoint, continues, waits for the next stop, captures a snapshot, optionally correlates it to a project, and removes the temporary stop condition.

Exactly one stop condition is accepted in 7H1. Multi-breakpoint sessions belong to 7H2.

### `runtime step`

```bash
nds-toolkit runtime step --cpu arm9 --count 1
```

Single-steps a bounded number of instructions and returns the final snapshot plus ordered stop PCs. `--count` is capped to prevent accidental unbounded CLI tracing; high-volume tracing belongs to 7H2.

## Error model

Add toolkit-owned runtime exceptions under the existing `NdsToolkitError` hierarchy:

```text
RuntimeAnalysisError
RuntimeConnectionError
RuntimeProtocolError
RuntimeTimeoutError
RuntimeTargetStateError
```

Required distinctions:

- connection refused/unreachable peer;
- malformed/checksum-invalid RSP packet;
- peer returned `E..` protocol error;
- operation timeout while target may still be running;
- command unsupported by negotiated peer;
- target state unsuitable for requested operation;
- project-correlation ambiguity is data, not an exception.

CLI maps these through the established toolkit error path rather than printing raw socket exceptions or stack traces.

## Determinism

Runtime timestamps are metadata only and are not required in 7H1 JSON. Ordered lists use stable register/component/symbol/function ordering. Addresses and memory extents use Phase 7G canonical hexadecimal strings.

Live execution is inherently non-deterministic, but serialization and correlation of a given captured snapshot must be deterministic.

## Security and networking

Default host is loopback only. The CLI does not automatically expose a listener.

The user may explicitly connect to another host, but documentation must warn that classic GDB RSP has no authentication or transport encryption and should not be exposed to untrusted networks.

All packet and memory lengths are bounded. The client validates hexadecimal responses before allocating decoded buffers.

## Testing strategy

7H1 is implemented TDD-first with no live emulator required in CI.

Create a deterministic fake RSP server/socket harness covering:

- checksum/framing and ACK behavior;
- capability negotiation and no-ack mode;
- fragmented TCP receives;
- malformed packets and checksum errors;
- peer `E..` responses;
- register endian decoding;
- ARM vs Thumb derivation from CPSR;
- chunked memory reads;
- breakpoint/watchpoint add/remove;
- continue and stop-reply parsing;
- temporary stop-condition cleanup on success/failure;
- timeouts;
- ARM9/ARM7 default ports;
- project correlation with exact component identities;
- overlapping overlay ambiguity;
- CLI JSON/address formatting and error mapping.

Full pytest, Ruff, and strict mypy remain required on every final head and after merge.

A manual melonDS smoke test is a release gate for 7H1 but is separate from CI: enable GDB stub, disable JIT, break ARM9 on startup or pause it, run `runtime probe`, `snapshot`, one memory read, one temporary breakpoint, and one step.

## Explicitly deferred to 7H2 or later

- persistent runtime-event schema;
- continuous/high-volume instruction tracing;
- memory before/after differential storage;
- behavior-to-behavior trace comparison;
- dynamic function ranking;
- overlay-load instrumentation;
- call/return reconstruction from full traces;
- emulator process launching/config-file mutation;
- custom melonDS patches or plugins;
- angr symbolic execution;
- pseudo-C generation.

## Success condition

Phase 7H1 is complete when a stock GDB-enabled melonDS instance can be inspected through the toolkit for ARM9 or ARM7, one-shot break/watch/step operations return typed snapshots, runtime PCs can be correlated safely with an existing `.ndsre` project, CI is green, and no melonDS GPL implementation code is present in the MIT repository.
