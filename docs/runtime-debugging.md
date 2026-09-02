# Runtime debugging with melonDS

Phase 7H1 adds a game-neutral runtime-analysis bridge for a running Nintendo DS target exposed through melonDS's GDB Remote Serial Protocol (RSP) debugger interface. The toolkit attaches to an already configured debugger stub; it does not launch melonDS, reset the emulated system, load a ROM, or guess game-specific meaning.

The runtime layer is intentionally separate from static analysis. Live state is represented with toolkit-owned immutable records, and optional `.ndsre` correlation uses only the existing public, read-only `AnalysisProject` API.

## melonDS setup

Before using `nds-toolkit runtime`:

1. launch the stock melonDS build you intend to debug;
2. enable its GDB debugger stub for the CPU you want to inspect;
3. configure the stub port to match the toolkit connection;
4. for reproducible stepping and breakpoint behavior, disable JIT while debugging;
5. start or pause the emulated title at the state you want to inspect.

The toolkit defaults are:

| CPU | Toolkit default port |
| --- | ---: |
| ARM9 | `3333` |
| ARM7 | `3334` |

Use `--port` when your melonDS configuration differs.

The default host is `127.0.0.1`. Keep the debugger bound to loopback unless you deliberately need remote access. Classic GDB RSP does not provide authentication or transport encryption, so exposing a debugger stub directly to an untrusted network is unsafe. Prefer local connections or a separately secured tunnel.

## Probe the debugger

Probe establishes an RSP connection, negotiates capabilities, reports them as deterministic JSON, and detaches. It does not continue, step, or reset the target.

```bash
nds-toolkit runtime probe --cpu arm9
```

ARM7 or an explicit endpoint:

```bash
nds-toolkit runtime probe \
  --cpu arm7 \
  --host 127.0.0.1 \
  --port 3334
```

All runtime commands accept `--timeout`; the default is five seconds. Commands that produce JSON also accept `--output`, which writes by atomic temporary-file replacement.

## Capture a register snapshot

```bash
nds-toolkit runtime snapshot --cpu arm9
```

A snapshot reports:

- CPU identity;
- canonical register names and values;
- PC and CPSR;
- ARM versus Thumb state derived from CPSR;
- the current toolkit stop record;
- optional static-project correlation.

Runtime addresses and extents are emitted as lowercase canonical hexadecimal strings such as `0x02012340`.

### Correlate with a persistent analysis project

```bash
nds-toolkit runtime snapshot \
  --cpu arm9 \
  --project game.ndsre
```

The project is opened read-only. Correlation checks every persisted component whose runtime range contains the live PC, then queries each component independently for:

- an exact function with matching ARM/Thumb identity;
- symbols at the exact address;
- a location annotation at the exact address.

Overlapping Nintendo DS overlays are never collapsed into one guessed owner. If multiple persisted components cover the same PC, all candidates remain in deterministic component-name order.

Runtime commands do not write observations back into `.ndsre` in Phase 7H1.

## Read runtime memory

```bash
nds-toolkit runtime read-memory \
  --cpu arm9 \
  0x02000000 \
  0x100
```

The command performs bounded RSP memory reads and returns the requested address, length, CPU, and lowercase hexadecimal bytes. A zero-length request is rejected.

Large requests are internally split into smaller RSP reads so correctness does not depend on one unusually large debugger packet.

## Continue to a temporary breakpoint

```bash
nds-toolkit runtime run-until \
  --cpu arm9 \
  --break 0x02012340
```

The bridge installs a temporary RSP breakpoint, continues execution, captures the stop plus registers, removes the temporary breakpoint in a `finally` path, and returns the resulting snapshot.

Use `--project game.ndsre` to correlate the resulting PC with static analysis.

## Continue to a temporary watchpoint

Write watchpoint:

```bash
nds-toolkit runtime run-until \
  --cpu arm9 \
  --watch-write 0x02100000 \
  --length 4
```

Read and access watchpoints are also available:

```bash
nds-toolkit runtime run-until --cpu arm9 --watch-read 0x02100000 --length 4
nds-toolkit runtime run-until --cpu arm9 --watch-access 0x02100000 --length 4
```

Exactly one of `--break`, `--watch-read`, `--watch-write`, or `--watch-access` is required. Length must be positive. The adapter maps the semantic toolkit kind to the corresponding standard GDB RSP `Z`/`z` packet type and removes the temporary condition even when the continue operation fails.

## Bounded single-step

```bash
nds-toolkit runtime step --cpu arm9 --count 4
```

`--count` defaults to one and is limited to `1..256`. Output contains the final full snapshot plus the ordered PC observed after every step. Optional project correlation applies to the final snapshot.

The bound is deliberate: Phase 7H1 is an interactive inspection bridge, not an unbounded tracing engine.

## Connection and protocol behavior

The runtime transport is an independently implemented standard-library TCP RSP client. It handles:

- `$payload#checksum` framing and checksum validation;
- fragmented TCP receives without assuming one packet per `recv()`;
- normal ACK mode and negotiated `QStartNoAckMode`;
- `qSupported` capability negotiation;
- complete register reads with `g`;
- chunked memory reads with `m`;
- temporary breakpoint/watchpoint insertion and removal with `Z`/`z`;
- continue, single-step, interrupt, detach, signal-stop, metadata-stop, and target-exit replies;
- explicit connection, timeout, protocol, and target-state error boundaries.

melonDS-specific knowledge is confined to the adapter. The generic RSP layer does not contain the melonDS register-bank ordering.

## Register mapping

The supplied melonDS source archive was used only to verify the debugger interoperability layout. The adapter decodes the observed 39-word register dump as:

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

Each word is decoded as a little-endian 32-bit value. A truncated or non-word-aligned register payload is rejected rather than silently assigning shifted register names.

## Error and output contract

Runtime commands use the toolkit's existing top-level exit-code boundary:

- invalid user input: `2`;
- expected toolkit/runtime failure: `4`;
- filesystem failure: `5`.

Successful output is deterministic JSON with sorted object keys. `--output` uses atomic replacement so a complete previous result is not partially overwritten by a failed write.

## Phase 7H1 scope

Phase 7H1 deliberately does **not** add:

- a melonDS runtime or build dependency;
- vendored or linked melonDS implementation code;
- a new `.ndsre` table or schema version;
- persistent runtime trace storage;
- game-specific addresses, symbols, or heuristics;
- automatic overlay residency detection;
- an unbounded trace collector;
- a stateful debugger REPL/TUI;
- decompiled or pseudo-C output.

Those boundaries keep the runtime bridge reusable by Bakugan and other game projects without moving consumer-specific evidence into the generic toolkit.

## Verification status

The unit/integration suite covers RSP framing, fragmentation, checksums, capability negotiation, register decoding, memory chunking, stop parsing, temporary break/watch cleanup, ARM9/ARM7 endpoint selection, static-project correlation, overlapping overlay candidates, deterministic CLI JSON, parser bounds, and top-level error mapping.

A live stock-melonDS smoke test is a separate manual gate because the repository CI environment does not run an interactive emulator instance. Before treating a specific melonDS release/configuration as manually validated, run `probe`, `snapshot`, a small `read-memory`, a temporary breakpoint, a temporary watchpoint, and bounded stepping against that live instance and record the tested melonDS build/configuration.
