# Phase 7H3 runtime orchestration and deterministic acceptance design

Date: 2026-09-02
Status: approved direction; formalized for implementation review
Base: `main` at `a19d8eb7c3e65ed2f57bd0c3d47dff6353273cf9`

## Purpose

Phase 7H3 closes the reliability gap exposed by live Task 13 acceptance work: the toolkit can already inspect, trace, correlate, diff, rank, and decompile runtime behavior once a debugger session is healthy, but it does not yet own the steps required to create, preserve, drive, recover, and repeat that healthy runtime state.

The goal is to make emulator-backed experiments deterministic and resumable. A game project should be able to define a game-specific scenario such as "restore the battle-ready checkpoint, place a test value in memory, enter the required gameplay state, perform a DS input gesture, capture evidence, verify postconditions, then repeat from the same baseline" while the generic toolkit owns emulator lifecycle, debugger attachment, process isolation, save-state/checkpoint handling, normalized DS input, bounded state waits, evidence bundles, and recovery.

Phase 7H3 remains game-neutral. The toolkit may know about Nintendo DS buttons, touchscreen coordinates, ARM9/ARM7 debugger state, emulator capabilities, process/display state, generic memory/register/PC predicates, generic guarded memory writes, and generic pass/fail evidence. It must not know Bakugan concepts such as Gate Cards, G-Power, Battle Arena screens, archetype names, or game-specific addresses.

## Scope classification

This is architectural. It introduces a new runtime-orchestration subsystem around the verified Phase 7H1/7H2 runtime core. It adds managed emulator processes, emulator capability adapters, debugger-dialect selection, deterministic host-display/input automation, runtime checkpoints, guarded runtime mutation, state-aware scenario execution, resumable journals, acceptance matrices, environment diagnostics, and failure evidence bundles.

It does **not** replace the existing runtime transport, trace format, static-analysis project, decompiler, investigation engine, or game-specific consumer layer.

## Problem statement derived from Task 13

The Task 13 live-acceptance sequence exposed six generic failure classes:

1. **Launch/environment mismatch.** DeSmuME inherited `SDL_VIDEODRIVER=dummy`, so the process could exist without a usable interactive X11 window.
2. **Debugger-dialect mismatch.** DeSmuME did not use the same initial RSP ACK handshake behavior as the validated melonDS path, even though normal RSP packets were otherwise usable.
3. **Process/session collision.** Delayed commands and stale emulator/debugger processes could spawn later and interfere with the active run because executable path, GDB port, and control resources were not owned by one durable session identity.
4. **State/checkpoint fragmentation.** Savestate, battery save, ROM identity, emulator version, current runtime position, and evidence were separate artifacts rather than one validated checkpoint/session object.
5. **Blind host input.** A touchscreen flick was valid only after entering a specific game state, but the automation could inject the gesture while the game was still on the overview screen. The input action had no precondition.
6. **Poor stall recovery.** After a stalled controller/chat process, substantial effort was required to determine which emulator was authoritative, which resources belonged to it, whether the debugger was still valid, and where it was safe to resume.

These failures are not specific to Bakugan. Any NDS reverse-engineering task that needs repeatable "prepare state → trigger behavior → capture evidence → restore → repeat" testing can encounter the same class of problems.

## Existing guarantees that 7H3 must preserve

The verified runtime architecture already provides:

- one toolkit-owned GDB Remote Serial Protocol transport in `analysis/runtime/rsp.py`;
- `MelonDSSession` as the current melonDS-specific session adapter;
- a generic `RuntimeCaptureSession` protocol consumed by Phase 7H2 capture orchestration;
- bounded `.ndstrace` capture;
- BEFORE/AFTER memory evidence;
- read-only `.ndsre` correlation;
- trace differentials and deterministic runtime ranking;
- component-safe static/runtime correlation;
- no game-specific addresses or policies in the generic toolkit.

Phase 7H3 must extend these boundaries rather than bypass them.

In particular:

- there must still be exactly one RSP packet transport implementation;
- DeSmuME support must reuse `RSPClient`, not add a second raw socket/GDB implementation;
- `.ndsre` schema version 1 remains unchanged;
- `.ndstrace` schema version 1 remains unchanged unless a later explicit trace-format requirement proves otherwise;
- Phase 7H3 orchestration state is stored separately from both `.ndsre` and `.ndstrace`;
- existing attach-only `nds-toolkit runtime` commands remain usable without the orchestration layer.

## Approaches considered

### 1. Generic runtime-orchestration subsystem — selected

Build emulator lifecycle, host automation, checkpoints, scenarios, and acceptance matrices as reusable toolkit infrastructure around the existing runtime core. This requires moderate implementation work but solves the entire class of Task 13 failures for future games.

### 2. Consumer-specific automation scripts

Continue adding Bakugan-owned process launchers, xdotool scripts, GDB wrappers, savestate helpers, and retry logic. This is initially faster but duplicates generic infrastructure, encourages ad hoc raw debugger access, and recreates the same failure modes on each game. Rejected.

### 3. Standardize on a single emulator

Require all runtime work to use melonDS and remove DeSmuME from acceptance workflows. This reduces one compatibility dimension but does not solve stale processes, display/input state, checkpoint recovery, scenario preconditions, or deterministic matrix execution. It also discards a useful second emulator/runtime path. Rejected.

## Core design decisions

1. **Orchestration owns experiments, not game semantics.** Game projects define addresses, expected values, and semantic labels. The toolkit owns execution mechanics and evidence.
2. **One session owns every runtime resource.** Emulator PID/process group, debugger ports, display, window binding, logs, saves, checkpoints, traces, and journals are recorded under one unique session directory.
3. **Runtime mutation uses the existing RSP transport.** Add bounded memory-write support to `RSPClient` and compatible runtime sessions rather than spawning external GDB clients or writing a second protocol path.
4. **Input is expressed in DS coordinates and DS buttons.** Consumer scenarios never depend on desktop pixel coordinates or host key names.
5. **Actions are state-aware.** Input and mutation steps may declare generic debugger-visible preconditions and postconditions. The scenario engine waits with explicit bounds; it never blindly assumes the game advanced.
6. **Resume occurs only at safe boundaries.** A journal distinguishes started from completed steps. An interrupted non-idempotent step is never silently skipped; recovery returns to the most recent declared checkpoint/resume anchor.
7. **Failure is evidence.** A failed step produces a durable bundle containing the exact session identity, step, process/debugger state, logs, register snapshot when possible, optional memory/frame evidence, and any trace already finalized.
8. **Managed launch is additive.** Existing attach-only runtime commands continue to work. Users are not forced to let the toolkit own emulator launch when manual attachment is preferable.
9. **Linux/X11 is the first managed-host implementation.** The current automation/CI environment is Linux and the observed failures were Xvfb/X11 related. Host automation is protocolized so macOS/Windows drivers can be added later without changing scenario semantics.
10. **No image-recognition engine in 7H3.** Initial state predicates are process, debugger, register, PC, and memory based. Screenshots are captured for evidence, not interpreted as game state.

## Package architecture

Add orchestration beside, not inside, the existing low-level runtime transport:

```text
src/nds_disassembly_toolkit/analysis/runtime/
├── __init__.py
├── model.py
├── rsp.py
├── melonds.py
├── desmume.py                 # new RSP session adapter; reuses RSPClient
├── capture.py
├── trace_model.py
├── trace_store.py
├── memory_diff.py
├── correlation.py
└── trace_diff.py

src/nds_disassembly_toolkit/analysis/orchestration/
├── __init__.py
├── model.py                   # immutable session/checkpoint/scenario records
├── backend.py                 # emulator backend capability protocol
├── melonds_backend.py         # managed melonDS launch/state/window conventions
├── desmume_backend.py         # managed DeSmuME launch/state/window conventions
├── process.py                 # process-group ownership, ports, logs, lifecycle
├── host.py                    # host automation protocol
├── x11.py                     # Linux Xvfb/xdotool implementation
├── input.py                   # DS buttons/touch gestures and coordinate mapping
├── checkpoint.py              # checkpoint bundle create/validate/restore
├── predicates.py              # process/debugger/register/PC/memory conditions
├── scenario.py                # bounded journaled scenario runner
├── acceptance.py              # parameterized baseline-restore matrix runner
├── evidence.py                # failure/result bundle creation
└── doctor.py                  # environment/capability diagnostics
```

CLI integration remains under the established runtime command family rather than creating an unrelated top-level program.

No new Python runtime dependency is required for the first implementation. Linux managed UI automation may require external executables such as `Xvfb` and `xdotool`; `runtime doctor` must detect and report those requirements before a scenario is started.

## Emulator backend model

### `EmulatorBackend`

The backend protocol describes emulator-specific behavior without exposing it to scenario consumers.

Conceptually it owns:

```text
EmulatorBackend
├── kind
├── capabilities
├── build_launch_spec(...)
├── wait_until_ready(...)
├── connect_debugger(...)
├── identify_window(...)
├── save_state(...)
├── load_state(...)
├── locate_battery_save(...)
├── capture_backend_metadata(...)
└── request_graceful_shutdown(...)
```

The process manager, not the backend, owns actual subprocess lifetime and resource cleanup. The backend supplies launch arguments/environment and emulator-specific conventions.

### Capabilities

Capabilities are explicit data rather than assumptions:

```text
EmulatorCapabilities
├── debugger_arm9
├── debugger_arm7
├── managed_launch
├── save_state
├── battery_save_isolation
├── window_input
├── touchscreen_input
├── screenshot
└── debugger_handshake_mode
```

A scenario may declare required capabilities. Validation fails before launch if the selected backend cannot satisfy them.

### Debugger dialect

The existing `RSPClient` remains the only transport. Emulator-specific session adapters determine connection/handshake behavior and register mapping.

Initial dialect distinction:

- melonDS retains the validated initial ACK handshake and register mapping already implemented by `MelonDSSession`;
- DeSmuME may connect without the melonDS initial ACK exchange and then use normal RSP negotiation/packets.

The exact behavior is verified in adapter tests and live smoke tests. No game code may choose packet-level behavior directly.

## Managed runtime session

### Session directory

Each managed run receives a cryptographically random session id and a dedicated directory, for example:

```text
.nds-runtime/
└── 5d46d0d2cfe747ef9c8c7a9b4ec08c24/
    ├── session.json
    ├── journal.json
    ├── emulator.stdout.log
    ├── emulator.stderr.log
    ├── debugger.log
    ├── display.log
    ├── current-frame.png
    ├── saves/
    ├── checkpoints/
    ├── traces/
    ├── cases/
    └── failure/
```

The root is configurable. Files are written atomically where partial state would be misleading.

### Session identity

`RuntimeSessionRecord` contains at minimum:

- session schema version;
- unique session id;
- lifecycle state;
- emulator kind;
- emulator executable path;
- executable SHA-256 when readable;
- emulator version/build metadata when available;
- ROM path and SHA-256;
- CPU/debugger target;
- process PID;
- process-group identity;
- process start identity sufficient to defend against PID reuse on supported hosts;
- debugger host/port;
- optional control socket/path;
- optional X11 display lease;
- bound window id when present;
- isolated save/config paths;
- timestamps as diagnostic metadata only;
- last completed scenario step/case when applicable.

Timestamps never define semantic target identity.

### Lifecycle state machine

```text
CREATED
  ↓
PREPARING
  ↓
LAUNCHING
  ↓
WAITING_FOR_RUNTIME
  ↓
READY
  ↓
RUNNING
  ↓
STOPPING
  ↓
CLOSED
```

Any non-terminal state may transition to `FAILED` with a durable failure reason. Recovery may adopt a still-valid owned process only after identity checks succeed.

### Process safety

Managed emulator processes are launched in their own process group/session. Cleanup targets only resources whose persisted identity still matches the session record.

The toolkit must not kill a process merely because its PID equals a recorded PID. On Linux, process start identity and executable identity are checked to prevent PID-reuse accidents. If ownership cannot be proven, cleanup reports the process as unowned and leaves it untouched.

### Port allocation

Hard-coded shared debugger ports are not used for managed concurrent sessions.

The allocator:

1. selects a currently free loopback port;
2. records it in the session before launch;
3. launches the backend configured for that port;
4. verifies that the expected debugger dialect becomes reachable within a bounded readiness window;
5. retries with a new port only when startup evidence shows a bind/collision failure rather than a game/runtime failure.

Port retry count is bounded. Existing attach-only commands keep their historical default ports.

## Host display and input automation

### Host driver boundary

`HostAutomationDriver` owns host-specific window/display operations:

```text
HostAutomationDriver
├── start_display()
├── stop_display()
├── wait_for_window()
├── bind_window()
├── query_client_geometry()
├── send_key()
├── pointer_down()
├── pointer_move()
├── pointer_up()
└── capture_window()
```

The first implementation is Linux/X11. It may invoke validated external tools through `subprocess`; no shell interpolation of user data is allowed.

### Isolated display

When a managed headless display is requested, the toolkit owns the Xvfb process and `DISPLAY` value for that session. It does not reuse an arbitrary shared global Xvfb instance unless explicitly requested.

The emulator launch environment is constructed explicitly. Ambient values such as `SDL_VIDEODRIVER=dummy` must not silently override a backend's required interactive display mode.

### Window binding

Input is sent only to a window that has been positively associated with the owned emulator process/backend. A window title match alone is insufficient when process identity is available.

If the window disappears, changes ownership, or cannot provide the expected geometry, the scenario stops rather than sending input to another desktop application.

## Nintendo DS input abstraction

### Buttons

Consumers use canonical DS controls:

```text
DSButton
├── A
├── B
├── X
├── Y
├── L
├── R
├── START
├── SELECT
├── UP
├── DOWN
├── LEFT
└── RIGHT
```

The emulator backend owns the deterministic mapping from these controls to configured host keys. Managed sessions use isolated emulator configuration where practical so user key bindings do not make automation nondeterministic.

### Touchscreen

Public touch coordinates use native NDS touchscreen coordinates:

```text
x: 0..255
y: 0..191
```

Initial gesture records:

```text
TouchTap
TouchDrag
TouchFlick
```

A gesture contains bounded timing and points in DS coordinates. The backend/host combination maps the lower-screen viewport into host window coordinates using the verified runtime window geometry and the backend's controlled screen layout.

Consumer scenario files never store X11 desktop coordinates.

### Deterministic layout requirement

Managed input runs require a backend layout profile the toolkit knows how to map. Rotation, unsupported screen separation, arbitrary resize, or unknown scaling cause preflight failure rather than guessed coordinate conversion.

## Guarded runtime memory mutation

Task 13 required changing a live value before triggering gameplay. That should use the same runtime transport as reads/traces rather than an external GDB path.

### RSP extension

Add bounded memory writes to the existing `RSPClient`, using standard RSP memory-write packets supported by the target. Runtime session adapters expose:

```python
write_memory(address: int, data: bytes) -> None
```

This is an explicit mutation operation; attaching remains non-mutating.

### Guarded write model

Scenario mutation uses a stronger primitive:

```text
RuntimeMemoryWrite
├── address
├── expected_before (optional but strongly recommended)
├── replacement
└── verify_after = true
```

For a guarded write:

1. read the current bytes;
2. if `expected_before` is supplied and differs, fail without writing;
3. perform one bounded write through `RSPClient`;
4. read back the region;
5. require exact replacement bytes when verification is enabled;
6. journal both pre-write and verified post-write hashes/bytes according to the configured evidence policy.

The toolkit does not infer what the bytes mean.

## Runtime checkpoints

### Checkpoint bundle

A checkpoint is a directory, not a naked savestate file:

```text
checkpoints/battle-ready/
├── checkpoint.json
├── state.bin          # opaque emulator-owned savestate extension/name as needed
├── battery-save.bin   # when available/applicable
└── evidence.json      # optional verification snapshot/fingerprints
```

`checkpoint.json` records:

- checkpoint schema version;
- emulator kind;
- emulator version/build identity;
- executable fingerprint when available;
- ROM SHA-256;
- CPU target;
- savestate filename/hash;
- battery-save filename/hash when present;
- optional PC/CPSR/register evidence;
- optional bounded memory fingerprints chosen by the consumer;
- creation metadata.

Savestate bytes remain emulator-specific and opaque to the toolkit.

### Restore compatibility

A checkpoint is restorable only when:

- ROM identity matches exactly;
- emulator backend matches;
- backend-declared savestate compatibility requirements are satisfied;
- required files/hashes validate.

Cross-emulator savestate conversion is out of scope.

### Restore verification

A successful emulator load command is not sufficient proof of correct game state. After restore, the runner waits for configured generic verification predicates such as expected PC range, register value, or memory fingerprint.

If verification fails, the scenario does not continue with input.

## State predicates

Initial predicates intentionally use deterministic runtime evidence rather than computer vision.

Supported predicate families:

```text
ProcessAlive
DebuggerReachable
WindowReady
PcEquals
PcInRange
RegisterEquals
MemoryEquals
MemoryMaskedEquals
AllOf
AnyOf
```

Each wait has:

- a finite timeout;
- a finite polling interval;
- a deterministic result record;
- last observed evidence on failure.

No unbounded polling loop is permitted.

A future phase may add framebuffer/image predicates, but 7H3 only captures frames for evidence.

## Scenario format and engine

### File format

The first scenario format is versioned JSON to avoid adding a YAML dependency and to match the toolkit's existing deterministic JSON conventions.

Example shape:

```json
{
  "schema_version": 1,
  "name": "representative-trigger",
  "backend": "desmume",
  "cpu": "arm9",
  "required_capabilities": ["save_state", "touchscreen_input"],
  "checkpoint": "battle-ready",
  "steps": [
    {
      "type": "wait",
      "condition": {"type": "memory_equals", "address": "0x02100000", "bytes": "00"},
      "timeout": 5.0
    },
    {
      "type": "memory_write",
      "address": "0x02100020",
      "expected_before": "48",
      "replacement": "01"
    },
    {
      "type": "button",
      "button": "A"
    },
    {
      "type": "wait",
      "condition": {"type": "memory_equals", "address": "0x02100004", "bytes": "01"},
      "timeout": 5.0
    },
    {
      "type": "touch_flick",
      "start": [128, 170],
      "end": [128, 40],
      "duration_ms": 180
    }
  ]
}
```

Addresses and bytes in game-owned files are data supplied by the consumer; they do not become toolkit policy.

### Step types

Initial generic steps:

- `wait`;
- `button` / `button_sequence`;
- `touch_tap`;
- `touch_drag` / `touch_flick`;
- `memory_write`;
- `capture_snapshot`;
- `capture_trace` using the existing Phase 7H2 engine;
- `assert` using the same predicate model;
- `checkpoint_save`;
- `checkpoint_restore`.

Every step has a stable id in the normalized internal model, even when omitted from user JSON and deterministically generated from ordinal position.

### Preconditions/postconditions

Input and mutation steps may include `precondition` and `postcondition` predicates. The runner evaluates the precondition before performing the action and the postcondition afterward.

This is the direct architectural answer to the Task 13 overview-map/launch-lane failure: the flick step cannot execute until its declared generic runtime condition is satisfied.

### Time semantics

All waits use monotonic time. Optional short settling delays may exist for GUI input, but a sleep is never accepted as proof that the game reached a state.

## Durable scenario journal and recovery

### Journal states

Each step is recorded as:

```text
PENDING
STARTED
COMPLETED
FAILED
```

The journal is atomically updated before a non-idempotent action begins and after its required postcondition/evidence succeeds.

### Resume anchors

A scenario may mark checkpoints as safe resume anchors. The runner also treats the scenario's initial checkpoint restore as an anchor.

If execution stops while a step is `STARTED` but not `COMPLETED`, the toolkit never assumes whether that action partially occurred. Recovery returns to the most recent valid anchor and replays from there.

### Live-session adoption

`runtime session resume` first determines whether the recorded process is still safely adoptable:

- PID/process-start identity still matches;
- executable identity matches when available;
- debugger endpoint answers with the expected dialect;
- ROM/session metadata matches;
- bound window/display still belongs to the session when UI input is required.

If all checks succeed, the session may continue from the journal's safe point.

If the process is gone or invalid but the last resume checkpoint remains valid, the toolkit launches a new owned emulator, restores the checkpoint, verifies it, and resumes from that anchor.

If neither condition is satisfied, it reports a real recovery blocker rather than reconstructing state by guesswork.

## Deterministic acceptance matrix

### Purpose

The matrix runner handles repeated representative cases that share one baseline state but vary controlled inputs/mutations and expected results.

Conceptual flow:

```text
validate environment once
        ↓
create isolated run/session
        ↓
restore baseline checkpoint
        ↓
verify baseline
        ↓
apply case parameters
        ↓
run guarded scenario
        ↓
capture evidence
        ↓
assert postconditions
        ↓
record PASS/FAIL
        ↓
restore same baseline
        ↓
next case
```

A case failure does not contaminate the next case; the next case starts only after the baseline checkpoint has been restored and verified again.

### Matrix file

A versioned JSON matrix references a scenario and supplies named cases. Case parameters may fill explicit scenario placeholders for byte values, labels, trace output names, or expected generic predicate values. Arbitrary string templating or shell-command interpolation is not allowed.

Example conceptual case records:

```json
{
  "schema_version": 1,
  "scenario": "representative-trigger.json",
  "cases": [
    {"id": "case-1", "parameters": {"test_value": "01"}},
    {"id": "case-2", "parameters": {"test_value": "15"}}
  ]
}
```

Game projects may give these cases semantic names; the toolkit treats them only as ids/labels.

### Result model

Each case records:

- case id;
- baseline checkpoint identity;
- session/run identity;
- resolved parameters;
- completed steps;
- assertions and evidence;
- trace paths/fingerprints when requested;
- duration as diagnostic metadata;
- PASS/FAIL;
- structured failure reason when failed.

The matrix summary is deterministic in case order and does not call a case PASS merely because the emulator stayed alive.

## Failure evidence bundles

When a managed action/scenario fails, 7H3 attempts bounded best-effort evidence collection without masking the original error.

A failure directory may contain:

```text
failure/
├── failure.json
├── session.json
├── journal.json
├── registers.json
├── memory.json
├── last-frame.png
├── emulator.stdout.log
├── emulator.stderr.log
├── debugger.log
├── display.log
├── process-state.json
└── relevant.ndstrace
```

`failure.json` contains at minimum:

- failure category;
- scenario/case/step id;
- action type;
- original exception/error boundary;
- last completed step;
- failed precondition/postcondition if applicable;
- last observed predicate evidence;
- current PC/stop reason when obtainable;
- whether the owned emulator was still alive;
- whether a safe resume anchor exists.

Evidence collection errors are appended as secondary diagnostics and never replace the primary failure.

## `runtime doctor`

Before a long experiment, the toolkit must be able to prove the environment is capable of running it.

Example:

```bash
nds-toolkit runtime doctor --emulator desmume
```

Checks are backend/capability aware and may include:

- emulator executable discoverable/executable;
- emulator version probe;
- ROM launch argument support when a ROM is supplied;
- Xvfb availability when managed display is requested;
- xdotool availability for X11 input;
- controlled SDL/X11 environment viability;
- window discovery/binding;
- deterministic layout/geometry support;
- ARM9/ARM7 debugger availability;
- RSP handshake/negotiation;
- register snapshot;
- bounded memory read;
- bounded verified memory write against a disposable deterministic CI target only when explicitly requested;
- temporary code breakpoint/step;
- savestate save/load capability when required by a scenario.

Doctor checks do not alter a user's game state unless the user supplies an explicit disposable test target and requests mutation/state tests. Basic environment checks remain non-destructive.

Human-readable output explains exactly which capability is missing. JSON output is deterministic for automation.

## CLI design

The initial command family is additive:

```text
nds-toolkit runtime doctor
nds-toolkit runtime launch
nds-toolkit runtime session info
nds-toolkit runtime session stop
nds-toolkit runtime session resume
nds-toolkit runtime checkpoint save
nds-toolkit runtime checkpoint restore
nds-toolkit runtime scenario run
nds-toolkit runtime matrix run
```

Existing commands remain:

```text
runtime probe
runtime snapshot
runtime read-memory
runtime run-until
runtime step
runtime trace capture
runtime trace inspect
runtime diff
```

Managed commands accept an emulator/backend selector. Existing attach-only commands preserve melonDS-compatible defaults for backward compatibility unless the user explicitly selects another runtime adapter.

## Error boundaries

Add orchestration-specific toolkit errors under the existing error hierarchy, for example:

```text
RuntimeOrchestrationError
├── RuntimeEnvironmentError
├── RuntimeLaunchError
├── RuntimeOwnershipError
├── RuntimeDisplayError
├── RuntimeInputError
├── RuntimeCheckpointError
├── RuntimeScenarioError
└── RuntimeRecoveryError
```

CLI mapping continues to use the toolkit's established error-code policy. Validation errors are detected before launching a process whenever possible.

Timeout messages identify the awaited condition and last observed evidence rather than reporting a generic timeout alone.

## Security and safety boundaries

Managed orchestration executes local emulator/helper processes. Therefore:

- command arguments are passed as argument arrays, never constructed through shell interpolation;
- scenario files cannot execute arbitrary shell commands;
- executable paths are explicit or discovered through constrained backend lookup;
- debugger endpoints default to loopback;
- session cleanup never kills a process without ownership validation;
- file writes remain inside configured session/checkpoint/result roots unless the user explicitly names an output path;
- checkpoint extraction/restore never trusts archive paths; the initial checkpoint format is a plain directory, not an untrusted archive;
- memory writes are explicit, bounded, and optionally guarded by expected-before bytes;
- no automatic patching of emulator binaries is introduced.

## Persistence/versioning

Phase 7H3 introduces independent JSON schema versions for:

- managed session record: version 1;
- checkpoint metadata: version 1;
- scenario format: version 1;
- acceptance matrix format: version 1;
- acceptance result/journal: version 1.

These versions are independent of `.ndsre` and `.ndstrace`.

Opening a newer unknown schema is rejected for mutation/resume. Older versions may receive explicit migrations in future phases; no implicit destructive migration is allowed.

## Testing strategy

### Unit tests

Use deterministic fake backends/host drivers/sessions to verify:

- lifecycle state transitions;
- process ownership and PID-reuse defense;
- bounded port retry behavior;
- emulator capability validation;
- melonDS and DeSmuME debugger handshake differences without duplicating `RSPClient`;
- bounded RSP memory-write framing and error handling;
- guarded write compare-before/write/read-back behavior;
- DS button mapping;
- DS touchscreen coordinate validation and geometry transforms;
- checkpoint metadata/hash validation;
- restore incompatibility rejection;
- predicate timeout and last-observation reporting;
- precondition prevents input/mutation;
- postcondition failure stops the scenario;
- journal `STARTED` versus `COMPLETED` behavior;
- recovery from the most recent safe anchor;
- matrix baseline restore between every case;
- failure evidence preserves the primary error when evidence collection also fails;
- deterministic JSON output/order.

### Integration tests

Use subprocess-backed deterministic fixtures to verify:

- owned process groups terminate without affecting unrelated processes;
- isolated log/session directories;
- Xvfb lifecycle and window binding on Linux;
- input is sent only to the owned test window;
- scenario resume after intentional controller termination;
- atomic journals/result files;
- existing Phase 7H2 `capture_trace()` works unchanged through the generic session protocol.

### Live emulator gates

Preserve the current pinned stock-melonDS live interoperability gate.

Add managed-launch coverage incrementally:

1. managed melonDS launch under the new process/session layer;
2. debugger readiness and existing runtime smoke tests through that managed session;
3. save/load and DS-input tests only where the pinned build provides deterministic automation semantics;
4. a pinned DeSmuME Linux/X11 integration gate that verifies the no-initial-ACK debugger dialect, owned Xvfb window, deterministic button/touch injection, and savestate restore on a synthetic/disposable ROM target.

If a stock emulator lacks a capability, the toolkit reports the limitation explicitly rather than faking the result, matching the precedent established for stock-melonDS watchpoints.

## Phased implementation boundary

The architecture is implemented in four reviewable slices.

### Phase 7H3A — Managed emulator lifecycle and diagnostics

- orchestration models/errors;
- emulator backend protocol;
- managed process/session directory;
- process ownership and cleanup;
- dynamic debugger port allocation;
- Linux Xvfb lease;
- melonDS managed backend;
- DeSmuME debugger session/backend with shared `RSPClient`;
- `runtime doctor`;
- `runtime launch` / session info/stop;
- live managed-launch smoke tests.

This slice solves launch, display inheritance, RSP-dialect, and stale-process collision problems before input automation is introduced.

### Phase 7H3B — Checkpoints and normalized DS input

- Linux/X11 host automation driver;
- owned-window binding;
- deterministic backend layout profile;
- `DSButton` and touch gesture models;
- DS-to-window coordinate transform;
- save/load checkpoint bundle;
- battery-save isolation/copying;
- restore compatibility and verification;
- checkpoint CLI commands.

This slice solves fragmented state and desktop-coordinate brittleness.

### Phase 7H3C — Guarded mutation and scenario runner

- standard RSP memory-write support in the existing transport;
- guarded runtime writes with read-back verification;
- predicate model;
- bounded waits;
- state-aware scenario steps;
- durable journal;
- safe-anchor resume;
- trace/snapshot integration;
- structured failure bundles;
- `runtime scenario run` and `runtime session resume`.

This slice directly prevents "correct input on the wrong game screen" failures and removes consumer-owned raw GDB mutation paths.

### Phase 7H3D — Deterministic acceptance matrix

- parameterized cases;
- baseline checkpoint restore before every case;
- contamination prevention after failures;
- per-case evidence/result bundles;
- resumable case boundaries;
- deterministic summary output;
- `runtime matrix run`;
- end-to-end live acceptance fixture.

This slice turns representative manual validation matrices into repeatable toolkit experiments.

## Explicitly deferred

Phase 7H3 does not implement:

- image/OCR-based game-state recognition;
- arbitrary shell-command scenario steps;
- cross-emulator savestate conversion;
- emulator binary patching;
- a second debugger/RSP stack;
- unrestricted runtime scripting/plugin execution;
- network-distributed emulator farms;
- macOS/Windows managed UI drivers;
- unbounded fuzzing/input exploration;
- game-specific scenario libraries inside the toolkit;
- automatic inference of which memory address represents a semantic game state.

Game-specific projects remain responsible for discovering and naming their state predicates and acceptance expectations using the static/dynamic RE capabilities already present in the toolkit.

## Success criteria

Phase 7H3 is complete when a consumer project can, through public toolkit APIs/CLI and without consumer-owned raw RSP/X11 process management:

1. diagnose whether a selected emulator/host can satisfy a declared experiment;
2. launch an isolated managed emulator session with unique debugger/display resources;
3. prove ownership and safely clean up or resume that session after controller interruption;
4. restore a ROM/emulator-matched checkpoint and verify the restored state;
5. send DS buttons/touch gestures without desktop-coordinate knowledge;
6. perform explicit bounded guarded runtime memory mutation through the existing RSP path;
7. refuse an action when its declared runtime precondition is false;
8. capture existing Phase 7H2 trace/memory evidence as scenario steps;
9. produce a durable diagnostic bundle on failure;
10. execute a multi-case acceptance matrix where every case starts from the same verified baseline and produces independently inspectable PASS/FAIL evidence.

The architectural outcome is:

```text
ROM + game-owned scenario/matrix
            ↓
      runtime doctor
            ↓
 isolated managed emulator
            ↓
 validated checkpoint restore
            ↓
 generic preconditions
            ↓
 guarded mutation + DS input
            ↓
 existing debugger / .ndstrace evidence
            ↓
 generic postconditions
            ↓
 result / failure bundle
            ↓
 baseline restore → next case
```

This makes runtime acceptance a reproducible experiment rather than an externally coordinated collection of emulator processes, host input scripts, save files, and debugger commands.