# Phase 7H runtime provenance addendum

Audit date: 2026-09-01

This addendum records the external-source and licensing boundary for the Phase 7H1 melonDS runtime-analysis bridge. It supplements `docs/provenance-and-licenses.md` without changing the repository's MIT license or the existing third-party dependency list.

## melonDS reference boundary

Reference lineage: `https://github.com/melonDS-emu/melonDS`

Supplied source archive: `melonDS-master.zip`

License observed in the supplied archive: GNU GPL v3.

Phase 7H1 uses melonDS as behavioral and interoperability reference material only. No melonDS implementation file is vendored, copied into a toolkit module, compiled into the toolkit, linked to the toolkit, or imported as a Python dependency.

The runtime bridge communicates with a separately running emulator process through the GDB Remote Serial Protocol over TCP. This preserves a process/interface boundary between the GPL emulator and the MIT toolkit.

## Source facts inspected

The supplied archive was inspected to verify debugger-facing facts necessary for correct interoperability, principally the debugger register enumeration in `src/debug/GdbArch.h`.

That enumeration established the order of the 39 32-bit words returned by the melonDS register dump:

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

The toolkit records that ordering as interoperability data in its own Python adapter and independently decodes each word as little-endian data. It does not reproduce melonDS debugger classes, control flow, packet-parser implementation, emulator-core logic, or source comments.

Standard GDB RSP packet forms used by the bridge (`qSupported`, `g`, `m`, `Z`/`z`, `c`, `s`, interrupt, and detach) are protocol interoperability behavior, not incorporated melonDS implementation expression.

## Independently implemented toolkit code

Phase 7H1 implementation is toolkit-owned Python using the standard library plus existing toolkit models:

- `analysis/runtime/model.py` defines immutable CPU/register/stop/location models;
- `analysis/runtime/rsp.py` independently implements TCP RSP framing, buffering, checksums, ACK/no-ACK handling, capability negotiation, memory/register reads, stop parsing, execution control, and explicit error translation;
- `analysis/runtime/melonds.py` confines melonDS-specific endpoint/register-layout behavior to one adapter;
- `analysis/runtime/correlation.py` correlates live PCs through the existing public `AnalysisProject` query API;
- `analysis/runtime_cli.py` provides bounded argparse commands and deterministic atomic JSON output.

No source file from the supplied melonDS archive was used as a base file or translated line-by-line.

## Dependency and persistence audit

Phase 7H1 adds no third-party runtime dependency. `pyproject.toml` remains unchanged by the phase.

The runtime package does not import or depend on:

- `sqlite3` directly;
- Capstone directly;
- angr;
- melonDS libraries or bindings.

Static project correlation is read-only and goes through `AnalysisProject.open(..., read_only=True)`. Phase 7H1 does not alter the `.ndsre` manifest format, SQLite schema, analysis-model version, or annotation semantics, and it does not persist live runtime observations.

## Game-specific boundary

No game-specific address, symbol, patch, record schema, gameplay assumption, or consumer-specific confidence rule belongs in the Phase 7H runtime package. Game projects may consume runtime snapshots and correlate them with their own `.ndsre` analysis, but interpretation remains consumer-owned.

## Security boundary

GDB RSP itself does not provide authentication or encryption. The toolkit therefore defaults to `127.0.0.1` and documentation recommends loopback or a separately secured tunnel rather than direct exposure to an untrusted network. This is an interface-safety property, not a melonDS licensing requirement.

## Manual validation boundary

Automated tests use protocol doubles and persisted-project fixtures. CI does not run an interactive stock melonDS instance, so a live-emulator smoke test remains a manual release gate. Such a test should record the exact melonDS build/configuration and exercise probe, snapshot, memory read, breakpoint, watchpoint, and bounded stepping before claiming live compatibility for that configuration.
