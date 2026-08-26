# NDS Disassembly Toolkit

Reusable Nintendo DS reverse-engineering infrastructure for inspecting and working with NDS ROM structures without tying the core implementation to one game.

## Current status

Phase 1 provides the low-level standalone core:

- NDS header parsing
- FAT parsing
- FNT/NitroFS name-tree parsing
- ARM9 and ARM7 overlay-table parsing
- deterministic LZ10 compression and decompression
- BLZ footer parsing, decompression, in-place decode modeling, and deterministic compression
- shared binary bounds/read helpers and generic error types
- a minimal `nds-toolkit` CLI entry point ready for later command groups

Higher-level inspection, workspace extraction/rebuild, disassembly/analysis, asset tooling, and patch/source infrastructure are intentionally scheduled for later migration phases rather than being stubbed with incomplete behavior.

## Reuse and project separation

The initial low-level core is migrated from proven generic Nintendo DS infrastructure previously developed inside `79cbd8hmgj-wq/Bakugan-DS-`. Working format logic is retained wherever it is already game-independent; changes are limited to package boundaries, generic naming, and neutral synthetic tests unless a real abstraction or correctness issue requires more.

Bakugan-specific ROM identity, runtime addresses, Gate Card systems, G-Power logic, gameplay patches, and game-specific integration tests remain in the Bakugan project. The old generic copies are not removed until the standalone toolkit is verified and Bakugan has been converted to consume it successfully.

## Legal boundary

This repository contains source code, documentation, schemas, and synthetic tests. It must not contain commercial ROM images, extracted copyrighted game assets, or rebuilt ROM images. Users are responsible for supplying any legally obtained ROMs required by future integration workflows.

## Development setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
```

Run static checks with:

```bash
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

## CLI

```bash
nds-toolkit --help
# or
python -m nds_disassembly_toolkit --help
```

The CLI is deliberately minimal in Phase 1. Commands such as `inspect`, `extract`, `rebuild`, `disassemble`, `analyze`, `assets`, and `patch` will be added only as their underlying reusable subsystems are migrated and verified.

## Architecture and implementation plan

- `docs/superpowers/specs/2026-08-26-standalone-toolkit-architecture-design.md`
- `docs/superpowers/plans/2026-08-26-phase-1-low-level-core.md`
