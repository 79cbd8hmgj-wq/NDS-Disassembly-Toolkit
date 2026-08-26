# Phase 2: Generic Inspection and Workspace Round-Trip

**Status:** Complete; Python 3.11 CI, pytest, Ruff, and strict mypy pass.

## Goal

Migrate the proven ROM inspection, workspace extraction/validation, manifest, override, and rebuild machinery from `Bakugan-DS-` into the standalone toolkit while preserving behavior and removing game-specific policy.

## Reuse rule

Reuse the Bakugan implementation unless a change is required to make it game-agnostic. Do not rewrite algorithms for style.

## API boundary

- `RomProfile` and profile loading remain available as generic optional strict-validation machinery.
- `inspect_rom(path, profile=None, require_supported=False)` works without a profile.
- `extract_workspace(rom, options, *, profile=None, require_supported=False)` works without a profile.
- `validate_workspace(source_rom, workspace, *, profile=None, require_supported=False)` binds the workspace to the exact source ROM by size/SHA-256 and optionally to a profile.
- `rebuild_rom(source_rom, workspace, options, *, profile=None, require_supported=False)` preserves exact-copy behavior for unchanged workspaces.
- Workspace manifests and build overrides may carry an optional `profile_id`; no game-specific profile ID is hard-coded in the toolkit.

## Migration order

1. Generic ROM profiles and identity hashing.
2. Profile-optional ROM inspection.
3. Workspace paths/model/manifest.
4. Profile-neutral build overrides.
5. Transactional extraction.
6. Workspace validation/change detection.
7. Deterministic rebuild and structural verification.
8. CLI commands for inspect/extract/rebuild.
9. Synthetic no-profile extraction/rebuild round-trip verification.

## Verification

- Python 3.11 installation: pass.
- Unit/regression suite: 62 tests passed.
- Ruff: pass.
- Strict mypy: pass.
- Synthetic profile-free extract/rebuild: byte-for-byte exact round trip.

## Safety invariants

- Never commit ROMs or extracted copyrighted assets.
- Original workspace trees remain read-only after extraction.
- Existing workspaces/outputs require `--force` to replace.
- Source ROM size and SHA-256 must match the workspace manifest before rebuilding.
- FNT paths are traversal-safe and unique.
- FAT payloads remain non-overlapping and 0x200-aligned after changed rebuilds.
- Modified overlays must match declared RAM geometry unless an explicit validated override expands it.
- Changed compressed NitroFS data is deterministically re-encoded with existing LZ10 behavior.
- Unchanged workspaces rebuild to a byte-for-byte exact source copy.
