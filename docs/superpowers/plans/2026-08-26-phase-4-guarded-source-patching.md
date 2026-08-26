# Phase 4: Generic Guarded Source Patching

**Status:** Contract tests first; implementation pending.

## Goal

Migrate the proven guarded C/assembly source-patching pipeline from `Bakugan-DS-` into the standalone toolkit while removing hidden game-specific storage policy.

## Reuse rule

Preserve the existing manifest validation, compile/link pipeline, hook guards, transactional writes, and exact-size storage re-encoding. Refactor only where Bakugan policy is embedded in otherwise generic mechanics.

## Generic API boundary

- Source-patch manifests may optionally carry a consumer `profile_id`; exact runtime SHA-256 guards remain mandatory.
- Overlay targets can resolve from a toolkit workspace without a ROM profile because overlay RAM metadata is already in the workspace manifest.
- ARM9/ARM7 targets require an explicit generic `RomProfile` until ARM runtime geometry is persisted directly in the workspace manifest.
- BLZ passthrough length defaults to the original stream geometry and may be explicitly overridden by the caller.
- No profile ID, ROM hash, fixed ARM9 size, fixed passthrough length, or game address is hard-coded in runtime policy.
- Hook encoding supports ARM B/BL and Thumb B/BL with exact alignment/range validation.
- Source compilation remains clang/LLD/nm based, deterministic, shell-free, and size-budgeted.

## Deliberately retained in Bakugan

- The `b6re_rev0` source-patch manifests and game addresses.
- B6RE ARM9's `0x8000` BLZ passthrough choice.
- Gate-system helper definitions and hook symbols.
- Bakugan source files and game-specific patch reports.

## Safety invariants

- Runtime SHA-256 is checked before external compilation and rechecked before writeback.
- Hook expected bytes are validated before any mutation.
- Hook ranges cannot overlap each other or injected code.
- Compiled symbols used by hooks must resolve inside the emitted image.
- Target writes and patch reports are committed transactionally with rollback on report failure.
- Existing BLZ stored size must be reproduced exactly or the patch fails closed.
- Source paths cannot escape the manifest directory.
- No shell command construction is used.
