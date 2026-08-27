# Guarded ARM/Thumb source patching

The source-patch bridge compiles small, explicitly approved ARMv5TE C/assembly payloads into an existing runtime allocation and applies guarded branch hooks inside an extracted workspace.

It does not discover free space, grow overlays, download a compiler, guess symbols, or build a ROM directly. Rebuild remains a separate operation.

## Command

```bash
nds-toolkit source-patch build WORKSPACE MANIFEST \
  [--profile PROFILE] [--clang PATH] [--ld PATH] [--nm PATH]
```

Default tools are `clang`, `ld.lld`, and `nm`. They are executed directly as argument arrays; no shell is used.

## Manifest

Format version `1` uses this general shape:

```json
{
  "format_version": 1,
  "profile_id": "optional-profile-id",
  "target": "overlay:7",
  "runtime_address": 35655680,
  "max_size": 256,
  "mode": "arm",
  "expected_runtime_sha256": "64-character-decoded-runtime-sha256",
  "sources": ["src/injected.c"],
  "definitions": {
    "known_function": 33558528
  },
  "hooks": [
    {
      "id": "call_injected",
      "runtime_address": 35651584,
      "expected": "000000ea",
      "symbol": "injected_entry",
      "link": true,
      "mode": "arm"
    }
  ]
}
```

`profile_id`, `definitions`, `hooks`, and `blz_passthrough_length` are optional at the generic toolkit level. Consumer projects may require additional policy.

## Targets

Source patches support:

- `arm9`
- `arm7`
- `overlay:<id>`

NitroFS data files are not source-patch execution targets.

The runtime placement must be aligned for the selected mode: 4-byte alignment for ARM and 2-byte alignment for Thumb.

## Source files

Manifest source paths are relative to the manifest directory. The loader rejects absolute/path-traversal forms, duplicates, missing files, and unsupported suffixes. The current bridge accepts `.c` and `.s`.

## Compilation model

C/assembly is compiled for Nintendo DS ARM9-compatible ARMv5TE:

```text
clang --target=arm-none-eabi -mcpu=arm946e-s -marm|-mthumb \
  -ffreestanding -fno-builtin -fno-stack-protector \
  -fno-unwind-tables -fno-asynchronous-unwind-tables
```

The generated linker script:

- starts at the approved `runtime_address`;
- keeps `.text*`, `.rodata*`, and `.data*`;
- rejects nonzero `.bss`;
- discards unwind/comment/note metadata;
- asserts that the emitted image stays inside `max_size`.

Externally known functions/data are supplied explicitly through `definitions`; the bridge does not infer symbols.

## Runtime guards

`expected_runtime_sha256` binds the manifest to the complete decoded runtime image before mutation. This prevents a source patch from silently applying to a different binary state.

The selected runtime placement must resolve inside the target component and fit inside the approved byte budget.

## Hooks

ARM hooks use ARM `B`/`BL`. Thumb hooks support the implemented Thumb branch encodings within architectural range. The bridge does not synthesize interworking veneers, so hook mode must match source mode.

Every hook declares:

- a unique ID;
- runtime address;
- exact expected instruction bytes;
- compiled destination symbol;
- branch vs branch-with-link selection;
- ARM/Thumb mode.

Before mutation, hook guards, ranges, destination symbols, source placement, and overlap constraints are validated. A stale guard fails closed.

## BLZ ARM targets

ARM9/ARM7 targets stored as BLZ are decoded before runtime addressing. On re-encode, the toolkit preserves the original stored size and validates the resulting storage image.

`blz_passthrough_length` may optionally select a non-negative passthrough geometry for a BLZ ARM target. It is invalid for overlay targets or non-BLZ ARM targets. Game projects may enforce one exact passthrough value when their ROM evidence requires it.

Overlay workspace files are already represented as decoded runtime images and therefore do not use a BLZ passthrough override.

## Transaction and report

The patcher builds and validates the complete replacement in memory, revalidates the target around external compilation, and performs stale-write checks before publication. Failure after target replacement during final report publication triggers rollback to the original bytes.

A successful run writes:

```text
WORKSPACE/manifests/source-patch-<manifest-stem>.json
```

The report records normalized tool commands, source hashes, compiled size/hash, original/final runtime and stored hashes, storage encoding, placement information, and applied hook metadata.

After source patching, rebuild normally:

```bash
nds-toolkit rebuild GAME.nds WORKSPACE output.nds
```

## Ownership boundary

The compiler bridge, addressing mechanics, branch encoding, guarding, rollback, and reporting are generic toolkit behavior. A game repository should own approved runtime placements, exact hashes/bytes, known symbol addresses, profile requirements, and evidence that a hook or code cave is safe for its target ROM.
