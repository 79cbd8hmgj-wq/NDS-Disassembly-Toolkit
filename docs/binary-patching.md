# Guarded binary patching

The toolkit applies fixed-length binary replacements to an extracted workspace. Every change is guarded by the exact bytes expected at the target location.

## Command

```bash
nds-toolkit patch work/game patch.json
```

A successful application writes a normalized report under:

```text
WORKSPACE/manifests/patch-<patch-file-stem>.json
```

## Patch document

Format version `1` uses this shape:

```json
{
  "format_version": 1,
  "profile_id": "optional-profile-id",
  "patches": [
    {
      "id": "example-change",
      "type": "binary_replace",
      "target": "overlay:7",
      "offset": 4096,
      "expected": "00112233",
      "replacement": "44556677",
      "rationale": "Documented behavior change"
    }
  ]
}
```

`profile_id` may be `null`/omitted for a generic unbound patch set. Consumer projects may require a nonempty profile ID as additional policy.

## Supported targets

Patch application resolves workspace targets using these forms:

- `arm9`
- `arm7`
- `overlay:<id>`
- `nitrofs:<original FNT path>`

Offsets are non-negative byte offsets into the editable target representation.

## Validation

Each patch must satisfy all of the following:

- `format_version` is `1`;
- the patch list is nonempty;
- IDs are nonempty and unique;
- `type` is `binary_replace`;
- expected/replacement values are nonempty valid hexadecimal;
- expected and replacement lengths are identical;
- the target and byte range resolve inside the workspace;
- current target bytes exactly equal `expected` before mutation;
- profile binding, when declared, is compatible with the workspace.

The guarded model is intentionally fixed-length. Binary patching does not insert bytes, grow components, discover free space, or infer relocation changes.

## Transaction boundary

Guards are evaluated before their corresponding writes. A stale expected byte sequence fails closed rather than applying a best-effort patch.

The patch report records the normalized changes that were applied. Rebuild remains a separate operation:

```bash
nds-toolkit rebuild GAME.nds work/game output.nds
```

For commercial-game projects, write operations should normally be wrapped in an exact-profile policy even though the generic toolkit permits unbound workspaces and patch sets.

## Ownership boundary

The patch engine and schema are generic toolkit infrastructure. Game repositories should own the actual patch documents, rationale, addresses/offsets, expected bytes, supported-profile policy, and evidence that a modification is correct for a specific ROM.
