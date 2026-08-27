# Workspace extraction and rebuild

The toolkit can convert a Nintendo DS ROM into a deterministic editable workspace and rebuild a ROM from that workspace.

## Extract

```bash
nds-toolkit extract GAME.nds work/game
```

Use `--force` only when replacing an existing workspace. Extraction is transactional: a complete staging workspace is built and validated before it replaces the target path.

Generic extraction does not require a game profile. To bind extraction to an exact ROM identity, provide both a profile and strict support policy:

```bash
nds-toolkit extract GAME.nds work/game \
  --profile profile.json \
  --require-supported
```

## Workspace layout

The workspace separates immutable reference bytes from editable content:

```text
workspace/
├── original/
│   ├── arm9.bin
│   ├── arm7.bin
│   ├── raw/
│   │   ├── overlays/
│   │   └── nitrofs/
│   └── decoded/
│       ├── overlays/
│       └── nitrofs/
├── modified/
│   ├── arm9.bin
│   ├── arm7.bin
│   ├── overlays/
│   └── nitrofs/
└── manifests/
    ├── workspace.json
    ├── files.json
    └── overlays.json
```

`original/raw` preserves stored ROM payload bytes. `original/decoded` contains decoded reference payloads where the toolkit understands the storage encoding. `modified` begins from the editable decoded representation and is the tree intended for changes.

The original tree is made read-only after successful extraction as an accidental-edit safeguard. File permissions are not treated as a security boundary.

### Compression representation

- NitroFS files with valid LZ10 storage are preserved compressed under `original/raw/nitrofs` and decoded under `original/decoded/nitrofs` and `modified/nitrofs`.
- Overlay FAT payloads are preserved exactly under `original/raw/overlays`; decoded overlay runtime images are stored under `original/decoded/overlays` and `modified/overlays`.
- Unrecognized/raw NitroFS files remain byte-identical between raw and decoded representations unless an explicit supported transform applies.

The manifests record the hashes, sizes, compression classification, file/overlay identities, runtime addresses, and mapping information required for validation and rebuild.

## Validate before rebuild

Rebuild validates the reference ROM and workspace mappings before writing output. The validator rejects stale or structurally inconsistent workspaces rather than guessing how to repair them.

Profile binding is optional at the generic toolkit level. A workspace extracted with a profile records that profile ID; consumer projects may impose stricter profile rules.

## Rebuild

```bash
nds-toolkit rebuild GAME.nds work/game output.nds
```

For exact-profile workflows:

```bash
nds-toolkit rebuild GAME.nds work/game output.nds \
  --profile profile.json \
  --require-supported
```

Use `--force` to replace an existing output. The build report is written beside the ROM as:

```text
output.nds.build.json
```

The report records source/output SHA-256 values, output size, whether the output is an exact copy, and normalized changed-component records.

## Rebuild behavior

When no editable component has changed, rebuild produces an exact copy of the source ROM.

For changed payloads:

- changed NitroFS resources originally stored as LZ10 are recompressed deterministically;
- changed raw NitroFS resources are written as raw bytes;
- unchanged FAT-backed payloads reuse the exact original stored bytes;
- changed overlays are written as decoded/uncompressed overlay payloads and their compression flag is cleared unless an explicit validated overlay-layout override supplies replacement metadata;
- ARM9 and ARM7 edits must satisfy workspace validation and fixed-layout constraints;
- FAT-backed payloads are repacked deterministically and the rebuilt ROM is structurally reparsed before publication.

The original ROM remains the template for structures and bytes that are not explicitly rebuilt.

## Build overrides

The toolkit supports validated workspace override metadata for advanced cases such as raw NitroFS replacement or approved overlay layout changes. These overrides are generic mechanisms, not automatic expansion or free-space discovery. Consumer projects remain responsible for proving that a requested layout change is valid for their target ROM.

## Safety boundary

Workspace extraction/rebuild is infrastructure, not game-specific correctness proof. A consumer that modifies a known commercial game should normally bind write operations to an exact, reviewed profile and keep game-specific evidence outside this repository.
