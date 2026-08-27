# Nitro asset inventory

The asset inventory is a read-only scanner for recognized Nintendo DS NitroFS asset formats.

## Command

```bash
nds-toolkit assets inventory GAME.nds --output assets.json
```

Use `--include-unknown` when unrecognized NitroFS files should also appear in the detailed record list. Unknown files are always counted even when omitted from the detailed list.

Generic inventory does not require a ROM profile. To require an exact profile match:

```bash
nds-toolkit assets inventory GAME.nds \
  --profile profile.json \
  --require-supported \
  --output assets.json
```

## Detection model

The scanner first applies the toolkit's strict LZ10 decoder when a file is LZ10-wrapped, then inspects the decoded payload.

### Signature-backed formats

These decoded four-byte signatures are recognized:

| Signature | Format |
| --- | --- |
| `BMD0` | NSBMD |
| `BTX0` | NSBTX |
| `SDAT` | SDAT |
| `NARC` | NARC |
| `RGCN` | NCGR |
| `RLCN` | NCLR |
| `RCSN` | NSCR |
| `BCA0` | NSBCA |
| `BMA0` | NSBMA |
| `BTP0` | NSBTP |
| `BTA0` | NSBTA |
| `BVA0` | NSBVA |

For signature-backed filename families, a matching extension without the expected decoded signature is not silently accepted. The record instead exposes an extension/signature mismatch.

### Raw extension-backed formats

Two raw payload families are recognized by extension because they do not carry the same self-identifying four-byte signature:

- `.ntft` -> NTFT tile data;
- `.ntfp` -> NTFP palette data.

These records are marked with `extension` evidence rather than signature evidence.

### Localized suffixes

Known extensions may include suffix variants such as `.nsbmd_x` or `.nsbtx_y`. The inventory preserves the literal suffix while normalizing the expected format family for signature comparison.

## Report contents

The deterministic JSON report includes:

- optional profile/support information from ROM inspection;
- scanned, recognized, unknown, and signed-mismatch counts;
- format and compression counts;
- file ID and NitroFS path;
- raw/decoded sizes;
- raw vs LZ10 storage classification;
- literal extension and expected extension family;
- detected format;
- evidence level;
- decoded four-byte magic text;
- extension/signature match state.

## Scope

Inventory stops at classification. It does not parse model geometry, texture contents, animation semantics, sound-bank internals, or game-specific `.bin` formats. Those should be implemented as separate format readers only when their structure is understood and reusable.
