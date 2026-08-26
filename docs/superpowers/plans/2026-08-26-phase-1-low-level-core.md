# Phase 1 Low-Level Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bootstrap the standalone NDS Disassembly Toolkit and migrate the proven game-agnostic NDS header/FAT/FNT/overlay and LZ10/BLZ implementations with their behavior preserved under a new namespace.

**Architecture:** Reuse the existing implementations from `79cbd8hmgj-wq/Bakugan-DS-` wherever they already describe Nintendo DS formats generically. Change only package imports, generic exception naming, package metadata, and synthetic fixtures that currently carry Bakugan identity. No Bakugan ROM profile, Gate Card, G-Power, or gameplay code enters this repository.

**Tech Stack:** Python 3.11+, setuptools, pytest 8.3+, ruff 0.6+, mypy 1.11+

**Spec:** `docs/superpowers/specs/2026-08-26-standalone-toolkit-architecture-design.md`

## Global Constraints

- Preserve proven generic code rather than rewriting it for stylistic reasons.
- The package namespace is `nds_disassembly_toolkit`.
- The distribution name is `nds-disassembly-toolkit`.
- Python requirement remains `>=3.11`.
- Nintendo DS structural parsing must not depend on a Bakugan game code, title, revision, or hash.
- No ROMs, extracted copyrighted assets, or rebuilt ROMs are committed.
- Existing validation and deterministic compression behavior must be preserved.
- Tests use synthetic fixtures; ROM-dependent tests remain future integration tests requiring user-supplied files.
- Phase 1 does not migrate workspace extraction/rebuild, disassembly analysis, assets, patching, source compilation, or Bakugan consumer imports.

---

## File Structure

```text
NDS-Disassembly-Toolkit/
├── .gitignore
├── README.md
├── pyproject.toml
├── src/
│   └── nds_disassembly_toolkit/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── errors.py
│       ├── util.py
│       ├── nds/
│       │   ├── __init__.py
│       │   ├── header.py
│       │   ├── fat.py
│       │   ├── fnt.py
│       │   └── overlays.py
│       └── compression/
│           ├── __init__.py
│           ├── lz10.py
│           └── blz.py
└── tests/
    ├── conftest.py
    └── unit/
        ├── test_header.py
        ├── test_fat.py
        ├── test_fnt.py
        ├── test_overlays.py
        ├── test_lz10.py
        ├── test_lz10_compress.py
        └── test_blz.py
```

---

### Task 1: Bootstrap the standalone Python package

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `README.md`
- Create: `src/nds_disassembly_toolkit/__init__.py`
- Create: `src/nds_disassembly_toolkit/__main__.py`
- Create: `src/nds_disassembly_toolkit/cli.py`

**Interfaces:**
- Produces: installable `nds-disassembly-toolkit` distribution and `nds-toolkit` console entry point.
- Produces: `nds_disassembly_toolkit.cli.main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1: Add the package metadata and smoke test**

Create `pyproject.toml` with setuptools, Python `>=3.11`, MIT license metadata, dev dependencies `mypy>=1.11`, `pytest>=8.3`, `ruff>=0.6`, strict mypy for `nds_disassembly_toolkit`, and:

```toml
[project.scripts]
nds-toolkit = "nds_disassembly_toolkit.cli:main"
```

Create a minimal CLI whose no-argument parser succeeds and returns `0` after displaying help through argparse.

- [ ] **Step 2: Run package smoke checks**

Run:

```bash
python -m pip install -e '.[dev]'
python -m nds_disassembly_toolkit --help
nds-toolkit --help
```

Expected: all commands exit successfully and identify the project as the NDS Disassembly Toolkit.

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml .gitignore README.md src/nds_disassembly_toolkit
git commit -m "feat: bootstrap standalone NDS toolkit"
```

---

### Task 2: Migrate generic errors and binary buffer helpers

**Files:**
- Create: `src/nds_disassembly_toolkit/errors.py`
- Create: `src/nds_disassembly_toolkit/util.py`
- Test: `tests/unit/test_header.py`

**Interfaces:**
- Produces: `NdsToolkitError`, `ProfileError`, `UnsupportedRomError`, `RomFormatError`, `BoundsError`, `WorkspaceError`.
- Produces: `Buffer = bytes | bytearray | memoryview`.
- Produces: `require_range(data, offset, size, label) -> memoryview`, `read_u16_le(...) -> int`, `read_u32_le(...) -> int`.

- [ ] **Step 1: Write failing utility tests**

```python
import pytest
from nds_disassembly_toolkit.errors import BoundsError
from nds_disassembly_toolkit.util import read_u16_le, read_u32_le, require_range


def test_require_range_returns_requested_slice() -> None:
    assert bytes(require_range(b"abcdef", 1, 3, "test")) == b"bcd"


def test_require_range_rejects_negative_offset() -> None:
    with pytest.raises(BoundsError, match="test"):
        require_range(b"abc", -1, 1, "test")


def test_integer_readers_use_little_endian() -> None:
    data = bytes.fromhex("341278563412")
    assert read_u16_le(data, 0, "u16") == 0x1234
    assert read_u32_le(data, 2, "u32") == 0x12345678
```

- [ ] **Step 2: Verify failure**

Run `pytest tests/unit/test_header.py -k 'require_range or integer_readers' -v`.
Expected: import failure because the standalone modules do not exist yet.

- [ ] **Step 3: Migrate the existing implementations**

Copy the existing `bakugan_ds.util` implementation with imports changed to `nds_disassembly_toolkit.errors`. Copy the existing exception hierarchy but rename the base class from `BakuganDSError` to `NdsToolkitError`; subclasses inherit from `NdsToolkitError` without otherwise changing their semantics.

- [ ] **Step 4: Verify pass**

Run `pytest tests/unit/test_header.py -k 'require_range or integer_readers' -v`.
Expected: 3 passing tests.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/errors.py src/nds_disassembly_toolkit/util.py tests/unit/test_header.py
git commit -m "feat: add generic binary parsing primitives"
```

---

### Task 3: Migrate NDS header parsing with a game-neutral fixture

**Files:**
- Create: `src/nds_disassembly_toolkit/nds/__init__.py`
- Create: `src/nds_disassembly_toolkit/nds/header.py`
- Create: `tests/conftest.py`
- Modify: `tests/unit/test_header.py`

**Interfaces:**
- Produces: immutable `SectionRange(name: str, offset: int, size: int)` with `.end`.
- Produces: immutable `NdsHeader` with existing ARM9/ARM7/FNT/FAT/overlay fields.
- Produces: `NdsHeader.from_bytes(data: Buffer) -> NdsHeader`.
- Produces: `NdsHeader.section_ranges() -> tuple[SectionRange, ...]`.

- [ ] **Step 1: Add a synthetic neutral NDS header fixture**

Use a 0x200-byte fixture with title `SYNTH NDS`, game code `TST0`, maker code `00`, revision `1`, and structurally valid synthetic offsets/sizes. Do not preserve `BAKUGAN W` or `B6RE` in standalone unit fixtures.

- [ ] **Step 2: Port the existing header tests**

Retain tests for truncation, little-endian parsing, section fields, and overlay-table-size validation. Change only imports and expected synthetic fixture identity/values.

- [ ] **Step 3: Verify tests fail before implementation**

Run `pytest tests/unit/test_header.py -v`.
Expected: header imports/behavior missing.

- [ ] **Step 4: Migrate `NdsHeader` and `SectionRange`**

Copy the proven parser from `bakugan_ds.nds.header`, changing imports only. Preserve strict ASCII decoding and the requirement that overlay table sizes are multiples of 32.

- [ ] **Step 5: Verify pass**

Run `pytest tests/unit/test_header.py -v`.
Expected: all header tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/nds_disassembly_toolkit/nds tests/conftest.py tests/unit/test_header.py
git commit -m "feat: migrate generic NDS header parser"
```

---

### Task 4: Migrate FAT and FNT parsing

**Files:**
- Create: `src/nds_disassembly_toolkit/nds/fat.py`
- Create: `src/nds_disassembly_toolkit/nds/fnt.py`
- Create: `tests/unit/test_fat.py`
- Create: `tests/unit/test_fnt.py`

**Interfaces:**
- Produces: `FatEntry(file_id: int, start: int, end: int)` with `.size`.
- Produces: `parse_fat(data: Buffer, header: NdsHeader) -> tuple[FatEntry, ...]`.
- Produces: `ROOT_DIRECTORY_ID = 0xF000`.
- Produces: `FntDirectory`, `FntFile`, `FntTree` and `FntTree.file_by_id()`.
- Produces: `parse_fnt(data: Buffer, header: NdsHeader, fat_entry_count: int) -> FntTree`.

- [ ] **Step 1: Port FAT/FNT tests with namespace-only changes**

Preserve the existing malformed-range, bounds, file-ID, directory-cycle, unreachable-directory, ASCII-name, and path-building expectations. Where an old fixture embeds Bakugan identity only to construct an `NdsHeader`, replace it with the neutral synthetic header fixture.

- [ ] **Step 2: Verify failure**

Run:

```bash
pytest tests/unit/test_fat.py tests/unit/test_fnt.py -v
```

Expected: imports fail because FAT/FNT modules are not present.

- [ ] **Step 3: Migrate the existing FAT/FNT implementations**

Copy the proven code with imports redirected to the standalone package. Preserve range validation, FAT ordering validation, directory-cycle detection, unreachable-directory rejection, and POSIX path semantics.

- [ ] **Step 4: Verify pass**

Run `pytest tests/unit/test_fat.py tests/unit/test_fnt.py -v`.
Expected: all migrated FAT/FNT tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/nds/fat.py src/nds_disassembly_toolkit/nds/fnt.py tests/unit/test_fat.py tests/unit/test_fnt.py
git commit -m "feat: migrate NDS filesystem table parsers"
```

---

### Task 5: Migrate overlay-table parsing

**Files:**
- Create: `src/nds_disassembly_toolkit/nds/overlays.py`
- Create: `tests/unit/test_overlays.py`

**Interfaces:**
- Produces: `OVERLAY_ENTRY_SIZE = 32`.
- Produces: immutable `OverlayEntry` with `.compressed_size`, `.flags`, and `.ram_end`.
- Produces: `parse_overlay_table(data, offset, size, table_name) -> tuple[OverlayEntry, ...]`.
- Produces: `parse_arm9_overlays(data, header)` and `parse_arm7_overlays(data, header)`.

- [ ] **Step 1: Port existing overlay tests**

Preserve duplicate-ID rejection, 32-byte table-size validation, static-initializer range validation, empty-table behavior, and reserved-field compressed-size/flag interpretation.

- [ ] **Step 2: Verify failure**

Run `pytest tests/unit/test_overlays.py -v`.
Expected: import failure.

- [ ] **Step 3: Copy the generic implementation with namespace updates**

Do not change binary layout or validation semantics.

- [ ] **Step 4: Verify pass**

Run `pytest tests/unit/test_overlays.py -v`.
Expected: all overlay tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/nds/overlays.py tests/unit/test_overlays.py
git commit -m "feat: migrate NDS overlay table parser"
```

---

### Task 6: Migrate deterministic LZ10 support

**Files:**
- Create: `src/nds_disassembly_toolkit/compression/__init__.py`
- Create: `src/nds_disassembly_toolkit/compression/lz10.py`
- Create: `tests/unit/test_lz10.py`
- Create: `tests/unit/test_lz10_compress.py`

**Interfaces:**
- Produces: `is_lz10(data: Buffer) -> bool`.
- Produces: `lz10_declared_size(data: Buffer) -> int`.
- Produces: `decompress_lz10(data: Buffer) -> bytes`.
- Produces: `compress_lz10(data: bytes) -> bytes`.

- [ ] **Step 1: Port existing decompression and compression tests**

Keep tests for malformed/truncated headers, invalid displacements, literals, references, declared-size termination, empty-input rejection, 24-bit input-size rejection, deterministic literal-only encoder output, and round trips.

- [ ] **Step 2: Verify failure**

Run `pytest tests/unit/test_lz10.py tests/unit/test_lz10_compress.py -v`.
Expected: import failure.

- [ ] **Step 3: Migrate LZ10 implementation unchanged except imports**

Preserve the current deterministic literal-only compressor. Optimization is explicitly out of scope for this migration.

- [ ] **Step 4: Verify pass**

Run `pytest tests/unit/test_lz10.py tests/unit/test_lz10_compress.py -v`.
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/compression tests/unit/test_lz10.py tests/unit/test_lz10_compress.py
git commit -m "feat: migrate deterministic LZ10 support"
```

---

### Task 7: Migrate BLZ decode/encode support

**Files:**
- Create: `src/nds_disassembly_toolkit/compression/blz.py`
- Create: `tests/unit/test_blz.py`
- Modify: `src/nds_disassembly_toolkit/compression/__init__.py`

**Interfaces:**
- Produces: `BlzFooter(compressed_length: int, header_length: int, added_length: int)`.
- Produces: `parse_blz_footer(data: Buffer) -> BlzFooter`.
- Produces: `is_blz(data: Buffer) -> bool`.
- Produces: `decompress_blz(data: Buffer) -> bytes`.
- Produces: `decompress_blz_in_place(data: Buffer) -> bytes`.
- Produces: `compress_blz(data: Buffer, *, passthrough_length: int = 0, target_size: int | None = None) -> bytes`.

- [ ] **Step 1: Port the complete existing BLZ test module**

Retain footer validation, padding validation, decompression behavior, in-place overwrite-safety behavior, target-size/passthrough validation, deterministic compression, and round-trip assertions.

- [ ] **Step 2: Verify failure**

Run `pytest tests/unit/test_blz.py -v`.
Expected: import failure.

- [ ] **Step 3: Migrate the existing BLZ implementation with namespace-only changes**

Keep `_encode_blz_suffix` and its lazy matching behavior intact. Do not substitute a new compressor during the repository split.

- [ ] **Step 4: Verify pass**

Run `pytest tests/unit/test_blz.py -v`.
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/compression tests/unit/test_blz.py
git commit -m "feat: migrate BLZ compression support"
```

---

### Task 8: Export the Phase 1 public API and document provenance

**Files:**
- Modify: `src/nds_disassembly_toolkit/nds/__init__.py`
- Modify: `src/nds_disassembly_toolkit/compression/__init__.py`
- Modify: `README.md`

**Interfaces:**
- `nds_disassembly_toolkit.nds` re-exports the principal header/FAT/FNT/overlay models and parsers.
- `nds_disassembly_toolkit.compression` re-exports LZ10 and BLZ public functions.

- [ ] **Step 1: Add explicit exports**

Expose only public models/functions used by consumers; keep private helpers such as `_DirectoryRecord` and `_encode_blz_suffix` private.

- [ ] **Step 2: Document Phase 1 scope**

README must state that the initial core was migrated/refactored from the project's previously proven Bakugan NDS tooling and that Bakugan-specific systems remain outside this repository. Add the legal boundary prohibiting ROM/assets from the repository.

- [ ] **Step 3: Run import smoke tests**

```bash
python - <<'PY'
from nds_disassembly_toolkit.nds import NdsHeader, parse_fat, parse_fnt, parse_arm9_overlays
from nds_disassembly_toolkit.compression import compress_lz10, decompress_lz10, compress_blz, decompress_blz
print(NdsHeader.__name__)
PY
```

Expected: exits 0 and prints `NdsHeader`.

- [ ] **Step 4: Commit**

```bash
git add src/nds_disassembly_toolkit/nds/__init__.py src/nds_disassembly_toolkit/compression/__init__.py README.md
git commit -m "docs: expose and document phase 1 core"
```

---

### Task 9: Verify Phase 1 independently of Bakugan

**Files:**
- Modify only if verification exposes a real defect in migrated code/tests.

**Interfaces:**
- Validates the complete Phase 1 package as an independent project.

- [ ] **Step 1: Run the complete test suite**

```bash
python -m pytest -v
```

Expected: all Phase 1 tests pass without importing `bakugan_ds`.

- [ ] **Step 2: Prove there are no Bakugan imports or identities in runtime code**

```bash
rg -n "bakugan_ds|BAKUGAN W|B6RE|Gate Card|G-Power" src tests
```

Expected: no runtime-code matches. A README migration/provenance sentence may mention Bakugan; synthetic unit fixtures must not use `BAKUGAN W` or `B6RE`.

- [ ] **Step 3: Run static checks**

```bash
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: both exit 0.

- [ ] **Step 4: Record migration status**

Update the architecture spec status from `Approved architecture, pending implementation plan` to `Approved architecture, Phase 1 implementation in progress/completed` as appropriate after verification.

- [ ] **Step 5: Commit verification-only fixes/status changes if any**

```bash
git add -A
git commit -m "test: verify standalone NDS low-level core"
```

## Phase 1 Completion Gate

Phase 1 is complete only when all of the following are true:

- the standalone project installs under Python 3.11+;
- header/FAT/FNT/overlay modules import only standalone generic modules;
- LZ10 and BLZ tests pass under the new namespace;
- neutral synthetic fixtures replace Bakugan identity in toolkit unit tests;
- ruff and strict mypy pass;
- no `bakugan_ds` imports remain anywhere under `src/`;
- no Bakugan gameplay/profile code has been migrated;
- the old Bakugan copies have not yet been deleted.

The next plan after this gate is Phase 2: generic inspection, workspace extraction/manifests, and deterministic rebuild.