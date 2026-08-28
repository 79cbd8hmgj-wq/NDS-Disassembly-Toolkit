# Phase 7G Persistent-Project CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic `nds-toolkit project` command family for creating, querying, inspecting, and annotating Phase 7F `.ndsre` projects without adding new analysis semantics.

**Architecture:** `src/nds_disassembly_toolkit/analysis/project_cli.py` owns parser construction, public-model JSON serialization, atomic JSON output, project open modes, and subcommand dispatch. `src/nds_disassembly_toolkit/cli.py` only registers and dispatches the new top-level command. Query commands consume public `AnalysisProject` APIs read-only; `annotate` uses the existing writable annotation API.

**Tech Stack:** Python 3.11+, argparse, dataclasses/enum-based toolkit analysis models, pathlib, json, Phase 7F `AnalysisProject`; no new dependency.

**Spec:** `docs/superpowers/specs/2026-08-28-phase-7g-project-cli-design.md`

## Global Constraints

- Keep `nds-toolkit analyze` unchanged as the one-shot flat-component scanner.
- Add top-level `nds-toolkit project <subcommand>`; do not nest persistence beneath `analyze`.
- Query commands must call `AnalysisProject.open(path, read_only=True)`.
- Only `project annotate` may open an existing project writable; `project create` uses `AnalysisProject.create()`.
- Do not import `sqlite3`, `analysis.project.schema`, `analysis.project.codec`, `cfg_records`, `flow_records`, or Capstone in Phase 7G CLI code.
- Do not add new analysis inference, project-schema changes, ROM/component byte persistence, arbitrary SQL, a REPL/TUI, emulator integration, or game-specific policy.
- Runtime addresses and memory offsets use canonical hexadecimal strings in JSON.
- All `StrEnum` values serialize to their `.value` strings. `OperandAccess` is the one non-string enum/flag and serializes symbolically as `[]`, `["read"]`, `["write"]`, or `["read", "write"]`.
- Output JSON is `indent=2`, `sort_keys=True`, terminated by one newline.
- `--output` uses sibling `<suffix>.tmp` write then `Path.replace()` so a completed document replaces the destination atomically.
- `pyproject.toml` must remain unchanged unless a real dependency blocker is found; that is a stop/review condition.
- Preserve the existing top-level exit mapping: argparse/`ValueError` -> 2, `NdsToolkitError`/`AnalysisProjectError` -> 4, `OSError` -> 5.
- Follow RED -> GREEN TDD per task and use PR-triggered exact-head CI before moving between major slices.

## File Structure

- Create `src/nds_disassembly_toolkit/analysis/project_cli.py`
  - `add_project_parser(subparsers: Any) -> None`
  - `run_project_command(arguments: argparse.Namespace) -> int`
  - address/mode parsers
  - explicit public-model JSON serializers
  - atomic JSON writer
  - subcommand handlers
- Modify `src/nds_disassembly_toolkit/cli.py`
  - import/register `add_project_parser`
  - dispatch `arguments.command == "project"` to `run_project_command`
- Create `tests/unit/test_analysis_project_cli.py`
  - parser, serializer, lifecycle/query, and annotation unit contracts
- Create `tests/unit/test_cli_analysis_project.py`
  - top-level dispatch and exit-code integration
- Modify `docs/disassembly-and-analysis.md`
  - Phase 7G usage and boundaries
- Modify `docs/provenance-and-licenses.md`
  - Phase 7G toolkit-owned CLI serialization/no-dependency boundary

---

### Task 1: CLI shell, parsers, scalar serialization, and atomic output

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/project_cli.py`
- Modify: `src/nds_disassembly_toolkit/cli.py`
- Create: `tests/unit/test_analysis_project_cli.py`
- Create: `tests/unit/test_cli_analysis_project.py`

**Interfaces:**
- Consumes: existing `AnalysisProject`, `AnalysisProjectError`, `InstructionSet`.
- Produces:
  - `add_project_parser(subparsers: Any) -> None`
  - `run_project_command(arguments: argparse.Namespace) -> int`
  - `_auto_int(value: str) -> int`
  - `_instruction_set(value: str) -> InstructionSet`
  - `_hex(value: int) -> str`
  - `_signed_hex(value: int) -> str`
  - `_operand_access_json(access: OperandAccess) -> list[str]`
  - `_write_json(payload: object, output: Path | None) -> None`

- [ ] **Step 1: Add RED parser/dispatch tests**

Add tests that prove the top-level parser knows `project`, a missing project subcommand is rejected by the project dispatcher, decimal/hex addresses parse, malformed addresses fail, and mode accepts only `arm`/`thumb`.

```python
from argparse import Namespace
from pathlib import Path

import pytest

from nds_disassembly_toolkit.cli import build_parser, main
from nds_disassembly_toolkit.analysis.model import InstructionSet, OperandAccess
from nds_disassembly_toolkit.analysis.project_cli import (
    _auto_int,
    _hex,
    _instruction_set,
    _operand_access_json,
    _signed_hex,
)


def test_top_level_parser_registers_project() -> None:
    args = build_parser().parse_args(["project", "info", "sample.ndsre"])
    assert args.command == "project"
    assert args.project_command == "info"
    assert args.project == Path("sample.ndsre")


def test_project_without_subcommand_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["project"]) == 2
    assert "project" in capsys.readouterr().err


def test_project_scalar_parsers_are_re_friendly() -> None:
    assert _auto_int("33554432") == 0x02000000
    assert _auto_int("0x02000000") == 0x02000000
    assert _instruction_set("arm") is InstructionSet.ARM
    assert _instruction_set("thumb") is InstructionSet.THUMB
    assert _hex(0x2012340) == "0x02012340"
    assert _signed_hex(-12) == "-0x0000000c"
    assert _signed_hex(12) == "0x0000000c"
    assert _operand_access_json(OperandAccess.NONE) == []
    assert _operand_access_json(OperandAccess.READ | OperandAccess.WRITE) == [
        "read",
        "write",
    ]
```

Also assert malformed integer and mode inputs raise `argparse.ArgumentTypeError`.

- [ ] **Step 2: Run RED tests**

Run:

```bash
python -m pytest tests/unit/test_analysis_project_cli.py tests/unit/test_cli_analysis_project.py -v
```

Expected: collection/import failures because `analysis.project_cli` does not exist.

- [ ] **Step 3: Implement the parser shell**

Create `analysis/project_cli.py` with:

```python
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from nds_disassembly_toolkit.analysis.model import InstructionSet, OperandAccess
from nds_disassembly_toolkit.errors import AnalysisProjectError


def _auto_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer/address: {value}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError(f"address must be non-negative: {value}")
    return parsed


def _instruction_set(value: str) -> InstructionSet:
    try:
        return InstructionSet(value.lower())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("instruction set must be 'arm' or 'thumb'") from exc


def _hex(value: int) -> str:
    if value < 0:
        raise ValueError("unsigned hexadecimal value cannot be negative")
    return f"0x{value:08x}"


def _signed_hex(value: int) -> str:
    prefix = "-" if value < 0 else ""
    return f"{prefix}0x{abs(value):08x}"


def _operand_access_json(access: OperandAccess) -> list[str]:
    result: list[str] = []
    if access & OperandAccess.READ:
        result.append("read")
    if access & OperandAccess.WRITE:
        result.append("write")
    return result
```

Add `project` subparsers for the complete command names from the spec immediately so help/dispatch shape is stable, even though later handlers initially raise `AnalysisProjectError("project command is not implemented")`.

Every subcommand has positional `project: Path` except `create`, whose destination is also stored as `project`. Every subcommand accepts `--output Path`.

- [ ] **Step 4: Implement atomic output**

Add:

```python
def _write_json(payload: object, output: Path | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(output)
```

Add tests that stdout bytes are deterministic and `--output` leaves no `.tmp` file after success.

- [ ] **Step 5: Wire top-level CLI dispatch**

Modify `cli.py`:

```python
from nds_disassembly_toolkit.analysis.project_cli import (
    add_project_parser,
    run_project_command,
)
```

In `build_parser()` call `add_project_parser(subparsers)` after `add_analysis_parser(subparsers)`.

In `main()` add before ROM command handling:

```python
if arguments.command == "project":
    return run_project_command(arguments)
```

`run_project_command()` must emit project parser usage to stderr and return 2 if `arguments.project_command is None`.

- [ ] **Step 6: Verify Task 1 GREEN**

Run:

```bash
python -m pytest tests/unit/test_analysis_project_cli.py tests/unit/test_cli_analysis_project.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project_cli.py src/nds_disassembly_toolkit/cli.py tests/unit/test_analysis_project_cli.py tests/unit/test_cli_analysis_project.py
python -m mypy src/nds_disassembly_toolkit/analysis/project_cli.py src/nds_disassembly_toolkit/cli.py
```

Expected: focused tests pass, Ruff clean, mypy clean.

- [ ] **Step 7: Commit Task 1**

```bash
git add src/nds_disassembly_toolkit/analysis/project_cli.py src/nds_disassembly_toolkit/cli.py tests/unit/test_analysis_project_cli.py tests/unit/test_cli_analysis_project.py
git commit -m "feat: add analysis project CLI shell"
```

---

### Task 2: Project lifecycle, metadata, function list, and string queries

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project_cli.py`
- Modify: `tests/unit/test_analysis_project_cli.py`
- Modify: `tests/unit/test_cli_analysis_project.py`

**Interfaces:**
- Consumes:
  - `AnalysisProject.create(path: Path) -> AnalysisProject`
  - `AnalysisProject.open(path: Path, *, read_only: bool = False) -> AnalysisProject`
  - `.metadata`, `.root`, `.component_identities()`, `.functions(component=...)`, `.strings(component=...)`
- Produces:
  - `_metadata_json(metadata: AnalysisProjectMetadata) -> dict[str, object]`
  - `_component_identity_json(identity: ComponentAnalysisIdentity) -> dict[str, object]`
  - `_function_candidate_json(function: FunctionCandidate) -> dict[str, object]`
  - `_string_json(record: StringRecord) -> dict[str, object]`
  - command handlers `_run_create`, `_run_info`, `_run_functions`, `_run_strings`

- [ ] **Step 1: Add RED lifecycle/query tests**

Create an empty project and test exact payloads:

```python
def test_project_create_and_info_are_deterministic(tmp_path: Path, capsys) -> None:
    project_path = tmp_path / "sample.ndsre"
    assert main(["project", "create", str(project_path)]) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["project"] == str(project_path)
    assert created["metadata"]["project_format_version"] == 1

    assert main(["project", "info", str(project_path)]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["metadata"]["read_only"] is True
    assert info["components"] == []
```

Use a helper fixture that stores a `ComponentAnalysisBundle` with two functions and two strings. Assert `functions --component` filters and `strings --contains BATTLE` matches `"battle manager"` case-insensitively without reordering.

Add a test that monkeypatches `AnalysisProject.open` or wraps it to prove query handlers pass `read_only=True`.

- [ ] **Step 2: Run RED tests**

Run the four new tests directly. Expected: failures from unimplemented handlers/serializers.

- [ ] **Step 3: Implement metadata/component/function/string serializers**

Use these payload shapes:

```python
def _metadata_json(metadata: AnalysisProjectMetadata) -> dict[str, object]:
    return {
        "analysis_model_version": metadata.analysis_model_version,
        "project_format_version": metadata.project_format_version,
        "read_only": metadata.read_only,
        "schema_version": metadata.schema_version,
    }


def _component_identity_json(identity: ComponentAnalysisIdentity) -> dict[str, object]:
    return {
        "base_address": _hex(identity.base_address),
        "name": identity.name,
        "sha256": identity.sha256,
        "size": _hex(identity.size),
    }


def _function_candidate_json(function: FunctionCandidate) -> dict[str, object]:
    return {
        "address": _hex(function.address),
        "component": function.component,
        "confidence": function.confidence,
        "evidence": list(function.evidence),
        "instruction_set": function.instruction_set.value,
        "offset": _hex(function.offset),
    }


def _string_json(record: StringRecord) -> dict[str, object]:
    return {
        "address": _hex(record.address),
        "component": record.component,
        "offset": _hex(record.offset),
        "text": record.text,
    }
```

- [ ] **Step 4: Implement lifecycle/query handlers**

`create`:

```python
with AnalysisProject.create(arguments.project) as project:
    payload = {
        "components": [],
        "metadata": _metadata_json(project.metadata),
        "project": str(project.root),
    }
_write_json(payload, arguments.output)
```

`info` opens read-only and uses `project.component_identities()`.

`functions` returns a JSON object with `"functions": [...]` and optional filter echoed as `"component"` only when supplied.

`strings` obtains `project.strings(component=...)`; when `contains` is not `None`, filter with `contains.casefold() in record.text.casefold()`.

- [ ] **Step 5: Verify Task 2 GREEN**

Run focused tests plus Task 1 tests, Ruff, mypy. Expected all green.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/nds_disassembly_toolkit/analysis/project_cli.py tests/unit/test_analysis_project_cli.py tests/unit/test_cli_analysis_project.py
git commit -m "feat: query project metadata functions and strings"
```

---

### Task 3: Deep public-model JSON serialization and function/symbol/xref queries

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project_cli.py`
- Modify: `tests/unit/test_analysis_project_cli.py`

**Interfaces:**
- Consumes public analysis models only:
  - `FunctionControlFlowGraph`
  - `DecodedInstruction`, `InstructionSemantics`, `InstructionOperand`, `MemoryOperand`, `OperandShift`
  - `FunctionDataFlow`, `InstructionFlowState`, `BlockFlowState`
  - `AbstractValue`, `RegisterState`, `StackState`
  - `FunctionSummary`, `ArgumentEvidence`, `ReturnEvidence`, `StackFrame`, `StackSlot`, `StackAccess`
  - `Symbol`, `CrossReference`, `LocationAnnotation`
- Produces explicit serializers plus handlers `_run_function`, `_run_symbols`, `_run_xrefs_from`, `_run_xrefs_to`.

- [ ] **Step 1: Add RED deep serialization tests**

Build/store a minimal bundle containing:

- ARM function at `0x02000000`;
- Thumb function at the same numeric address in a different component fixture where needed;
- CFG with one decoded instruction whose semantics include register, immediate, memory, and register-list operands across the fixture set;
- data flow with known constant/address/unknown values, stack before/after, warnings, argument evidence, return evidence, frame and slots;
- generated symbols and xrefs;
- a user annotation at the function entry.

Assert `project function ... arm` returns nested `function`, `cfg`, `data_flow`, and `annotation` objects; exact Thumb/ARM identity is respected; a missing exact function returns top-level exit 4 and stderr contains a stable `analysis function not found` message.

Add overlapping-overlay symbol tests proving `--address` without `--component` is rejected by parser/input validation and with a component returns only that component.

- [ ] **Step 2: Run RED tests**

Expected: unimplemented deep serializers/handlers fail.

- [ ] **Step 3: Implement instruction/CFG serializers**

Required payload shape for instructions:

```python
{
    "address": _hex(instruction.address),
    "conditional": instruction.conditional,
    "control_flow": instruction.control_flow.value,
    "data": instruction.data.hex(),
    "direct_target": None if instruction.direct_target is None else _hex(instruction.direct_target),
    "instruction_set": instruction.instruction_set.value,
    "mnemonic": instruction.mnemonic,
    "operands": instruction.operands,
    "semantics": _instruction_semantics_json(instruction.semantics),
    "size": instruction.size,
    "target_instruction_set": None if instruction.target_instruction_set is None else instruction.target_instruction_set.value,
}
```

Operand payload contains:

- `kind` string;
- symbolic `access` list from `_operand_access_json`;
- register/register-list string names;
- immediate as signed/unsigned hex string using `_signed_hex` for negative values and `_hex` otherwise;
- memory object `{base,index,scale,displacement,subtract_index}` with register strings/`None`, integer scale, signed displacement hex;
- shift object `{kind,value}`;
- `access_width` integer or `None`.

CFG payload contains serialized function, blocks, edges, unresolved transfers, and decode-failure addresses. Preserve tuple order exactly.

- [ ] **Step 4: Implement flow/summary serializers**

Abstract value:

```python
{
    "component": value.component,
    "kind": value.kind.value,
    "provenance": [_hex(address) for address in value.provenance],
    "value": None if value.value is None else _hex(value.value),
}
```

Register state is a list of `{register, value}` entries preserving model order. Stack state is `None` or `{offset, frame_pointers}` where offsets use `_signed_hex`.

Instruction flow includes serialized instruction plus before/after register states and stack before/after. Block flow includes address/mode, entry/exit register states, and stack entry/exit.

Summary payload contains:

```text
arguments
returns
stack_frame
stack_slots
```

Argument uses and return addresses are hex strings. Stack offsets use signed hex. Frame size uses unsigned hex or `None`. Stack access widths remain integer byte counts.

- [ ] **Step 5: Implement symbol/xref/annotation serializers**

Symbol:

```python
{
    "address": _hex(symbol.address),
    "component": symbol.component,
    "confidence": symbol.confidence,
    "evidence": list(symbol.evidence),
    "instruction_set": None if symbol.instruction_set is None else symbol.instruction_set.value,
    "kind": symbol.kind.value,
    "name": symbol.name,
    "offset": _hex(symbol.offset),
}
```

Xref source/target addresses are hex, optional source function is hex/`None`, enum modes/kind are strings, and no target component field is invented.

Annotation payload is `{component,address,name_override,comment,tags,bookmarked}` with address hex.

- [ ] **Step 6: Implement deep query handlers**

`function`:

```python
with AnalysisProject.open(arguments.project, read_only=True) as project:
    function = project.function(...)
    if function is None:
        raise AnalysisProjectError(
            f"analysis function not found: {arguments.component} "
            f"{_hex(arguments.address)} {arguments.instruction_set.value}"
        )
    payload = {
        "annotation": _annotation_json(project.annotation(...)),
        "cfg": _cfg_json(project.cfg(...)),
        "data_flow": _data_flow_json(project.data_flow(...)),
        "function": _function_candidate_json(function),
    }
```

Serializer helpers accept `None` where the project API may return no CFG/flow/annotation and return JSON `null`.

`symbols`:

- name mode -> `project.symbols_named(name, component=...)`;
- address mode -> require component before project open, then `project.symbols_at(component, address)`.

`xrefs-from` -> `project.xrefs_from(component,address)`.

`xrefs-to` -> `project.xrefs_to(address, source_component=...)`.

- [ ] **Step 7: Verify Task 3 GREEN**

Run all project CLI tests, Ruff, strict mypy. Also run existing Phase 7F project tests to ensure no persistence regression:

```bash
python -m pytest tests/unit/test_analysis_project_*.py tests/unit/test_cli_analysis_project.py -v
```

Expected all pass.

- [ ] **Step 8: Commit Task 3**

```bash
git add src/nds_disassembly_toolkit/analysis/project_cli.py tests/unit/test_analysis_project_cli.py
git commit -m "feat: inspect persisted analysis project records"
```

---

### Task 4: Patch-style annotation mutation

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project_cli.py`
- Modify: `tests/unit/test_analysis_project_cli.py`
- Modify: `tests/unit/test_cli_analysis_project.py`

**Interfaces:**
- Consumes:
  - `AnalysisProject.annotation(component,address)`
  - `AnalysisProject.set_annotation(annotation)`
  - `LocationAnnotation`
- Produces `_run_annotations` and `_run_annotate`.

- [ ] **Step 1: Add RED annotation parser tests**

Assert argparse rejects each mutually exclusive pair:

```text
--name / --clear-name
--comment / --clear-comment
--tag / --clear-tags
--bookmark / --unbookmark
```

Assert `project annotate PROJECT arm9 0x02000000` with no mutation flags reaches the dispatcher and returns status 2 with `at least one annotation field must be changed`.

- [ ] **Step 2: Add RED mutation semantics tests**

Store an initial annotation:

```python
LocationAnnotation(
    component="arm9",
    address=0x02000000,
    name_override="OldName",
    comment="keep me",
    tags=("alpha", "beta"),
    bookmarked=True,
)
```

Run only `--name NewName` and assert comment/tags/bookmark are preserved after reopen.

Then separately test:

- `--clear-name` -> `None`;
- `--clear-comment` -> `None`;
- `--clear-tags` -> `()`;
- `--unbookmark` -> `False`;
- repeated `--tag beta --tag alpha --tag beta` -> normalized `("alpha","beta")`;
- new annotation with only `--bookmark` gets other defaults;
- unknown component returns exit 4 through `AnalysisProjectError`.

- [ ] **Step 3: Implement annotation parser flags**

Use mutually exclusive argparse groups and `default=None` for tri-state bookmark handling:

```python
bookmark_group = annotate_parser.add_mutually_exclusive_group()
bookmark_group.add_argument("--bookmark", dest="bookmark", action="store_const", const=True)
bookmark_group.add_argument("--unbookmark", dest="bookmark", action="store_const", const=False)
annotate_parser.set_defaults(bookmark=None)
```

Use analogous clear booleans for name/comment/tags.

- [ ] **Step 4: Implement `_run_annotations`**

Open read-only, call `project.annotations(component=arguments.component)`, serialize each annotation, and write JSON.

- [ ] **Step 5: Implement patch-style `_run_annotate`**

Compute whether any mutation is requested before opening writable. If none, raise `ValueError("at least one annotation field must be changed")`.

Then:

```python
with AnalysisProject.open(arguments.project, read_only=False) as project:
    current = project.annotation(arguments.component, arguments.address)
    if current is None:
        current = LocationAnnotation(arguments.component, arguments.address)

    if arguments.clear_name:
        name_override = None
    elif arguments.name is not None:
        name_override = arguments.name
    else:
        name_override = current.name_override

    # Same pattern for comment and tags.
    bookmarked = current.bookmarked if arguments.bookmark is None else arguments.bookmark

    updated = LocationAnnotation(
        component=arguments.component,
        address=arguments.address,
        name_override=name_override,
        comment=comment,
        tags=tags,
        bookmarked=bookmarked,
    )
    project.set_annotation(updated)
```

Write the serialized updated annotation only after `set_annotation()` returns successfully.

- [ ] **Step 6: Verify Task 4 GREEN**

Run project CLI tests plus Phase 7F component/transaction tests to verify annotation durability remains intact. Run Ruff and mypy.

- [ ] **Step 7: Commit Task 4**

```bash
git add src/nds_disassembly_toolkit/analysis/project_cli.py tests/unit/test_analysis_project_cli.py tests/unit/test_cli_analysis_project.py
git commit -m "feat: edit persistent analysis annotations"
```

---

### Task 5: Documentation, provenance, complete gates, PR audit, and merge

**Files:**
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`
- Modify: tests only if a final contract gap is discovered

**Interfaces:**
- Consumes completed Phase 7G CLI.
- Produces documented user contract and verified merge.

- [ ] **Step 1: Add final top-level integration tests**

Ensure `main()` maps:

- missing function `AnalysisProjectError` -> exit 4;
- malformed project -> exit 4;
- no-op annotation `ValueError` -> exit 2;
- output filesystem `OSError` -> exit 5 where injectable without platform-specific assumptions.

Also assert existing `analyze` parsing remains unchanged.

- [ ] **Step 2: Run focused final RED/GREEN check**

If any added tests expose a gap, verify RED for the intended reason, make only the minimal production correction, then rerun focused tests to GREEN.

- [ ] **Step 3: Document Phase 7G**

Add a `Phase 7G persistent-project CLI` section to `docs/disassembly-and-analysis.md` with exact examples:

```bash
nds-toolkit project create game.ndsre
nds-toolkit project info game.ndsre
nds-toolkit project functions game.ndsre --component arm9
nds-toolkit project function game.ndsre arm9 0x02012340 arm
nds-toolkit project strings game.ndsre --contains battle
nds-toolkit project symbols game.ndsre --address 0x02012340 --component arm9
nds-toolkit project xrefs-to game.ndsre 0x02012340
nds-toolkit project annotate game.ndsre arm9 0x02012340 --name BattleManager --bookmark
```

State explicitly:

- queries are read-only;
- JSON is deterministic and can be redirected with `--output`;
- address lookups remain component-aware for overlays;
- annotations are durable user facts separate from generated symbols;
- no ROM bytes or new inference are added;
- REPL/TUI remains deferred; Phase 7H is emulator/trace integration.

- [ ] **Step 4: Update provenance**

Record that Phase 7G:

- is toolkit-owned argparse/JSON presentation code;
- consumes only public Phase 7F toolkit models/APIs;
- does not import/copy angr persistence/UI machinery;
- does not embed melonDS or ROM payloads;
- does not move Capstone outside the decoder-owned typed-model boundary;
- adds no third-party dependency.

- [ ] **Step 5: Run complete verification**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: zero pytest failures, Ruff clean, strict mypy clean.

- [ ] **Step 6: Run scope audit**

Compare branch to exact Phase 7F base `b4d4bc9d860cc090b69247243e02138027b44f97` and confirm changed files are limited to Phase 7G spec/plan, CLI source, CLI tests, docs/provenance, and any directly required shared CLI import/dispatch surface.

Confirm:

- `pyproject.toml` unchanged;
- no `Bakugan`, `B6RE`, game addresses, game hashes, or game policies;
- no project schema/persistence implementation changes unless explicitly justified by a failing stable-API contract;
- no ROM/workspace/patching behavior changes;
- no Capstone imports in `project_cli.py`.

- [ ] **Step 7: Commit final docs/gate fixes**

```bash
git add docs/disassembly-and-analysis.md docs/provenance-and-licenses.md tests/unit/test_analysis_project_cli.py tests/unit/test_cli_analysis_project.py src/nds_disassembly_toolkit/analysis/project_cli.py src/nds_disassembly_toolkit/cli.py
git commit -m "docs: publish Phase 7G project CLI"
```

Skip the commit if there are no uncommitted changes after the documentation commit; do not create an empty commit.

- [ ] **Step 8: Open/update draft PR and exact-head CI**

Open `phase-7g-project-cli -> main` as draft with title:

```text
Phase 7G: persistent project CLI
```

Record exact head SHA. Require PR-triggered full pytest/Ruff/strict-mypy success on that exact head.

- [ ] **Step 9: Final diff/requirements review**

Re-read this plan's Completion Criteria and the design spec. Audit the complete PR file list/diff for every constraint. Fix Critical/Important review issues before merge. An unavailable optional external reviewer is not a blocker when exact-head CI and repository-side requirements review are complete.

- [ ] **Step 10: Mark ready and squash-merge with expected-head protection**

Only if PR remains mergeable and exact head is unchanged, mark ready and squash-merge with `expected_head_sha=<verified-head>`.

Suggested squash title:

```text
Phase 7G: persistent project CLI (#<PR>)
```

- [ ] **Step 11: Require post-merge `main` CI**

Find the push-triggered CI run whose `head_sha` is the squash commit and `head_branch` is `main`. Require Test, Ruff, and Mypy all successful. Read logs to confirm full test count and strict-mypy source count before declaring Phase 7G complete.

## Completion Criteria

1. `nds-toolkit project` exposes `create`, `info`, `functions`, `function`, `strings`, `symbols`, `xrefs-from`, `xrefs-to`, `annotations`, and `annotate`.
2. Existing `nds-toolkit analyze` behavior is unchanged.
3. Every read command opens `.ndsre` with `read_only=True`; only annotation mutation opens writable.
4. Exact function identity includes component/address/instruction-set and overlapping overlays are never range-guessed.
5. Deep function JSON includes persisted CFG, typed semantics, data-flow, stack/ABI summary, and entry annotation without Capstone/SQLite objects.
6. Symbol address lookup requires component; xref target lookup does not invent target-component ownership.
7. Strings support deterministic case-insensitive `--contains` filtering.
8. Annotation mutation is patch-style, preserves unspecified fields, supports explicit clears, and rejects no-op updates.
9. All successful commands emit deterministic JSON; optional `--output` uses atomic sibling replacement.
10. Address/offset/provenance output is canonical hex; `StrEnum` values are strings and `OperandAccess` is symbolic.
11. Existing CLI exit-code policy remains intact.
12. No new analysis semantics, project-schema changes, ROM byte persistence, third-party dependencies, or game-specific policy are added.
13. Documentation/provenance describe Phase 7G and its Phase 7H boundary.
14. Exact PR head passes full pytest, Ruff, strict mypy, and scope audit.
15. Squash commit on `main` passes the same post-merge CI gate before Phase 7G is declared complete.
