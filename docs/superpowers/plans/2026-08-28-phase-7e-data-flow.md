# Phase 7E Data-Flow Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add conservative typed ARM/Thumb instruction semantics, intraprocedural register/constant/address propagation, then stack-frame/argument/return recovery on the same fixed-point engine.

**Architecture:** `analysis/decoder.py` remains the only Capstone boundary and enriches existing `DecodedInstruction` records with toolkit-owned immutable semantic detail. A new `analysis/data_flow.py` consumes existing Phase 7B CFGs and performs one deterministic fixed-point analysis; Phase 7E2 extends that same state/transfer machinery with stack facts while `analysis/stack.py` derives frame/slot summaries from the existing flow result rather than rebuilding control flow or re-decoding instructions.

**Tech Stack:** Python 3.11, existing `capstone>=5,<7` runtime dependency, existing Phase 7A-7D analysis models/CFGs, pytest, Ruff, strict mypy.

**Spec:** `docs/superpowers/specs/2026-08-28-phase-7e-data-flow-design.md`

## Global Constraints

- Capstone remains confined to `analysis/decoder.py`; no Capstone object or numeric register ID enters public analysis models.
- `DecodedInstruction.operands` remains presentation text and is never parsed by data-flow or stack analysis.
- Reuse `FunctionControlFlowGraph`; do not re-decode instructions or construct another CFG.
- Register aliases normalize canonically: `sp == r13`, `lr == r14`, `pc == r15`.
- The 7E1 value lattice is exactly `UNKNOWN`, `CONSTANT`, `ADDRESS`.
- Numeric resemblance to a pointer never promotes `CONSTANT` to `ADDRESS`; an address role must be proven by instruction/memory-use semantics.
- Component ownership is never inferred by searching overlapping runtime ranges.
- Unsupported writes invalidate affected registers rather than preserving stale values or guessing semantics.
- Conditional writes merge the executed result with the incoming state.
- 7E1 is intraprocedural. Calls conservatively clobber `r0-r3`, `r12`, and `lr`; `r4-r11` and `sp` remain preserved unless the decoded instruction proves another write.
- Provenance is deterministic metadata. Semantic fixed-point equality ignores provenance; provenance is enriched only after semantic values stabilize, so evidence cannot create non-converging value states.
- 7E2 extends the same data-flow engine; it may not introduce a second instruction/CFG traversal engine with independent state semantics.
- No Bakugan-specific addresses, symbols, policies, ABI exceptions, or gameplay knowledge.
- No new runtime dependency. angr remains reference-only; melonDS remains outside the static-analysis implementation.

## File Map

- Modify `src/nds_disassembly_toolkit/analysis/model.py`: immutable semantic, value, flow-result, and later stack/function-summary records.
- Modify `src/nds_disassembly_toolkit/analysis/decoder.py`: Capstone-to-toolkit semantic adapter only.
- Create `src/nds_disassembly_toolkit/analysis/data_flow.py`: value/state helpers, transfer functions, deterministic CFG fixed point, literal reads, call barrier, and later entry-argument liveness.
- Create `src/nds_disassembly_toolkit/analysis/stack.py`: Phase 7E2 frame/slot derivation from `FunctionDataFlow`; it never decodes bytes or constructs CFG edges.
- Modify `src/nds_disassembly_toolkit/analysis/__init__.py`: stable public exports.
- Modify `tests/unit/test_analysis_decoder.py`: typed semantic decoder contract.
- Create `tests/unit/test_analysis_data_flow.py`: 7E1 value/CFG/validation contract.
- Create `tests/unit/test_analysis_stack.py`: 7E2 stack/argument/return contract.
- Modify `docs/disassembly-and-analysis.md`: Phase 7E user-facing behavior and precision boundaries.
- Modify `docs/provenance-and-licenses.md`: dependency/reference boundary.

---

## Phase 7E1 PR

### Task 1: Toolkit-Owned Instruction Semantic Models

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Modify: `tests/unit/test_analysis_decoder.py`

**Interfaces:**
- Produces `Register(StrEnum)` with string values `r0` through `r15` and aliases `SP = R13`, `LR = R14`, `PC = R15`.
- Produces `ConditionCode(StrEnum)` with `INVALID`, `EQ`, `NE`, `HS`, alias `CS = HS`, `LO`, alias `CC = LO`, `MI`, `PL`, `VS`, `VC`, `HI`, `LS`, `GE`, `LT`, `GT`, `LE`, `AL`.
- Produces `OperandKind(StrEnum)`: `REGISTER`, `IMMEDIATE`, `MEMORY`, `REGISTER_LIST`.
- Produces `OperandAccess(IntFlag)`: `NONE = 0`, `READ = 1`, `WRITE = 2`.
- Produces `ShiftKind(StrEnum)`: `NONE`, `LSL`, `LSR`, `ASR`, `ROR`, `RRX`.
- Produces immutable `OperandShift(kind: ShiftKind = ShiftKind.NONE, value: int = 0)`.
- Produces immutable `MemoryOperand(base: Register | None, index: Register | None, scale: int, displacement: int, subtract_index: bool = False)`.
- Produces immutable `InstructionOperand(kind: OperandKind, access: OperandAccess, register: Register | None = None, registers: tuple[Register, ...] = (), immediate: int | None = None, memory: MemoryOperand | None = None, shift: OperandShift = OperandShift(), access_width: int | None = None)`.
- Produces immutable `InstructionSemantics(operands: tuple[InstructionOperand, ...] = (), registers_read: tuple[Register, ...] = (), registers_written: tuple[Register, ...] = (), condition: ConditionCode = ConditionCode.AL, writeback: bool = False)`.
- Extends `DecodedInstruction` with `semantics: InstructionSemantics = field(default_factory=InstructionSemantics)` so Phase 7A-7D direct constructors remain source-compatible.

- [ ] **Step 1: Write failing model/compatibility tests**

```python
from nds_disassembly_toolkit.analysis.model import (
    ControlFlowKind,
    DecodedInstruction,
    InstructionSemantics,
    InstructionSet,
    Register,
)


def test_register_aliases_are_canonical() -> None:
    assert Register.SP is Register.R13
    assert Register.LR is Register.R14
    assert Register.PC is Register.R15


def test_decoded_instruction_semantics_default_is_compatible() -> None:
    decoded = DecodedInstruction(
        address=0x02000000,
        size=4,
        data=b"\x00\x00\xA0\xE1",
        mnemonic="mov",
        operands="r0, r0",
        instruction_set=InstructionSet.ARM,
        control_flow=ControlFlowKind.ORDINARY,
    )
    assert decoded.semantics == InstructionSemantics()
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_decoder.py tests/unit/test_analysis_cfg.py tests/unit/test_analysis_xrefs.py tests/unit/test_analysis_symbols.py -v
```

Expected: new assertions fail because semantic types/field do not exist; existing direct-construction tests define the compatibility surface.

- [ ] **Step 3: Implement the immutable semantic models**

Use this shape in `model.py`:

```python
from dataclasses import dataclass, field
from enum import IntFlag, StrEnum


class Register(StrEnum):
    R0 = "r0"
    R1 = "r1"
    R2 = "r2"
    R3 = "r3"
    R4 = "r4"
    R5 = "r5"
    R6 = "r6"
    R7 = "r7"
    R8 = "r8"
    R9 = "r9"
    R10 = "r10"
    R11 = "r11"
    R12 = "r12"
    R13 = "r13"
    SP = "r13"
    R14 = "r14"
    LR = "r14"
    R15 = "r15"
    PC = "r15"

    @classmethod
    def from_name(cls, name: str) -> Register | None:
        normalized = name.strip().lower()
        normalized = {"sp": "r13", "lr": "r14", "pc": "r15"}.get(
            normalized, normalized
        )
        try:
            return cls(normalized)
        except ValueError:
            return None
```

Add the remaining enums/dataclasses from the Interfaces block. In `InstructionOperand.__post_init__`, reject payloads inconsistent with `kind`; canonicalize register-list creation at callers rather than mutating the frozen object; require `access_width is None or access_width > 0`. Unknown non-GPR names are intentionally omitted.

- [ ] **Step 4: Verify GREEN**

Run the Step 2 suite. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/model.py tests/unit/test_analysis_decoder.py
git commit -m "feat: define typed instruction semantics"
```

### Task 2: Populate Typed Semantics in the Decoder

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/decoder.py`
- Modify: `tests/unit/test_analysis_decoder.py`

**Interfaces:**
- `decode_instruction(data: bytes, *, address: int, instruction_set: InstructionSet) -> DecodedInstruction | None` remains unchanged and fills `semantics`.
- Uses only Capstone public attributes already permitted by `capstone>=5,<7`: `operands`, `reg_name`, `regs_access()`, ARM operand `type/reg/imm/mem/access/shift/subtracted`, ARM `cc`, and generic `writeback`.
- For `push`/`pop`, normalize Capstone's ordered register members into one `REGISTER_LIST` operand.
- Decoder-normalized memory direction is typed: loads mark the memory operand `READ`; stores mark it `WRITE`. This is derived from mnemonic/instruction semantics inside the decoder, never from `op_str`.
- `access_width`: word `ldr/str` = 4, `ldrh/strh` = 2, `ldrb/strb` = 1; signed byte/halfword loads may be represented with width but value propagation is unsupported until Task 4 explicitly handles a form.

- [ ] **Step 1: Write failing ARM/Thumb semantic tests**

```python
def test_decode_arm_move_exposes_typed_register_effects() -> None:
    decoded = decode_instruction(
        struct.pack("<I", 0xE1A01000),  # mov r1, r0
        address=0x02000000,
        instruction_set=InstructionSet.ARM,
    )
    assert decoded is not None
    assert [op.kind for op in decoded.semantics.operands] == [
        OperandKind.REGISTER,
        OperandKind.REGISTER,
    ]
    assert decoded.semantics.operands[0].register is Register.R1
    assert decoded.semantics.operands[1].register is Register.R0
    assert Register.R0 in decoded.semantics.registers_read
    assert Register.R1 in decoded.semantics.registers_written


def test_decode_thumb_literal_load_exposes_memory_direction_and_width() -> None:
    decoded = decode_instruction(
        struct.pack("<H", 0x4800),  # ldr r0, [pc, #0]
        address=0x02000000,
        instruction_set=InstructionSet.THUMB,
    )
    assert decoded is not None
    operand = decoded.semantics.operands[1]
    assert operand.memory is not None
    assert operand.memory.base is Register.PC
    assert operand.memory.displacement == 0
    assert operand.access == OperandAccess.READ
    assert operand.access_width == 4
```

Also test ARM `movne -> ConditionCode.NE`; writeback load/store -> `writeback=True`; ARM/Thumb push -> one canonical `REGISTER_LIST`; store memory operand -> `OperandAccess.WRITE`.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_decoder.py -v
```

Expected: FAIL because decoded semantics are still empty.

- [ ] **Step 3: Implement the Capstone adapter**

Keep all Capstone-specific helpers private:

```python
def _gpr(instruction: _CapstoneInstruction, reg_id: int) -> Register | None:
    if reg_id == 0:
        return None
    return Register.from_name(str(instruction.reg_name(reg_id)))


def _stable_registers(
    instruction: _CapstoneInstruction, ids: Sequence[int]
) -> tuple[Register, ...]:
    registers = {_gpr(instruction, reg_id) for reg_id in ids}
    return tuple(sorted((r for r in registers if r is not None), key=lambda r: int(r.value[1:])))
```

Add `_condition_code`, `_shift`, `_memory`, `_access_width`, `_normalize_memory_access`, `_operand`, `_semantics`. Preserve Capstone operand order except `push/pop`, where converted register members become one sorted/deduplicated `REGISTER_LIST`. Populate `registers_read/registers_written` from `regs_access()`. Preserve shifts and writeback. Do not change existing control-flow/direct-target behavior.

- [ ] **Step 4: Verify GREEN/regressions**

```bash
python -m pytest tests/unit/test_analysis_decoder.py tests/unit/test_analysis_functions.py tests/unit/test_analysis_cfg.py tests/unit/test_analysis_xrefs.py tests/unit/test_analysis_symbols.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/decoder.py tests/unit/test_analysis_decoder.py
git commit -m "feat: expose ARM Thumb instruction semantics"
```

### Task 3: Abstract Values, Register State, and Straight-Line Data Flow

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Create: `tests/unit/test_analysis_data_flow.py`

**Interfaces:**
- `AbstractValueKind`: `UNKNOWN`, `CONSTANT`, `ADDRESS`.
- `AbstractValue(kind, value: int | None = None, component: str | None = None, provenance: tuple[int, ...] = field(default=(), compare=False))`.
- Sparse immutable `RegisterState(values=())` with `value(register) -> AbstractValue`; omitted registers are unknown.
- `InstructionFlowState(instruction: DecodedInstruction, before: RegisterState, after: RegisterState)` plus `address` property.
- `BlockFlowState(address, instruction_set, entry, exit)`.
- `FunctionDataFlow(function, blocks, instructions, warnings=())`; **7E1 has no summary field**. Phase 7E2 adds the optional `FunctionSummary` field only after that type exists.
- `FunctionDataFlow.at_instruction(address)` / `for_block(address)` return a deterministic match or `None`.
- Public `analyze_data_flow(cfg, component) -> FunctionDataFlow`; Task 3 handles one block, Task 4 generalizes the same implementation.

**Test helpers in `test_analysis_data_flow.py`:**

```python
BASE = 0x02000000


def _arm_words(*words: int) -> bytes:
    return b"".join(struct.pack("<I", word) for word in words)


def _function(
    *,
    component: str = "arm9",
    address: int = BASE,
    instruction_set: InstructionSet = InstructionSet.ARM,
) -> FunctionCandidate:
    return FunctionCandidate(
        component=component,
        address=address,
        offset=address - BASE,
        instruction_set=instruction_set,
        confidence="high",
        evidence=("test",),
    )


def _flow_from_arm(*words: int) -> FunctionDataFlow:
    component = Component("arm9", Path("arm9.bin"), BASE, _arm_words(*words))
    return analyze_data_flow(build_function_cfg(component, _function()), component)
```

- [ ] **Step 1: Write failing straight-line tests**

```python
def test_mov_and_add_propagate_exact_constants() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(DataOpcode.MOV, rd=ArmRegister.R0, immediate=4),
        encode_data_processing_immediate(
            DataOpcode.ADD, rd=ArmRegister.R1, rn=ArmRegister.R0, immediate=3
        ),
        encode_bx(ArmRegister.LR),
    )
    state = flow.at_instruction(BASE + 4)
    assert state is not None
    value = state.after.value(Register.R1)
    assert value.kind is AbstractValueKind.CONSTANT
    assert value.value == 7
    assert value.provenance == (BASE, BASE + 4)
```

Also test register `mov`, `sub`, unknown source -> unknown destination, unsupported `mul` clears a previously known destination, and a constant used as a typed memory base is reclassified as `ADDRESS(component=None)` after use without gaining component ownership.

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_data_flow.py -v
```

Expected: FAIL because data-flow models/module do not exist.

- [ ] **Step 3: Implement models/state primitives**

```python
_UNKNOWN = AbstractValue(AbstractValueKind.UNKNOWN)


def _semantic_key(value: AbstractValue) -> tuple[AbstractValueKind, int | None, str | None]:
    return value.kind, value.value, value.component


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF
```

`AbstractValue.__post_init__`: UNKNOWN has no value/component; CONSTANT has a u32 value and no component; ADDRESS has a u32 value and optional component. `RegisterState` sorts by canonical register number and omits unknown entries. State update returns a new frozen state.

- [ ] **Step 4: Implement validation + one-block `analyze_data_flow` + transfer**

```python
def _validate_cfg(cfg: FunctionControlFlowGraph, component: Component) -> None:
    if cfg.function.component != component.name:
        raise ValueError("data-flow function component does not match component")
    for block in cfg.blocks:
        if block.component != component.name:
            raise ValueError("data-flow block component does not match component")
        expected = component.offset_for_address(block.address)
        if block.offset != expected:
            raise ValueError("data-flow block offset does not match component")
```

Task 3 may raise `ValueError("multi-block data flow requires CFG fixed-point support")` for more than one block. Implement typed unshifted `mov/add/sub`: CONSTANT +/- CONSTANT -> CONSTANT; ADDRESS +/- CONSTANT -> ADDRESS preserving component; unsupported shapes -> UNKNOWN for known destinations. Wrap arithmetic to u32. Apply decoder-proven writes conservatively. If a typed memory operand uses a register currently containing CONSTANT, reclassify that register as ADDRESS with `component=None`; this is an abstract-role refinement, not a machine write.

- [ ] **Step 5: Verify GREEN**

```bash
python -m pytest tests/unit/test_analysis_data_flow.py tests/unit/test_analysis_decoder.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/model.py src/nds_disassembly_toolkit/analysis/data_flow.py tests/unit/test_analysis_data_flow.py
git commit -m "feat: propagate register constants and addresses"
```

### Task 4: General CFG Fixed Point, PC/Literals, Conditions, Calls, and Provenance

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Modify: `tests/unit/test_analysis_data_flow.py`

**Interfaces:**
- Extends Task 3 `analyze_data_flow` to arbitrary existing Phase 7B CFGs.
- Fixed-point key: `(block.address, block.instruction_set)`; public tuples sort by `(address, instruction_set.value)`.
- Intraprocedural predecessors: local `BRANCH`/`FALLTHROUGH` only; CALL effects stay in instruction transfer.
- Semantic state equality ignores provenance.
- After semantic convergence, a second deterministic finite provenance-enrichment pass runs on the stabilized graph.

**Additional test helpers:**

```python
def _manual_cfg(
    function: FunctionCandidate,
    blocks: tuple[BasicBlock, ...],
    edges: tuple[CFGEdge, ...],
) -> FunctionControlFlowGraph:
    return FunctionControlFlowGraph(
        function=function,
        blocks=blocks,
        edges=edges,
        unresolved_transfers=(),
        decode_failures=(),
    )


def _single_block_cfg(
    *, component: str = "arm9", block_offset: int = 0
) -> FunctionControlFlowGraph:
    function = _function(component=component)
    block = BasicBlock(
        component=component,
        address=BASE,
        offset=block_offset,
        instruction_set=InstructionSet.ARM,
        instructions=(),
    )
    return _manual_cfg(function, (block,), ())
```

- [ ] **Step 1: Write failing join/loop/validation tests**

Construct manual `DecodedInstruction` records with explicit `InstructionSemantics`; never parse operand text. Build a diamond where one predecessor assigns r1=2 and another r1=3; assert join entry r1 UNKNOWN. Repeat with both r1=2; assert CONSTANT 2. Add backward edge to a stable loop and assert repeat runs produce equal results.

```python
def test_data_flow_rejects_mismatched_cfg_component() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    with pytest.raises(ValueError, match="component"):
        analyze_data_flow(_single_block_cfg(component="overlay_1"), component)


def test_data_flow_rejects_inconsistent_block_offset() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    with pytest.raises(ValueError, match="offset"):
        analyze_data_flow(_single_block_cfg(block_offset=4), component)
```

- [ ] **Step 2: Write failing PC/literal/conditional/call tests**

```python
def test_arm_literal_pool_load_is_constant_not_guessed_address() -> None:
    data = bytearray(0x10)
    struct.pack_into("<I", data, 0, encode_literal_load(BASE, BASE + 8, ArmRegister.R0))
    struct.pack_into("<I", data, 4, encode_bx(ArmRegister.LR))
    struct.pack_into("<I", data, 8, BASE + 0x40)
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(data))
    flow = analyze_data_flow(build_function_cfg(component, _function()), component)
    state = flow.at_instruction(BASE)
    assert state is not None
    value = state.after.value(Register.R0)
    assert value.kind is AbstractValueKind.CONSTANT
    assert value.value == BASE + 0x40
    assert value.component is None
```

Also test ARM `add r0,pc,#imm -> ADDRESS(component="arm9")` using `PC=address+8`; Thumb PC-relative load uses aligned `(address+4)`; unsigned word/halfword/byte literal widths; signed literal load remains unsupported/unknown unless explicitly implemented; out-of-range literal gives one stable warning and UNKNOWN destination; conditional write joins old/new; direct BL clobbers r0-r3/r12/lr but preserves known r4; separately analyzed overlapping overlays never cross-assign component ownership.

- [ ] **Step 3: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_data_flow.py -v
```

Expected: new multi-block/PC/literal/call tests FAIL; Task 3 straight-line tests remain green.

- [ ] **Step 4: Implement deterministic semantic fixed point**

```python
def _join_values(values: Sequence[AbstractValue]) -> AbstractValue:
    if not values:
        return _UNKNOWN
    first = values[0]
    if all(_semantic_key(value) == _semantic_key(first) for value in values[1:]):
        return AbstractValue(first.kind, first.value, first.component)
    return _UNKNOWN
```

Remove Task 3 multi-block restriction. Build predecessor lists from local branch/fallthrough edges. Entry starts with empty unknown register state; non-entry blocks are unreachable until a predecessor exits. Worklist order is deterministic. Enqueue successors only when semantic exit state changes.

- [ ] **Step 5: Implement PC/literal/conditional/call transfer**

For an explicit PC register source, materialize ARM PC as `instruction.address + 8`. For Thumb PC-relative memory construction use `(instruction.address + 4) & ~3`. A PC-derived effective address is ADDRESS owned by the current component.

For unsigned literal loads with known PC effective address and typed width 1/2/4, read exactly that many in-component bytes little-endian and produce CONSTANT. Signed forms remain conservative UNKNOWN unless a dedicated signed transfer is added with a matching test. Out-of-range access adds a deterministic warning such as `literal read at 0x02000004 is outside arm9: 0x02000100` and clears destination.

At CALL, clear `{R0,R1,R2,R3,R12,LR}` after decoded writes. For condition other than AL/INVALID, compute executed state then join each written/refined register with incoming state to account for the instruction not executing.

- [ ] **Step 6: Implement bounded provenance enrichment**

After semantic states stabilize, rerun blocks using those fixed semantic entry values while provenance sets grow. At joins, union sorted provenance only when semantic keys agree. Instruction transfer appends the current instruction address to provenance for supported produced/copied values. Repeat until no provenance tuple grows; the universe is bounded by reachable instruction addresses, so this cannot change semantic fixed-point convergence.

- [ ] **Step 7: Verify GREEN/regressions**

```bash
python -m pytest tests/unit/test_analysis_data_flow.py -v
python -m pytest tests/unit/test_analysis_decoder.py tests/unit/test_analysis_functions.py tests/unit/test_analysis_cfg.py tests/unit/test_analysis_xrefs.py tests/unit/test_analysis_symbols.py -v
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/data_flow.py tests/unit/test_analysis_data_flow.py
git commit -m "feat: solve intraprocedural register data flow"
```

### Task 5: 7E1 Public API, Documentation, and Merge Gate

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `tests/unit/test_analysis_data_flow.py`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`

**Interfaces:** Export `Register`, `ConditionCode`, `OperandKind`, `OperandAccess`, `ShiftKind`, `OperandShift`, `MemoryOperand`, `InstructionOperand`, `InstructionSemantics`, `AbstractValueKind`, `AbstractValue`, `RegisterState`, `InstructionFlowState`, `BlockFlowState`, `FunctionDataFlow`, `analyze_data_flow`.

- [ ] **Step 1: Write failing export test**

```python
def test_data_flow_api_is_exported() -> None:
    assert analysis.Register is Register
    assert analysis.AbstractValue is AbstractValue
    assert analysis.FunctionDataFlow is FunctionDataFlow
    assert analysis.analyze_data_flow is analyze_data_flow
```

- [ ] **Step 2: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_data_flow.py::test_data_flow_api_is_exported -v
```

Expected: FAIL until exports are wired.

- [ ] **Step 3: Export API + document/provenance**

Add imports/`__all__` entries. Add Phase 7E1 docs with:

```python
cfg = build_function_cfg(component, function)
flow = analyze_data_flow(cfg, component)
state = flow.at_instruction(0x02000020)
```

Document exact-value abstract interpretation, CONSTANT vs ADDRESS, overlay ownership, literal bounds, call clobbers, conditional joins, unsupported-write invalidation, and no operand-text parsing. Provenance doc: Capstone remains existing BSD-style decoder dependency; semantic adapter/fixed point are toolkit-owned; angr reference-only; melonDS external; no new dependency.

- [ ] **Step 4: Run complete gates**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: all PASS.

- [ ] **Step 5: PR/merge gate**

Open draft PR `phase-7e-data-flow -> main`. Require exact-head pull-request CI Test/Ruff/Mypy PASS. Mark ready, squash-merge, verify resulting main SHA, then verify push CI on main before Phase 7E2.

---

## Phase 7E2 PR

Create fresh branch `phase-7e2-stack-abi-recovery` from verified post-7E1 `main`. Do not continue 7E2 on the merged 7E1 branch.

### Task 6: Stack State, Frame Depth, and Stack Slots

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Modify: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Create: `src/nds_disassembly_toolkit/analysis/stack.py`
- Create: `tests/unit/test_analysis_stack.py`

**Interfaces:**
- `StackAccessKind`: LOAD, STORE.
- `StackSlotKind`: LOCAL, SAVED_REGISTER, INCOMING_ARGUMENT, UNKNOWN.
- `StackAccess(instruction_address, kind, width)`.
- `StackSlot(offset, kind, accesses)`; offset relative to function-entry SP.
- `StackFrame(frame_size: int | None, frame_pointer: Register | None, stack_depth_known: bool)`.
- `StackState(offset: int | None, frame_pointers: tuple[tuple[Register, int], ...] = ())`.
- Extend `InstructionFlowState` with `stack_before/stack_after: StackState | None = None`; `BlockFlowState` with `stack_entry/stack_exit: StackState | None = None`.
- `StackAnalysis(frame: StackFrame, slots: tuple[StackSlot, ...])`.
- `analyze_stack(flow: FunctionDataFlow) -> StackAnalysis` in `analysis/stack.py`; used by Task 7, not required as a root-package export.
- Same private CFG fixed-point state gains `stack: StackState`; no second solver.

**Test helpers in `test_analysis_stack.py`:**

```python
BASE = 0x02000000


def _function(instruction_set: InstructionSet = InstructionSet.ARM) -> FunctionCandidate:
    return FunctionCandidate(
        component="arm9",
        address=BASE,
        offset=0,
        instruction_set=instruction_set,
        confidence="high",
        evidence=("test",),
    )


def _flow_from_arm(*words: int) -> FunctionDataFlow:
    data = b"".join(struct.pack("<I", word) for word in words)
    component = Component("arm9", Path("arm9.bin"), BASE, data)
    return analyze_data_flow(build_function_cfg(component, _function()), component)


def _flow_from_thumb(*halfwords: int) -> FunctionDataFlow:
    data = b"".join(struct.pack("<H", word) for word in halfwords)
    component = Component("arm9", Path("arm9.bin"), BASE, data)
    return analyze_data_flow(
        build_function_cfg(component, _function(InstructionSet.THUMB)), component
    )
```

- [ ] **Step 1: Write failing stack-depth tests**

```python
def test_arm_push_and_sub_sp_recover_frame_size() -> None:
    flow = _flow_from_arm(
        encode_push((ArmRegister.R4, ArmRegister.LR)),
        encode_data_processing_immediate(
            DataOpcode.SUB, rd=ArmRegister.SP, rn=ArmRegister.SP, immediate=0x10
        ),
        encode_data_processing_immediate(
            DataOpcode.ADD, rd=ArmRegister.SP, rn=ArmRegister.SP, immediate=0x10
        ),
        encode_pop((ArmRegister.R4, ArmRegister.PC)),
    )
    stack = analyze_stack(flow)
    assert stack.frame.frame_size == 0x18
    assert stack.frame.stack_depth_known


def test_thumb_stack_adjustments_match_arm_depth() -> None:
    flow = _flow_from_thumb(0xB510, 0xB084, 0xB004, 0xBD10)
    assert analyze_stack(flow).frame.frame_size == 0x18
```

Build a manual diamond with typed `sub sp,sp,#4` on one branch and `sub sp,sp,#8` on the other; assert join block `stack_entry.offset is None`.

- [ ] **Step 2: Write failing slot/frame-pointer tests**

Create SP-relative word store/load after a known stack adjustment; assert one exact entry-SP-relative slot with LOAD/STORE accesses width 4. Create `mov r11,sp` then `[r11,#-4]`; assert frame-relative slot. For push `{r4,lr}`, assert SAVED_REGISTER slots at `-8` and `-4` in ascending-address register order.

- [ ] **Step 3: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_stack.py -v
```

Expected: FAIL because stack models/state/helper do not exist.

- [ ] **Step 4: Extend the existing fixed-point state**

Use entry `StackState(offset=0)`. Transfer rules:

```python
if mnemonic == "push" and register_list is not None and stack.offset is not None:
    next_offset = stack.offset - 4 * len(register_list)
elif mnemonic == "pop" and register_list is not None and stack.offset is not None:
    next_offset = stack.offset + 4 * len(register_list)
elif is_sub_sp_immediate and stack.offset is not None:
    next_offset = stack.offset - immediate
elif is_add_sp_immediate and stack.offset is not None:
    next_offset = stack.offset + immediate
elif Register.SP in instruction.semantics.registers_written:
    next_offset = None
```

At joins, identical offsets survive; disagreement/unknown -> None. `mov frame_reg,sp` records frame register -> current entry-SP offset. Any write to that frame register removes it. Join frame-pointer maps by intersection of identical facts. Populate stack fields on existing flow-state records.

- [ ] **Step 5: Implement `analyze_stack` from existing flow records**

```python
def _entry_relative_offset(
    operand: InstructionOperand, stack: StackState
) -> int | None:
    memory = operand.memory
    if memory is None or memory.index is not None:
        return None
    if memory.base is Register.SP and stack.offset is not None:
        return stack.offset + memory.displacement
    frame_map = dict(stack.frame_pointers)
    if memory.base in frame_map:
        return frame_map[memory.base] + memory.displacement
    return None
```

Iterate `flow.instructions` only; never call decoder or parse text. Use typed memory access/width. For push save slots: new SP = old SP - 4*n; canonical ascending registers occupy ascending addresses from new SP. Negative non-save slots = LOCAL; nonnegative = INCOMING_ARGUMENT. `frame_size` = deepest proven negative SP offset reached; retain proven maximum even if later merges lose precision, and set `stack_depth_known=False`. Populate one frame pointer only when consistently proven for recovered accesses.

- [ ] **Step 6: Verify GREEN**

```bash
python -m pytest tests/unit/test_analysis_stack.py tests/unit/test_analysis_data_flow.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/model.py src/nds_disassembly_toolkit/analysis/data_flow.py src/nds_disassembly_toolkit/analysis/stack.py tests/unit/test_analysis_stack.py
git commit -m "feat: recover stack frames and slots"
```

### Task 7: Argument/Return Evidence and Function Summary

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Modify: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Modify: `src/nds_disassembly_toolkit/analysis/stack.py`
- Modify: `tests/unit/test_analysis_stack.py`

**Interfaces:**
- `ArgumentLocationKind`: REGISTER, STACK.
- `ArgumentEvidence(index, kind, register, stack_offset, uses)`.
- `ReturnEvidence(return_address, value)`.
- `FunctionSummary(arguments, returns, stack_frame, stack_slots)`.
- Extend 7E1 `FunctionDataFlow` with `summary: FunctionSummary | None = None` **only now, after `FunctionSummary` exists**.
- Private fixed-point state gains `entry_arguments_live: frozenset[Register]` solved in the same worklist.
- `analyze_data_flow` fills `FunctionDataFlow.summary` by combining existing flow + `analyze_stack` + argument/return evidence.

- [ ] **Step 1: Write failing register-argument tests**

```python
def test_use_before_overwrite_recovers_register_argument() -> None:
    flow = _flow_from_arm(0xE2804001, 0xE12FFF1E)  # add r4,r0,#1; bx lr
    assert flow.summary is not None
    arg0 = next(item for item in flow.summary.arguments if item.register is Register.R0)
    assert arg0.index == 0
    assert arg0.uses == (BASE,)
```

Also: write r0 before first read -> no argument; read+write same instruction records read then kills liveness; call kills r0-r3 for later uses; join uses liveness intersection.

- [ ] **Step 2: Write failing stack-argument/return tests**

Use a proven `[entry_sp + 0]` load and assert STACK argument with `stack_offset=0`. Add:

```python
def test_constant_return_is_reported_at_return_site() -> None:
    flow = _flow_from_arm(0xE3A00007, 0xE12FFF1E)  # mov r0,#7; bx lr
    assert flow.summary is not None
    evidence = flow.summary.returns[0]
    assert evidence.return_address == BASE + 4
    assert evidence.value.kind is AbstractValueKind.CONSTANT
    assert evidence.value.value == 7
```

Also two return sites with different constants -> two sorted records; unknown r0 return -> UNKNOWN.

- [ ] **Step 3: Verify RED**

```bash
python -m pytest tests/unit/test_analysis_stack.py -v
```

Expected: summary tests FAIL while Task 6 tests stay green.

- [ ] **Step 4: Solve entry-argument liveness in the existing worklist**

```python
ENTRY_ARGUMENTS = frozenset({Register.R0, Register.R1, Register.R2, Register.R3})


def _join_live_arguments(states: Sequence[_FlowState]) -> frozenset[Register]:
    if not states:
        return frozenset()
    live = set(states[0].entry_arguments_live)
    for state in states[1:]:
        live.intersection_update(state.entry_arguments_live)
    return frozenset(live)
```

Before transfer, record reads of still-live entry registers; then remove decoded writes. Calls remove caller-clobbered argument registers. Evidence is finite/deterministic and does not affect register/stack semantic equality.

- [ ] **Step 5: Build deterministic summaries**

Merge r0-r3 uses and map indices 0-3. Convert INCOMING_ARGUMENT stack slots with accesses to stack argument evidence, using `index=None` when location does not prove a source-level parameter index. At every reachable `ControlFlowKind.RETURN`, capture r0 from instruction **before** state; keep return sites separate/sorted.

```python
stack = analyze_stack(flow_without_summary)
summary = FunctionSummary(
    arguments=arguments,
    returns=returns,
    stack_frame=stack.frame,
    stack_slots=stack.slots,
)
return replace(flow_without_summary, summary=summary)
```

- [ ] **Step 6: Verify GREEN**

```bash
python -m pytest tests/unit/test_analysis_stack.py tests/unit/test_analysis_data_flow.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/model.py src/nds_disassembly_toolkit/analysis/data_flow.py src/nds_disassembly_toolkit/analysis/stack.py tests/unit/test_analysis_stack.py
git commit -m "feat: recover function argument and return evidence"
```

### Task 8: 7E2 Public API, Documentation, Verification, and Merge

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `tests/unit/test_analysis_stack.py`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`

**Interfaces:** Export `StackAccessKind`, `StackSlotKind`, `StackAccess`, `StackSlot`, `StackFrame`, `StackState`, `StackAnalysis`, `ArgumentLocationKind`, `ArgumentEvidence`, `ReturnEvidence`, `FunctionSummary`. `analyze_stack` remains module-level in `analysis.stack`; normal stable entry is `analyze_data_flow(...).summary`.

- [ ] **Step 1: Write failing export test**

```python
def test_stack_summary_api_is_exported() -> None:
    assert analysis.StackFrame is StackFrame
    assert analysis.StackSlot is StackSlot
    assert analysis.ArgumentEvidence is ArgumentEvidence
    assert analysis.ReturnEvidence is ReturnEvidence
    assert analysis.FunctionSummary is FunctionSummary
```

- [ ] **Step 2: Verify RED**

Run the focused export test. Expected: FAIL until root exports are wired.

- [ ] **Step 3: Export + document/provenance**

Add imports/`__all__`. Document entry-SP offsets, typed widths/direction, saved/local/incoming slots, frame precision, r0-r3 use-before-overwrite, stack-argument evidence, per-return r0. Explicit exclusions: source-level signature/type inference, general alias analysis, interprocedural summaries, symbolic execution, decompilation. Provenance: Phase 7E logic toolkit-owned; Capstone existing dependency; angr/melonDS reference-only; no new dependency.

- [ ] **Step 4: Run complete gates**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: all PASS.

- [ ] **Step 5: Scope audit**

Verify via repository search/diff: no Bakugan/B6RE/Gate material; no dependency change; no Capstone import outside decoder introduced by 7E; no `.operands` parsing in data_flow/stack; no `decode_instruction` call in data_flow/stack; no second CFG; every approved spec test category has focused coverage.

- [ ] **Step 6: PR/merge**

Open `phase-7e2-stack-abi-recovery -> main`; require exact-head pull-request CI Test/Ruff/Mypy PASS; mark ready; squash-merge; verify main SHA and push CI.

- [ ] **Step 7: Final Phase 7E completion check**

Confirm 7E1 + 7E2 are on main, post-merge CI green, 7A-7D regressions green, and Phase 7F can persist `FunctionDataFlow`/`FunctionSummary` without re-analysis. Do not begin Phase 7F inside Phase 7E.
