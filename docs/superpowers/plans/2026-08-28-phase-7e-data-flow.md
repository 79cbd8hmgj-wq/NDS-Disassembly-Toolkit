# Phase 7E Data-Flow Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add conservative typed ARM/Thumb instruction semantics, intraprocedural register/constant/address propagation, then stack-frame/argument/return recovery on the same fixed-point engine.

**Architecture:** `analysis/decoder.py` remains the only Capstone boundary and enriches existing `DecodedInstruction` records with toolkit-owned immutable semantic detail. A new `analysis/data_flow.py` consumes existing Phase 7B CFGs and performs one deterministic fixed-point analysis; Phase 7E2 extends that same state/transfer machinery with stack state while `analysis/stack.py` derives stack/ABI summaries from the fixed-point result rather than rebuilding control flow or re-decoding instructions.

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
- Provenance is deterministic metadata and must not alter abstract-value semantic equality or fixed-point convergence.
- 7E2 extends the same data-flow engine; it may not introduce a second instruction/CFG traversal engine with independent state semantics.
- No Bakugan-specific addresses, symbols, policies, ABI exceptions, or gameplay knowledge.
- No new runtime dependency. angr remains reference-only; melonDS remains outside the static-analysis implementation.

## File Map

- Modify `src/nds_disassembly_toolkit/analysis/model.py`: immutable semantic, value, flow-result, and later summary records.
- Modify `src/nds_disassembly_toolkit/analysis/decoder.py`: Capstone-to-toolkit semantic adapter only.
- Create `src/nds_disassembly_toolkit/analysis/data_flow.py`: value/state helpers, transfer functions, deterministic CFG fixed point, literal reads, call barrier.
- Create `src/nds_disassembly_toolkit/analysis/stack.py`: Phase 7E2 stack-slot/frame and ABI summary derivation that reuses `FunctionDataFlow`.
- Modify `src/nds_disassembly_toolkit/analysis/__init__.py`: stable public exports.
- Modify `tests/unit/test_analysis_decoder.py`: typed semantic decoder contract.
- Create `tests/unit/test_analysis_data_flow.py`: 7E1 value/CFG/validation contract.
- Create `tests/unit/test_analysis_stack.py`: 7E2 stack/argument/return contract.
- Modify `docs/disassembly-and-analysis.md`: Phase 7E user-facing behavior and precision boundaries.
- Modify `docs/provenance-and-licenses.md`: dependency/reference boundary.

---

## Phase 7E1 PR

### Task 1: Toolkit-Owned Instruction Semantics Models

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Modify: `tests/unit/test_analysis_decoder.py`

**Interfaces:**
- Produces `Register(StrEnum)` with `R0` through `R15` and enum aliases `SP = R13`, `LR = R14`, `PC = R15`.
- Produces `ConditionCode(StrEnum)` with `INVALID`, `EQ`, `NE`, `HS`, `LO`, `MI`, `PL`, `VS`, `VC`, `HI`, `LS`, `GE`, `LT`, `GT`, `LE`, `AL`.
- Produces `OperandKind(StrEnum)`: `REGISTER`, `IMMEDIATE`, `MEMORY`.
- Produces `OperandAccess(IntFlag)`: `NONE = 0`, `READ = 1`, `WRITE = 2`.
- Produces `ShiftKind(StrEnum)`: `NONE`, `LSL`, `LSR`, `ASR`, `ROR`, `RRX`.
- Produces immutable `OperandShift(kind: ShiftKind = ShiftKind.NONE, value: int = 0)`.
- Produces immutable `MemoryOperand(base: Register | None, index: Register | None, scale: int, displacement: int, subtract_index: bool = False)`.
- Produces immutable `InstructionOperand(kind: OperandKind, access: OperandAccess, register: Register | None = None, immediate: int | None = None, memory: MemoryOperand | None = None, shift: OperandShift = OperandShift())`.
- Produces immutable `InstructionSemantics(operands: tuple[InstructionOperand, ...] = (), registers_read: tuple[Register, ...] = (), registers_written: tuple[Register, ...] = (), condition: ConditionCode = ConditionCode.AL, writeback: bool = False)`.
- Extends `DecodedInstruction` with `semantics: InstructionSemantics = field(default_factory=InstructionSemantics)` so all Phase 7A-7D direct constructors remain source-compatible.

- [ ] **Step 1: Write the failing model/compatibility tests**

Add assertions like:

```python
from nds_disassembly_toolkit.analysis.model import (
    DecodedInstruction,
    InstructionSemantics,
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

Run: `python -m pytest tests/unit/test_analysis_decoder.py tests/unit/test_analysis_cfg.py tests/unit/test_analysis_xrefs.py tests/unit/test_analysis_symbols.py -v`

Expected: focused semantic assertions fail because the new models/field do not exist; existing direct-construction tests demonstrate the compatibility surface that must remain green after implementation.

- [ ] **Step 3: Implement the immutable semantic models**

Use `StrEnum`, `IntFlag`, `dataclass(frozen=True)`, and `dataclasses.field`. Keep Capstone IDs/constants out of these classes. Implement `Register.from_name(name: str) -> Register | None` by normalizing lowercase `sp/lr/pc` to `r13/r14/r15` and accepting `r0` through `r15`; unknown names return `None` so CPSR/SPSR/vector registers can be conservatively excluded from the first general-purpose model.

- [ ] **Step 4: Verify GREEN**

Run the same focused suite. Expected: PASS.

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
- Consumes the Task 1 semantic records.
- `decode_instruction(...)` continues returning the same `DecodedInstruction | None` API, now with populated `semantics`.
- Decoder supports Capstone 5.x and 6.x public attributes already permitted by `capstone>=5,<7`: `operands`, `reg_name`, `regs_access()`, ARM operand `type/reg/imm/mem/access/shift/subtracted`, ARM `cc`, and generic `writeback`.

- [ ] **Step 1: Write failing ARM and Thumb semantic tests**

Use synthetic instructions, not operand-string parsing:

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


def test_decode_thumb_literal_load_exposes_memory_operand() -> None:
    decoded = decode_instruction(
        struct.pack("<H", 0x4800),  # ldr r0, [pc, #0]
        address=0x02000000,
        instruction_set=InstructionSet.THUMB,
    )
    assert decoded is not None
    memory = decoded.semantics.operands[1].memory
    assert memory is not None
    assert memory.base is Register.PC
    assert memory.displacement == 0
```

Also assert an ARM `movne`/conditional instruction maps to `ConditionCode.NE`, and a writeback load/store records `writeback=True`.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_decoder.py -v`

Expected: FAIL because `decode_instruction` still returns the default empty semantics.

- [ ] **Step 3: Implement the Capstone adapter**

Extend the private protocols only as far as required. Add helpers `_register(engine, reg_id)`, `_condition_code(raw_cc)`, `_operand(...)`, `_semantics(...)`. Convert every supported general-purpose register via `instruction.reg_name(...)` + `Register.from_name`; sort/deduplicate `regs_access()` results by register value for deterministic tuples. Preserve operand order. Preserve shift metadata so a shifted register is never misinterpreted as an unshifted value operation. Populate `writeback` directly from Capstone detail.

Do not change existing control-flow/direct-target behavior except to allow the already-computed semantic condition to support tests; keep existing Phase 7A-7D control-flow tests green.

- [ ] **Step 4: Verify GREEN and regression safety**

Run:

```bash
python -m pytest tests/unit/test_analysis_decoder.py tests/unit/test_analysis_functions.py tests/unit/test_analysis_cfg.py tests/unit/test_analysis_xrefs.py tests/unit/test_analysis_symbols.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/decoder.py tests/unit/test_analysis_decoder.py
git commit -m "feat: expose ARM Thumb instruction semantics"
```

### Task 3: Abstract Values, Register State, and Straight-Line Transfers

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Create: `tests/unit/test_analysis_data_flow.py`

**Interfaces:**
- Produces `AbstractValueKind(StrEnum)`: `UNKNOWN`, `CONSTANT`, `ADDRESS`.
- Produces immutable `AbstractValue(kind, value: int | None = None, component: str | None = None, provenance: tuple[int, ...] = field(default=(), compare=False))`.
- Produces immutable sparse `RegisterState(values: tuple[tuple[Register, AbstractValue], ...] = ())` with `value(register) -> AbstractValue`; missing registers read as `UNKNOWN`.
- Produces immutable `InstructionFlowState(address: int, before: RegisterState, after: RegisterState)`.
- Produces immutable `BlockFlowState(address: int, entry: RegisterState, exit: RegisterState)`.
- Produces immutable `FunctionDataFlow(function: FunctionCandidate, blocks: tuple[BlockFlowState, ...], instructions: tuple[InstructionFlowState, ...], warnings: tuple[str, ...] = ())` with `at_instruction(address) -> InstructionFlowState | None` and `for_block(address) -> BlockFlowState | None`.
- Internal transfer API: `_transfer(instruction: DecodedInstruction, state: RegisterState, component: Component) -> RegisterState`.

- [ ] **Step 1: Write failing straight-line value tests**

Use the existing ARM encoder to avoid hand-maintaining complex words:

```python
def test_mov_and_add_propagate_exact_constants() -> None:
    data = _arm_words(
        encode_data_processing_immediate(DataOpcode.MOV, rd=ArmRegister.R0, immediate=4),
        encode_data_processing_immediate(
            DataOpcode.ADD, rd=ArmRegister.R1, rn=ArmRegister.R0, immediate=3
        ),
        encode_bx(ArmRegister.LR),
    )
    flow = _analyze(data)
    after_add = flow.at_instruction(BASE + 4)
    assert after_add is not None
    assert after_add.after.value(Register.R1).kind is AbstractValueKind.CONSTANT
    assert after_add.after.value(Register.R1).value == 7
    assert after_add.after.value(Register.R1).provenance == (BASE, BASE + 4)
```

Add exact tests for register-to-register `mov`, `sub`, insufficient input becoming unknown, and unsupported `mul` invalidating its written destination rather than retaining a previous constant.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_data_flow.py -v`

Expected: FAIL because flow models/module do not exist.

- [ ] **Step 3: Implement value/state helpers and straight-line transfer**

Implement canonical factories for unknown/constant/address values; enforce that `UNKNOWN` has no value/component and `CONSTANT` cannot carry a component. Normalize state tuples by `Register.value` and omit unknown entries. Implement `mov`, `add`, `sub` only when operand shapes/shifts are explicitly supported. `ADDRESS +/- CONSTANT` remains `ADDRESS`; `CONSTANT +/- CONSTANT` remains `CONSTANT`; other combinations become `UNKNOWN`. All arithmetic is normalized to unsigned 32-bit ARM values.

If an instruction has a memory operand whose base register currently contains a `CONSTANT`, promote that base to `ADDRESS(component=None)` because address use is proven, but do not infer component ownership. Unsupported decoder-proven writes are set to unknown.

- [ ] **Step 4: Verify GREEN**

Run: `python -m pytest tests/unit/test_analysis_data_flow.py tests/unit/test_analysis_decoder.py -v`

Expected: straight-line tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/model.py src/nds_disassembly_toolkit/analysis/data_flow.py tests/unit/test_analysis_data_flow.py
git commit -m "feat: propagate register constants and addresses"
```

### Task 4: CFG Fixed Point, PC Semantics, Literal Pools, Conditions, and Calls

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Modify: `tests/unit/test_analysis_data_flow.py`

**Interfaces:**
- Produces public `analyze_data_flow(cfg: FunctionControlFlowGraph, component: Component) -> FunctionDataFlow`.
- The fixed point keys blocks by `(block.address, block.instruction_set)` but public results remain deterministically sorted by runtime address/mode.
- Only `BRANCH` and `FALLTHROUGH` edges whose targets are local CFG block starts are intraprocedural predecessors. `CALL` edges are not predecessor edges; call effects occur in the caller instruction transfer.

- [ ] **Step 1: Write failing CFG/PC/literal/call tests**

Add concrete tests:

```python
def test_cfg_join_degrades_conflicting_values_to_unknown() -> None:
    # mov r0,#1; conditional branch; one path mov r1,#2, other mov r1,#3; join; bx lr
    flow = _analyze_cfg_for_conflicting_join()
    joined = flow.for_block(JOIN)
    assert joined is not None
    assert joined.entry.value(Register.R1).kind is AbstractValueKind.UNKNOWN


def test_arm_literal_pool_load_is_constant_not_guessed_address() -> None:
    data = bytearray(0x10)
    struct.pack_into("<I", data, 0, encode_literal_load(BASE, BASE + 8, ArmRegister.R0))
    struct.pack_into("<I", data, 4, encode_bx(ArmRegister.LR))
    struct.pack_into("<I", data, 8, BASE + 0x40)
    flow = _analyze(bytes(data))
    state = flow.at_instruction(BASE)
    assert state is not None
    value = state.after.value(Register.R0)
    assert value.kind is AbstractValueKind.CONSTANT
    assert value.value == BASE + 0x40
    assert value.component is None
```

Also add: identical values survive a diamond join; a backward-loop CFG converges; `add r0, pc, #imm` creates an `ADDRESS` owned by the current component using ARM `PC=address+8`; Thumb PC-relative literal load uses aligned `(address+4)`; out-of-range literal address records a stable warning and writes unknown; a conditional register write merges old/new and becomes unknown when they differ; a direct `BL` clobbers `r0-r3/r12/lr` but preserves `r4-r11/sp`; same numeric address in two overlay components never causes cross-component ownership inference.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_data_flow.py -v`

Expected: new fixed-point/literal/call tests FAIL.

- [ ] **Step 3: Implement deterministic predecessor joins and worklist**

Validate `cfg.function.component == component.name`, every block belongs to the same component, and each block address/offset is consistent with the named `Component`. Build predecessor lists from local branch/fallthrough edges only. Initialize the function-entry block with an empty/unknown `RegisterState`; other blocks have no reachable input until a predecessor produces one.

Join each general-purpose register semantically: all reachable incoming values must have identical `(kind, value, component)` to survive; otherwise unknown. Merge provenance as a sorted finite union only after semantic agreement. Worklist ordering is deterministic by `(address, instruction_set.value)`.

- [ ] **Step 4: Implement PC/literal/call and conditional behavior**

For explicit PC source reads, use `address + 8` for ARM and `(address + 4) & ~3` for Thumb PC-relative memory/address construction. A PC-relative effective address is `ADDRESS(component=component.name)`. An in-bounds 32-bit literal read returns `CONSTANT` loaded little-endian; do not promote its contents to address merely because the value resembles one.

At a call instruction, set `{R0,R1,R2,R3,R12,LR}` unknown after normal decoded-write handling and preserve `{R4...R11,SP}`. For a non-`AL`/non-`INVALID` condition, compute the executed state then join each written register with its incoming value.

- [ ] **Step 5: Verify GREEN and convergence**

Run:

```bash
python -m pytest tests/unit/test_analysis_data_flow.py -v
python -m pytest tests/unit/test_analysis_decoder.py tests/unit/test_analysis_functions.py tests/unit/test_analysis_cfg.py tests/unit/test_analysis_xrefs.py tests/unit/test_analysis_symbols.py -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

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

**Interfaces:**
- Export `Register`, `ConditionCode`, `OperandKind`, `OperandAccess`, `ShiftKind`, `OperandShift`, `MemoryOperand`, `InstructionOperand`, `InstructionSemantics`, `AbstractValueKind`, `AbstractValue`, `RegisterState`, `InstructionFlowState`, `BlockFlowState`, `FunctionDataFlow`, and `analyze_data_flow` from `nds_disassembly_toolkit.analysis`.

- [ ] **Step 1: Write failing package-export tests**

```python
def test_data_flow_api_is_exported() -> None:
    assert analysis.Register is Register
    assert analysis.AbstractValue is AbstractValue
    assert analysis.FunctionDataFlow is FunctionDataFlow
    assert analysis.analyze_data_flow is analyze_data_flow
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_data_flow.py::test_data_flow_api_is_exported -v`

Expected: FAIL until exports are wired.

- [ ] **Step 3: Export API and update docs/provenance**

Document that 7E1 is exact-value abstract interpretation, not symbolic execution; show one `build_function_cfg(...) -> analyze_data_flow(...)` example; state constant/address distinction, component-aware overlay behavior, call clobber policy, and unsupported-write invalidation. Record that Capstone semantic metadata is converted through toolkit-owned code, while the fixed-point implementation is independent; angr remains reference-only and melonDS remains external.

- [ ] **Step 4: Run exact local quality gates**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: all PASS.

- [ ] **Step 5: Open the Phase 7E1 PR and verify exact-head CI**

Open a draft PR from `phase-7e-data-flow` to `main` once the RED/GREEN commits are present. Mark ready only when the exact branch head passes GitHub Actions Test, Ruff, and Mypy. Squash-merge and verify the push CI on `main` before starting 7E2 from the merged main commit.

---

## Phase 7E2 PR

### Task 6: Stack State, Frame Depth, and Stack Slots

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Modify: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Create: `src/nds_disassembly_toolkit/analysis/stack.py`
- Create: `tests/unit/test_analysis_stack.py`

**Interfaces:**
- Produces `StackAccessKind(StrEnum)`: `LOAD`, `STORE`.
- Produces `StackSlotKind(StrEnum)`: `LOCAL`, `SAVED_REGISTER`, `INCOMING_ARGUMENT`, `UNKNOWN`.
- Produces immutable `StackAccess(instruction_address: int, kind: StackAccessKind, width: int | None)`.
- Produces immutable `StackSlot(offset: int, kind: StackSlotKind, accesses: tuple[StackAccess, ...])`, where offset is relative to function-entry SP.
- Produces immutable `StackFrame(frame_size: int | None, frame_pointer: Register | None, stack_depth_known: bool)`.
- Extends the internal fixed-point state in `data_flow.py` with `sp_offset: int | None` and proven frame-pointer offsets while keeping public `RegisterState` unchanged.
- `stack.py` consumes `FunctionDataFlow` plus its existing instruction semantic states and produces deterministic frame/slot records; it does not call `decode_instruction` or rebuild CFG topology.

- [ ] **Step 1: Write failing ARM/Thumb stack tests**

Use concrete synthetic prologues:

```python
def test_arm_push_and_sub_sp_recover_frame_size() -> None:
    data = _arm_words(
        encode_push((ArmRegister.R4, ArmRegister.LR)),
        encode_data_processing_immediate(
            DataOpcode.SUB, rd=ArmRegister.SP, rn=ArmRegister.SP, immediate=0x10
        ),
        encode_data_processing_immediate(
            DataOpcode.ADD, rd=ArmRegister.SP, rn=ArmRegister.SP, immediate=0x10
        ),
        encode_pop((ArmRegister.R4, ArmRegister.PC)),
    )
    flow = _analyze(data)
    summary = summarize_stack(flow)
    assert summary.frame.frame_size == 0x18
```

Add a Thumb `push {r4,lr}; sub sp,#0x10; add sp,#0x10; pop {r4,pc}` case using `0xB510, 0xB084, 0xB004, 0xBD10`; an SP-relative local store/load producing one stable negative-offset slot; an explicit `mov r11, sp` frame pointer followed by frame-relative access; and a diamond whose incoming stack depths disagree, forcing stack depth unknown at the join.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_stack.py -v`

Expected: FAIL because stack models/state are absent.

- [ ] **Step 3: Extend the existing fixed-point state with stack facts**

Entry `sp_offset=0`. `push` subtracts `4 * register_count`; `pop` adds the same amount. Supported `sub sp, sp, #imm` subtracts and `add sp, sp, #imm` adds. At joins, identical known offsets survive; differing/unknown offsets become unknown. Track an explicit frame-pointer register only when a supported register move copies the current known SP position; invalidate that frame-pointer fact when the register is subsequently written.

Do not infer stack changes from operand text. For unsupported instructions that write SP, set stack depth unknown.

- [ ] **Step 4: Recover stack slots without general alias analysis**

For a memory operand whose base is SP with known entry-relative SP offset, compute `slot_offset = sp_offset + displacement`. For a proven frame-pointer base, use its stored entry-SP offset plus displacement. Merge accesses by exact offset, sorted by instruction address. Negative offsets are local/saved-frame locations; nonnegative entry-relative offsets accessed as data become incoming-argument candidates. Register-save locations produced by supported push operations are `SAVED_REGISTER` rather than generic locals. Derive `frame_size` from the deepest proven negative stack position reached; if stack depth becomes structurally unknowable before any trustworthy maximum can be maintained, expose `frame_size=None` rather than guessing.

- [ ] **Step 5: Verify GREEN**

Run: `python -m pytest tests/unit/test_analysis_stack.py tests/unit/test_analysis_data_flow.py -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/model.py src/nds_disassembly_toolkit/analysis/data_flow.py src/nds_disassembly_toolkit/analysis/stack.py tests/unit/test_analysis_stack.py
git commit -m "feat: recover stack frames and slots"
```

### Task 7: Argument and Return Evidence + Function Summary

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Modify: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Modify: `src/nds_disassembly_toolkit/analysis/stack.py`
- Modify: `tests/unit/test_analysis_stack.py`

**Interfaces:**
- Produces `ArgumentLocationKind(StrEnum)`: `REGISTER`, `STACK`.
- Produces immutable `ArgumentEvidence(index: int | None, kind: ArgumentLocationKind, register: Register | None, stack_offset: int | None, uses: tuple[int, ...])`.
- Produces immutable `ReturnEvidence(return_address: int, value: AbstractValue)`.
- Produces immutable `FunctionSummary(arguments: tuple[ArgumentEvidence, ...], returns: tuple[ReturnEvidence, ...], stack_frame: StackFrame, stack_slots: tuple[StackSlot, ...])`.
- Extends `FunctionDataFlow` with `summary: FunctionSummary | None = None` for source compatibility, and `analyze_data_flow(...)` populates it once 7E2 stack/ABI recovery is enabled.

- [ ] **Step 1: Write failing argument/return tests**

```python
def test_use_before_overwrite_recovers_register_argument() -> None:
    # add r4, r0, #1 consumes entry r0 before any local write to r0
    flow = _analyze(_arm_words(0xE2804001, 0xE12FFF1E))
    assert flow.summary is not None
    arg0 = next(item for item in flow.summary.arguments if item.register is Register.R0)
    assert arg0.index == 0
    assert arg0.uses == (BASE,)


def test_constant_return_is_reported_at_return_site() -> None:
    flow = _analyze(_arm_words(0xE3A00007, 0xE12FFF1E))
    assert flow.summary is not None
    assert flow.summary.returns[0].return_address == BASE + 4
    assert flow.summary.returns[0].value.value == 7
```

Add tests proving: a write to `r0` before its first read prevents argument evidence; call clobber removes incoming `r0-r3` evidence; a known `[entry_sp + 0]` load is an incoming stack argument rather than a local; two return sites with different constants remain two deterministic `ReturnEvidence` records instead of being collapsed into a fake single value; unknown `r0` at return is represented as unknown rather than inventing a type/value.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_stack.py -v`

Expected: FAIL until summary records/recovery exist.

- [ ] **Step 3: Track entry-argument liveness in the same fixed point**

Initialize an internal incoming-register set `{R0,R1,R2,R3}` at function entry. Remove a register after any proven write and remove caller-clobbered argument registers across calls. At joins use intersection, not union: an argument register is considered still the original entry value only when every reachable incoming path preserves it. Record a use only when `registers_read` includes that still-live entry register before the current instruction writes it.

- [ ] **Step 4: Build deterministic summaries**

Merge register argument uses by register and map `r0-r3` to indices 0-3. Convert proven nonnegative entry-SP stack slots into stack argument evidence without inventing a C type or name. At every reachable `RETURN` instruction, capture `r0` from the instruction's `before` state into `ReturnEvidence`. Sort arguments by register/stack location and returns by return address.

- [ ] **Step 5: Verify GREEN**

Run: `python -m pytest tests/unit/test_analysis_stack.py tests/unit/test_analysis_data_flow.py -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/model.py src/nds_disassembly_toolkit/analysis/data_flow.py src/nds_disassembly_toolkit/analysis/stack.py tests/unit/test_analysis_stack.py
git commit -m "feat: recover function argument and return evidence"
```

### Task 8: 7E2 Public API, Documentation, Full Verification, and Merge

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Modify: `tests/unit/test_analysis_stack.py`
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`

**Interfaces:**
- Export `StackAccessKind`, `StackSlotKind`, `StackAccess`, `StackSlot`, `StackFrame`, `ArgumentLocationKind`, `ArgumentEvidence`, `ReturnEvidence`, `FunctionSummary` together with the already-exported `FunctionDataFlow`/`analyze_data_flow`.

- [ ] **Step 1: Add failing 7E2 export tests**

```python
def test_stack_summary_api_is_exported() -> None:
    assert analysis.StackFrame is StackFrame
    assert analysis.StackSlot is StackSlot
    assert analysis.ArgumentEvidence is ArgumentEvidence
    assert analysis.ReturnEvidence is ReturnEvidence
    assert analysis.FunctionSummary is FunctionSummary
```

- [ ] **Step 2: Verify RED**

Run the focused export test; expect failure until package exports are wired.

- [ ] **Step 3: Export and document Phase 7E2**

Add a Phase 7E2 section explaining entry-relative stack offsets, frame-size confidence, stack-slot categories, evidence-based `r0-r3`/stack arguments, and per-return `r0` evidence. Explicitly state that this is not source-level signature/type recovery, full memory alias analysis, interprocedural summary propagation, or decompilation.

Update provenance text to say Phase 7E typed semantic conversion, fixed-point value propagation, stack analysis, and ABI evidence are toolkit-owned; Capstone remains the existing BSD-style runtime decoder dependency; angr and melonDS remain non-vendored references.

- [ ] **Step 4: Run the complete local quality gates**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: all PASS.

- [ ] **Step 5: Audit scope before PR**

Run repository search/diff checks to confirm no Bakugan/B6RE/Gate-specific material, no new dependency, no Capstone object outside `decoder.py`, no parsing of `.operands` in `data_flow.py`/`stack.py`, and no second CFG decoder. Compare against the approved spec section-by-section.

- [ ] **Step 6: Open/verify/merge Phase 7E2**

Create the Phase 7E2 PR from a fresh branch based on the merged 7E1 `main`. Require exact-head GitHub Actions Test, Ruff, and strict Mypy success, mark ready, squash-merge, then verify push CI on `main`.

- [ ] **Step 7: Final Phase 7E completion check**

Confirm both 7E1 and 7E2 are on `main`, post-merge CI is green, Phase 7A-7D regression tests remain green, and the next phase can consume `FunctionDataFlow`/`FunctionSummary` without re-analysis. The next roadmap item is Phase 7F persistence/analysis database; do not begin it inside the 7E PR.
