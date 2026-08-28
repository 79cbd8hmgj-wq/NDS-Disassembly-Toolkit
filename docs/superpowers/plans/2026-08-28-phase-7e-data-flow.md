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
- Produces `Register(StrEnum)` with `R0` through `R15` and aliases `SP = R13`, `LR = R14`, `PC = R15`.
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

Add these exact contract assertions to `test_analysis_decoder.py`:

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

Run:

```bash
python -m pytest tests/unit/test_analysis_decoder.py tests/unit/test_analysis_cfg.py tests/unit/test_analysis_xrefs.py tests/unit/test_analysis_symbols.py -v
```

Expected: the new semantic assertions fail because the types/field do not exist; existing direct-construction tests define the compatibility surface that must remain green after implementation.

- [ ] **Step 3: Implement the immutable semantic models**

Use `StrEnum`, `IntFlag`, `dataclass(frozen=True)`, and `dataclasses.field`. Implement:

```python
@classmethod
def from_name(cls, name: str) -> Register | None:
    normalized = name.strip().lower()
    aliases = {"sp": "r13", "lr": "r14", "pc": "r15"}
    normalized = aliases.get(normalized, normalized)
    if normalized.startswith("r") and normalized[1:].isdigit():
        index = int(normalized[1:])
        if 0 <= index <= 15:
            return cls(f"r{index}")
    return None
```

Unknown names such as CPSR/SPSR/vector registers return `None`; Phase 7E does not pretend they are general-purpose storage. Validate `InstructionOperand` shape in `__post_init__`: exactly the payload appropriate to its kind may be populated, register lists are nonempty/sorted/deduplicated, and `access_width` is either `None` or a positive integer.

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
- Consumes Task 1 semantic records.
- `decode_instruction(data: bytes, *, address: int, instruction_set: InstructionSet) -> DecodedInstruction | None` remains unchanged and now fills `semantics`.
- Uses only Capstone public attributes available under the existing `capstone>=5,<7` range: `operands`, `reg_name`, `regs_access()`, ARM operand `type/reg/imm/mem/access/shift/subtracted`, ARM `cc`, and generic `writeback`.
- For `push`/`pop`, normalize Capstone's ordered register operands into one `REGISTER_LIST` operand while preserving `registers_read`/`registers_written` from `regs_access()`.
- Set `access_width` from instruction semantics, never operand text: word `ldr/str` = 4, `ldrh/strh` = 2, `ldrb/strb` = 1; signed byte/halfword loads may be represented but value propagation remains unsupported until explicitly implemented.

- [ ] **Step 1: Write failing ARM and Thumb semantic tests**

Add:

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


def test_decode_thumb_literal_load_exposes_memory_width() -> None:
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
    assert operand.access_width == 4
```

Also assert: ARM `movne` maps to `ConditionCode.NE`; an ARM writeback load/store records `writeback=True`; ARM and Thumb push produce one `REGISTER_LIST` operand with canonical register aliases and stable ordering.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_decoder.py -v`

Expected: FAIL because decoder results still contain default empty semantics.

- [ ] **Step 3: Implement the Capstone adapter**

Extend private protocols only as required. Add `_register(instruction, reg_id)`, `_condition_code(raw_cc)`, `_shift(operand)`, `_memory(operand)`, `_access_width(mnemonic)`, `_operand(...)`, and `_semantics(...)`. Convert register IDs through `instruction.reg_name(...)` + `Register.from_name(...)`. Sort/deduplicate `regs_access()` by canonical `Register.value`. Preserve operand order. Preserve shifts so a shifted register is never treated as an unshifted transfer. Collapse `push`/`pop` register members into one list operand after conversion.

Capstone constants/objects stay inside `decoder.py`. Existing control-flow/direct-target behavior remains unchanged.

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

### Task 3: Abstract Values, Register State, and Straight-Line Data Flow

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Create: `tests/unit/test_analysis_data_flow.py`

**Interfaces:**
- Produces `AbstractValueKind(StrEnum)`: `UNKNOWN`, `CONSTANT`, `ADDRESS`.
- Produces immutable `AbstractValue(kind: AbstractValueKind, value: int | None = None, component: str | None = None, provenance: tuple[int, ...] = field(default=(), compare=False))`.
- Produces immutable sparse `RegisterState(values: tuple[tuple[Register, AbstractValue], ...] = ())` with `value(register: Register) -> AbstractValue`; omitted registers read as `UNKNOWN`.
- Produces immutable `InstructionFlowState(instruction: DecodedInstruction, before: RegisterState, after: RegisterState)` with `address` property delegating to `instruction.address`.
- Produces immutable `BlockFlowState(address: int, instruction_set: InstructionSet, entry: RegisterState, exit: RegisterState)`.
- Produces immutable `FunctionDataFlow(function: FunctionCandidate, blocks: tuple[BlockFlowState, ...], instructions: tuple[InstructionFlowState, ...], warnings: tuple[str, ...] = (), summary: FunctionSummary | None = None)`; define `FunctionSummary` later via forward annotation/default without importing a nonexistent implementation. `at_instruction(address)` and `for_block(address)` return one deterministic match or `None`.
- Produces public `analyze_data_flow(cfg: FunctionControlFlowGraph, component: Component) -> FunctionDataFlow`; Task 3 implements the one-block/straight-line case, Task 4 extends the same function to the general CFG fixed point.
- Internal transfer API: `_transfer(instruction: DecodedInstruction, state: RegisterState, component: Component, warnings: set[str]) -> RegisterState`.

**Test helper defined in this task:**

```python
BASE = 0x02000000


def _arm_words(*words: int) -> bytes:
    return b"".join(struct.pack("<I", word) for word in words)


def _flow_from_arm(*words: int) -> FunctionDataFlow:
    component = Component("arm9", Path("arm9.bin"), BASE, _arm_words(*words))
    function = FunctionCandidate(
        component="arm9",
        address=BASE,
        offset=0,
        instruction_set=InstructionSet.ARM,
        confidence="high",
        evidence=("test",),
    )
    return analyze_data_flow(build_function_cfg(component, function), component)
```

- [ ] **Step 1: Write failing straight-line value tests**

Use the existing ARM encoder with the root encoder register imported as `ArmRegister`:

```python
def test_mov_and_add_propagate_exact_constants() -> None:
    flow = _flow_from_arm(
        encode_data_processing_immediate(
            DataOpcode.MOV, rd=ArmRegister.R0, immediate=4
        ),
        encode_data_processing_immediate(
            DataOpcode.ADD, rd=ArmRegister.R1, rn=ArmRegister.R0, immediate=3
        ),
        encode_bx(ArmRegister.LR),
    )
    after_add = flow.at_instruction(BASE + 4)
    assert after_add is not None
    value = after_add.after.value(Register.R1)
    assert value.kind is AbstractValueKind.CONSTANT
    assert value.value == 7
    assert value.provenance == (BASE, BASE + 4)
```

Add exact tests for register-to-register `mov`, `sub`, insufficient input becoming unknown, unsupported `mul` invalidating its destination, and a `CONSTANT` used as a memory base becoming `ADDRESS(component=None)` in the post-instruction state without acquiring a component by numeric range.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_data_flow.py -v`

Expected: FAIL because flow models/module do not exist.

- [ ] **Step 3: Implement models, validation, one-block analysis, and straight-line transfer**

`AbstractValue.__post_init__` enforces: `UNKNOWN` has no value/component; `CONSTANT` has a 32-bit value and no component; `ADDRESS` has a 32-bit value and optional component. Normalize register states by canonical register value and omit unknown entries.

Validate `cfg.function.component == component.name`; validate each block's `component`, address range, and `offset == component.offset_for_address(block.address)`. Task 3 may raise `ValueError("multi-block data flow requires CFG fixed-point support")` for multiple-block CFGs until Task 4 replaces that temporary limitation.

Implement exact `mov`, `add`, `sub` only for unshifted operand forms represented by typed semantics. `ADDRESS +/- CONSTANT` remains `ADDRESS`; `CONSTANT +/- CONSTANT` remains `CONSTANT`; all other unsupported combinations become unknown. Arithmetic wraps to unsigned 32-bit values. Unsupported decoder-proven writes become unknown.

When a typed memory operand uses a register currently holding `CONSTANT`, update that register to `ADDRESS` with the same numeric value/provenance and `component=None`; the address role is proven by use, but ownership is not inferred.

- [ ] **Step 4: Verify GREEN**

Run: `python -m pytest tests/unit/test_analysis_data_flow.py tests/unit/test_analysis_decoder.py -v`

Expected: all straight-line tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/model.py src/nds_disassembly_toolkit/analysis/data_flow.py tests/unit/test_analysis_data_flow.py
git commit -m "feat: propagate register constants and addresses"
```

### Task 4: General CFG Fixed Point, PC Semantics, Literal Pools, Conditions, Calls, and Provenance

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/data_flow.py`
- Modify: `tests/unit/test_analysis_data_flow.py`

**Interfaces:**
- Extends the Task 3 `analyze_data_flow(...)` implementation to arbitrary existing Phase 7B CFGs.
- Fixed-point keys blocks by `(block.address, block.instruction_set)`; public tuples sort by `(address, instruction_set.value)`.
- Only local `BRANCH`/`FALLTHROUGH` edges are predecessor edges. `CALL` edges are not graph predecessors; call clobbering occurs at the caller instruction.
- Semantic worklist equality compares abstract values by `(kind, value, component)` only.
- After semantic convergence, a second deterministic provenance-enrichment pass runs over the stabilized semantic graph. Provenance sets only grow from the finite set of reachable instruction addresses and therefore converge without changing semantic values or block scheduling decisions.

**Additional test helper defined in this task:**

```python
def _manual_cfg(
    component: Component,
    *,
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
```

Manual CFG tests construct `DecodedInstruction` objects with explicit `InstructionSemantics`; they never rely on `.operands` text.

- [ ] **Step 1: Write failing CFG join/validation tests**

Create a three-block diamond manually. One predecessor exits with `r1=2`, the other with `r1=3`; the join block must enter with unknown `r1`. Create the same diamond with both sides `r1=2`; the join must preserve constant 2. Add a backward edge to a stable loop and assert deterministic convergence.

Add exact rejection tests:

```python
def test_data_flow_rejects_mismatched_cfg_component() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    cfg = _cfg_named("overlay_1")
    with pytest.raises(ValueError, match="component"):
        analyze_data_flow(cfg, component)


def test_data_flow_rejects_inconsistent_block_offset() -> None:
    component = Component("arm9", Path("arm9.bin"), BASE, bytes(0x20))
    cfg = _cfg_with_block_offset(4)
    with pytest.raises(ValueError, match="offset"):
        analyze_data_flow(cfg, component)
```

Define `_cfg_named` and `_cfg_with_block_offset` directly beside these tests by constructing the same immutable CFG records used elsewhere in the file.

- [ ] **Step 2: Write failing PC/literal/conditional/call tests**

Add:

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

Also add: `add r0, pc, #imm` produces `ADDRESS(component="arm9")` using ARM `PC=address+8`; Thumb PC-relative literal `ldr` uses aligned `(address+4)`; word `ldr` reads 4 bytes little-endian, byte/halfword PC-relative loads use their typed width when unsigned, signed literal forms remain unsupported/unknown; out-of-range literal access writes unknown and records exactly one stable warning; conditional write joins old/new; direct `BL` clobbers `r0-r3/r12/lr` but preserves a known `r4`; identical runtime addresses in separately analyzed overlay components never acquire the other overlay's ownership.

- [ ] **Step 3: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_data_flow.py -v`

Expected: multi-block/PC/literal/call tests FAIL while Task 3 straight-line tests remain green.

- [ ] **Step 4: Implement deterministic semantic fixed point**

Remove Task 3's temporary multi-block rejection. Build predecessor lists only from edges whose kind is `BRANCH`/`FALLTHROUGH` and whose target exactly matches a local CFG block. Function entry starts with empty unknown `RegisterState`; non-entry blocks remain unreachable until a predecessor has an exit state.

Join each register: identical semantic triples `(kind, value, component)` across all reachable incoming states survive; any disagreement/unknown combination becomes unknown. Use a deterministic deque ordered by `(address, instruction_set.value)` and enqueue successors only when semantic exit state changes.

- [ ] **Step 5: Implement PC, literal, conditional, and call behavior**

For explicit PC source reads use `address + 8` in ARM state. For Thumb PC-relative memory/address calculations use `(address + 4) & ~3`. A PC-derived effective address is `ADDRESS(component=component.name)` because its ownership comes from the current decoded component.

For unsigned in-bounds literal loads, read exactly `access_width` bytes little-endian and produce `CONSTANT`. Do not classify the loaded integer as an address by numeric appearance. Unsupported signed literal forms write unknown. Out-of-range effective addresses add a deterministic warning string keyed by instruction/effective address and write unknown.

At `CALL`, set `{R0,R1,R2,R3,R12,LR}` unknown after decoded-write handling while preserving `R4-R11,SP` unless the instruction itself explicitly writes them. For `condition` other than `AL`/`INVALID`, compute the executed state and join each written register with the incoming value to represent the not-executed path.

- [ ] **Step 6: Implement provenance enrichment and verify convergence**

Run the semantic fixed point without letting provenance participate in state equality. Then rerun transfer over the stabilized block-entry semantic states, propagating finite sorted instruction-address provenance. At joins with identical semantic values, union provenance from agreeing predecessors; never union evidence across a semantic disagreement that became unknown. Iterate provenance sets until they stop growing, but do not reschedule semantic value computation.

- [ ] **Step 7: Verify GREEN and regressions**

Run:

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

- [ ] **Step 3: Export API and update documentation/provenance**

Add a Phase 7E1 section to `docs/disassembly-and-analysis.md` showing:

```python
cfg = build_function_cfg(component, function)
flow = analyze_data_flow(cfg, component)
state = flow.at_instruction(0x02000020)
```

Document exact-value abstract interpretation rather than symbolic execution; `CONSTANT` vs `ADDRESS`; component-aware overlays; call clobbers; conditional merges; literal-pool bounds; unsupported-write invalidation; no operand-text parsing.

In provenance, record that Capstone semantic metadata is converted through toolkit-owned adapter code; the fixed-point implementation is toolkit-owned; angr remains architecture/reference-only; melonDS remains external; no new dependency was added.

- [ ] **Step 4: Run complete local quality gates**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: all PASS.

- [ ] **Step 5: Open and verify the Phase 7E1 PR**

Open a draft PR from `phase-7e-data-flow` to `main`. Because current CI runs on pull requests, require the exact branch-head run to pass Test, Ruff, and Mypy. Mark ready only after exact-head success, squash-merge, verify the resulting `main` SHA, and verify push CI on `main` before beginning 7E2.

---

## Phase 7E2 PR

Start Phase 7E2 on a fresh branch named `phase-7e2-stack-abi-recovery` from the verified post-7E1 `main` commit. Do not continue 7E2 commits on the already-merged 7E1 branch.

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
- Produces immutable `StackSlot(offset: int, kind: StackSlotKind, accesses: tuple[StackAccess, ...])`, where `offset` is relative to function-entry SP.
- Produces immutable `StackFrame(frame_size: int | None, frame_pointer: Register | None, stack_depth_known: bool)`.
- Produces immutable `StackState(offset: int | None, frame_pointers: tuple[tuple[Register, int], ...] = ())`.
- Extends `InstructionFlowState` with `stack_before: StackState | None = None`, `stack_after: StackState | None = None`; extends `BlockFlowState` with `stack_entry: StackState | None = None`, `stack_exit: StackState | None = None`. Defaults preserve 7E1 source compatibility.
- Produces immutable `StackAnalysis(frame: StackFrame, slots: tuple[StackSlot, ...])`.
- Produces module-level `analyze_stack(flow: FunctionDataFlow) -> StackAnalysis` in `analysis/stack.py`. It is an implementation-layer helper used by Task 7 and is not required to be re-exported from `nds_disassembly_toolkit.analysis`.
- Extends the **same** private fixed-point state in `data_flow.py` with `stack: StackState`; no second CFG solver is added.

- [ ] **Step 1: Write failing ARM/Thumb stack-depth tests**

Add:

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
```

Add a Thumb fixture with words `0xB510, 0xB084, 0xB004, 0xBD10` (`push {r4,lr}; sub sp,#0x10; add sp,#0x10; pop {r4,pc}`) and assert the same frame size. Add a manual diamond whose predecessor `StackState.offset` values disagree and assert the join's stack offset becomes `None`.

- [ ] **Step 2: Write failing stack-slot/frame-pointer tests**

Create an SP-relative word store/load around a known negative SP offset and assert one `StackSlot` with that exact entry-SP-relative offset and two accesses of width 4. Create `mov r11, sp` followed by `[r11,#-4]` and assert frame-pointer-relative recovery. For `push {r4,lr}`, assert saved-register slots are `SAVED_REGISTER` and occupy exact entry-relative offsets `-8` and `-4` in ascending-address register order.

- [ ] **Step 3: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_stack.py -v`

Expected: FAIL because stack models/state/helper do not exist.

- [ ] **Step 4: Extend the existing fixed-point state with stack facts**

Initialize function entry `StackState(offset=0)`. Supported `push` subtracts `4 * len(registers)`; `pop` adds it. Supported `sub sp, sp, #imm` subtracts; `add sp, sp, #imm` adds. If a decoded instruction writes SP by an unsupported form, set `offset=None` and clear frame-pointer offsets that depended on an unknowable SP transformation.

At CFG joins, identical known stack offsets survive; differing or unknown offsets become `None`. A supported unshifted `mov frame_reg, sp` records `frame_reg -> current entry-SP offset`; any later write to that frame register removes the fact. Frame-pointer maps join by keeping only identical `(register, offset)` facts present on every reachable path.

Populate the new stack fields on the same `InstructionFlowState`/`BlockFlowState` records produced by 7E1.

- [ ] **Step 5: Implement `analyze_stack` from existing flow records**

`analyze_stack` iterates `flow.instructions` in deterministic address order; it does **not** call `decode_instruction` or inspect `.operands`. For each typed memory operand, resolve entry-SP-relative offset from `stack_before.offset` when base is SP, or from `stack_before.frame_pointers` when base is a proven frame pointer. Use `InstructionOperand.access_width` and access flags to create load/store evidence.

For supported `push`, emit saved-register slots using ARM full-descending ordering: new SP is `old_sp - 4*n`; registers in canonical ascending register order occupy ascending addresses from new SP. Negative non-save offsets are `LOCAL`; nonnegative offsets are `INCOMING_ARGUMENT`; unresolved locations are not guessed into a slot.

`StackFrame.frame_size` is the deepest **proven** negative entry-SP offset reached anywhere in reachable flow. `stack_depth_known` is false if any reachable merged state loses stack offset precision; retain a proven maximum frame depth if one exists rather than pretending the whole frame is exact. `frame_pointer` is populated only when one canonical frame register remains proven consistently enough to describe recovered frame-relative slots.

- [ ] **Step 6: Verify GREEN**

Run: `python -m pytest tests/unit/test_analysis_stack.py tests/unit/test_analysis_data_flow.py -v`

Expected: PASS.

- [ ] **Step 7: Commit**

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
- Replaces the Task 3 forward/default summary annotation with the concrete `FunctionSummary | None` type.
- The private fixed-point state gains `entry_arguments_live: frozenset[Register]`; this is solved alongside register/stack semantics in the same block worklist.
- `analyze_data_flow(...)` returns `FunctionDataFlow(..., summary=FunctionSummary(...))` in 7E2 by calling `analyze_stack()` on the already-computed flow states and combining stack facts with argument/return evidence.

- [ ] **Step 1: Write failing register-argument tests**

Add:

```python
def test_use_before_overwrite_recovers_register_argument() -> None:
    flow = _flow_from_arm(0xE2804001, 0xE12FFF1E)  # add r4, r0, #1; bx lr
    assert flow.summary is not None
    arg0 = next(item for item in flow.summary.arguments if item.register is Register.R0)
    assert arg0.index == 0
    assert arg0.uses == (BASE,)
```

Add: write `r0` before first read -> no r0 argument; read/write in the same instruction records the read before killing liveness; a call kills incoming `r0-r3` liveness for later uses; at a CFG join, liveness uses intersection so a register overwritten on either incoming path is no longer classified as the original argument.

- [ ] **Step 2: Write failing stack-argument and return tests**

Add a known `[entry_sp + 0]` load and assert `ArgumentLocationKind.STACK`, `stack_offset=0`, and stable use address. Add:

```python
def test_constant_return_is_reported_at_return_site() -> None:
    flow = _flow_from_arm(0xE3A00007, 0xE12FFF1E)  # mov r0,#7; bx lr
    assert flow.summary is not None
    evidence = flow.summary.returns[0]
    assert evidence.return_address == BASE + 4
    assert evidence.value.kind is AbstractValueKind.CONSTANT
    assert evidence.value.value == 7
```

Add two return sites with different constants and assert two sorted `ReturnEvidence` records; add a return with unknown r0 and assert `UNKNOWN` rather than an invented type/value.

- [ ] **Step 3: Verify RED**

Run: `python -m pytest tests/unit/test_analysis_stack.py -v`

Expected: argument/summary tests FAIL while Task 6 frame/slot tests remain green.

- [ ] **Step 4: Solve entry-argument liveness in the existing fixed point**

Initialize `{R0,R1,R2,R3}` at the entry. Before executing each instruction, any `registers_read` member still live is a use of the original entry value; record the instruction address. After the read is recorded, any decoded write removes that register. A call removes caller-clobbered argument registers. At block joins use set intersection across reachable predecessors.

Keep argument-use accumulation deterministic and finite; like provenance, evidence does not alter register/stack semantic equality.

- [ ] **Step 5: Build deterministic function summaries**

Merge register uses by `r0-r3`, mapping them to indices 0-3. Convert `INCOMING_ARGUMENT` stack slots with actual accesses into stack argument evidence; do not invent C types/names or a positional index when the ABI location alone does not prove one (`index=None` is allowed for stack arguments).

For every reachable instruction with `control_flow is ControlFlowKind.RETURN`, capture `r0` from that instruction's **before** register state. Keep each return site separate and sort by address.

Construct a stack analysis from the already-produced flow, then create `FunctionSummary(arguments, returns, stack_frame, stack_slots)` and return a new frozen `FunctionDataFlow` with `summary` populated.

- [ ] **Step 6: Verify GREEN**

Run: `python -m pytest tests/unit/test_analysis_stack.py tests/unit/test_analysis_data_flow.py -v`

Expected: PASS.

- [ ] **Step 7: Commit**

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
- Export `StackAccessKind`, `StackSlotKind`, `StackAccess`, `StackSlot`, `StackFrame`, `StackState`, `StackAnalysis`, `ArgumentLocationKind`, `ArgumentEvidence`, `ReturnEvidence`, and `FunctionSummary` together with existing `FunctionDataFlow`/`analyze_data_flow`.
- `analyze_stack` remains available from `nds_disassembly_toolkit.analysis.stack` but is not required in the root `analysis` export list; the normal stable entry point is `analyze_data_flow` and its `summary`.

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

Run the focused export test. Expected: FAIL until exports are wired.

- [ ] **Step 3: Export and document Phase 7E2**

Document entry-SP-relative offsets, typed access widths, saved-register/local/incoming-argument slot categories, frame-size precision, `r0-r3` use-before-overwrite evidence, stack-argument evidence, and per-return r0 values. Explicitly state that this is not source-level signature/type recovery, full memory alias analysis, interprocedural summary propagation, symbolic execution, or decompilation.

Update provenance: typed semantic conversion, fixed-point propagation, stack analysis, and ABI evidence are toolkit-owned; Capstone remains the existing BSD-style decoder dependency; angr/melonDS remain non-vendored references; no dependency added.

- [ ] **Step 4: Run complete local quality gates**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: all PASS.

- [ ] **Step 5: Audit scope before PR**

Run repository search/diff checks confirming:

- no `Bakugan`, `B6RE`, or Gate-specific content in Phase 7E source/tests;
- `pyproject.toml` has no new runtime dependency;
- no `capstone` import outside `analysis/decoder.py` was introduced by 7E;
- neither `data_flow.py` nor `stack.py` parses `DecodedInstruction.operands`;
- neither `data_flow.py` nor `stack.py` calls `decode_instruction` or builds a second CFG;
- every approved-spec testing requirement has at least one focused test.

- [ ] **Step 6: Open/verify/merge Phase 7E2**

Open a PR from `phase-7e2-stack-abi-recovery` to `main`. Require exact-head GitHub Actions Test, Ruff, and Mypy success; mark ready; squash-merge; verify resulting `main`; verify push CI on `main`.

- [ ] **Step 7: Final Phase 7E completion check**

Confirm both 7E1 and 7E2 are on `main`, post-merge CI is green, Phase 7A-7D regression tests remain green, and Phase 7F can persist `FunctionDataFlow`/`FunctionSummary` directly without re-analysis. Do not begin Phase 7F inside either Phase 7E PR.
