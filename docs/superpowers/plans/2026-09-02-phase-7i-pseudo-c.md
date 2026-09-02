# Phase 7I Conservative Pseudo-C Decompiler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic, conservative pseudo-C decompilation for persisted ARM/Thumb functions by lifting existing toolkit-owned CFG/data-flow evidence into a dedicated IR, safely structuring provable control flow, and rendering read-only text/JSON through `nds-toolkit project decompile`.

**Architecture:** Add a focused `analysis/decompiler/` package. `model.py` owns immutable IR/result models, `names.py` owns component-aware function/variable naming, `lift.py` consumes persisted `FunctionControlFlowGraph` + `FunctionDataFlow`, `structure.py` converts only provable graph patterns into source-like control flow, `render.py` emits stable pseudo-C, and `service.py` is the read-only public facade. `project_cli.py` remains a thin adapter and never implements decompiler semantics.

**Tech Stack:** Python 3.11+, existing toolkit-owned dataclasses/enums, existing `AnalysisProject`, existing CFG/data-flow/symbol/annotation/xref models, argparse/json/pathlib, pytest, Ruff, strict mypy. No new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-09-02-phase-7i-pseudo-c-design.md`

## Global Constraints

- Start implementation from branch `phase-7i-pseudo-c` at approved-spec head `5eb31b25fc351a8934c019a755ba7754fbb2743a`.
- Do not modify `src/nds_disassembly_toolkit/analysis/project/schema.py`, `SCHEMA_VERSION`, `ANALYSIS_MODEL_VERSION`, or any existing `.ndsre` table.
- Do not add a runtime dependency and do not change dependency declarations in `pyproject.toml`.
- Do not add another Capstone integration or decoder. The decompiler consumes persisted toolkit-owned `DecodedInstruction` semantics only.
- Do not re-run register propagation, stack analysis, ABI recovery, or function discovery inside the decompiler. Consume existing persisted `FunctionDataFlow` and `FunctionSummary`.
- Do not persist pseudo-C, decompiler IR, temporary names, or decompiler-specific inference back into `.ndsre`.
- Keep runtime Phase 7H1/7H2 code separate. Runtime traces may identify a function to decompile, but dynamic observations do not rewrite static semantics in Phase 7I.
- Preserve component-aware overlay identity. Runtime address alone never identifies an overlay symbol/function.
- User annotation `name_override` has naming precedence, then an unambiguous generated symbol, then deterministic structural fallback.
- Unsupported/ambiguous instructions remain visible as explicit fallback IR/comments. Never silently discard them.
- Direct external call targets are named only when one persisted `(component, address, instruction_set)` target is unambiguous; overlapping-overlay matches remain unresolved.
- No struct/class reconstruction, aggressive type inference, jump-table synthesis, symbolic execution, whole-program SSA, semantic ROM diffing, signature DB, or targeted angr integration in Phase 7I.
- Pseudo-C is evidence-backed presentation, not claimed recompilable source.
- Deterministic ordering is mandatory: blocks by `(address, instruction_set)`, instructions in persisted block order, variables by explicit stable keys, labels from addresses, JSON with `sort_keys=True`, and stable text whitespace.
- CLI `--format` accepts exactly `text` or `json` and defaults to `text`; `--output` uses atomic sibling temporary-file replacement.
- Existing top-level error mapping remains: `ValueError` -> exit 2, `NdsToolkitError` -> exit 4, `OSError` -> exit 5.
- Every task follows RED -> minimal GREEN -> focused regression -> commit.
- Final proof requires full pytest, Ruff, strict mypy, unchanged stock-melonDS live CI, exact-head PR verification, squash merge with expected-head protection, and exact post-merge `main` CI.

## File Map

Create:

```text
src/nds_disassembly_toolkit/analysis/decompiler/__init__.py
src/nds_disassembly_toolkit/analysis/decompiler/model.py
src/nds_disassembly_toolkit/analysis/decompiler/names.py
src/nds_disassembly_toolkit/analysis/decompiler/lift.py
src/nds_disassembly_toolkit/analysis/decompiler/structure.py
src/nds_disassembly_toolkit/analysis/decompiler/render.py
src/nds_disassembly_toolkit/analysis/decompiler/service.py

tests/unit/test_analysis_decompiler_model.py
tests/unit/test_analysis_decompiler_names.py
tests/unit/test_analysis_decompiler_lift.py
tests/unit/test_analysis_decompiler_structure.py
tests/unit/test_analysis_decompiler_render.py
tests/unit/test_analysis_decompiler_service.py
```

Modify:

```text
src/nds_disassembly_toolkit/errors.py
src/nds_disassembly_toolkit/analysis/__init__.py
src/nds_disassembly_toolkit/analysis/project_cli.py

tests/unit/test_analysis_data_flow_exports.py
tests/unit/test_analysis_project_cli.py

docs/disassembly-and-analysis.md
docs/provenance-and-licenses.md
README.md
```

Do not modify unless a genuine blocker is demonstrated and reviewed:

```text
src/nds_disassembly_toolkit/analysis/decoder.py
src/nds_disassembly_toolkit/analysis/data_flow.py
src/nds_disassembly_toolkit/analysis/stack.py
src/nds_disassembly_toolkit/analysis/project/schema.py
src/nds_disassembly_toolkit/analysis/runtime/
pyproject.toml
```

---

### Task 1: Decompiler IR, result models, error boundary, and exports

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/decompiler/model.py`
- Create: `src/nds_disassembly_toolkit/analysis/decompiler/__init__.py`
- Modify: `src/nds_disassembly_toolkit/errors.py`
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Create: `tests/unit/test_analysis_decompiler_model.py`
- Modify: `tests/unit/test_analysis_data_flow_exports.py`

**Interfaces:**

Define these public models exactly enough that later tasks consume one stable vocabulary:

```python
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from nds_disassembly_toolkit.analysis.model import CFGEdge, ConditionCode, InstructionSet, Register

@dataclass(frozen=True, slots=True)
class SourceRef:
    address: int
    instruction_set: InstructionSet

class DecompilerVariableKind(StrEnum):
    ARGUMENT = "argument"
    LOCAL = "local"
    TEMPORARY = "temporary"

@dataclass(frozen=True, slots=True)
class DecompilerVariable:
    name: str
    kind: DecompilerVariableKind
    register: Register | None = None
    stack_offset: int | None = None

@dataclass(frozen=True, slots=True)
class ConstantExpression:
    value: int
    source: tuple[SourceRef, ...] = ()

@dataclass(frozen=True, slots=True)
class AddressExpression:
    address: int
    component: str | None
    source: tuple[SourceRef, ...] = ()

@dataclass(frozen=True, slots=True)
class VariableExpression:
    variable: DecompilerVariable
    source: tuple[SourceRef, ...] = ()

@dataclass(frozen=True, slots=True)
class RegisterExpression:
    register: Register
    source: tuple[SourceRef, ...] = ()

class UnaryOperator(StrEnum):
    NEGATE = "negate"
    BITWISE_NOT = "bitwise_not"

class BinaryOperator(StrEnum):
    ADD = "add"
    SUBTRACT = "subtract"
    MULTIPLY = "multiply"
    BITWISE_AND = "bitwise_and"
    BITWISE_OR = "bitwise_or"
    BITWISE_XOR = "bitwise_xor"
    SHIFT_LEFT = "shift_left"
    SHIFT_RIGHT_LOGICAL = "shift_right_logical"
    SHIFT_RIGHT_ARITHMETIC = "shift_right_arithmetic"

@dataclass(frozen=True, slots=True)
class UnaryExpression:
    operator: UnaryOperator
    operand: "DecompilerExpression"
    source: tuple[SourceRef, ...] = ()

@dataclass(frozen=True, slots=True)
class BinaryExpression:
    operator: BinaryOperator
    left: "DecompilerExpression"
    right: "DecompilerExpression"
    source: tuple[SourceRef, ...] = ()

@dataclass(frozen=True, slots=True)
class CompareExpression:
    condition: ConditionCode
    left: "DecompilerExpression"
    right: "DecompilerExpression"
    source: tuple[SourceRef, ...] = ()

@dataclass(frozen=True, slots=True)
class MemoryReadExpression:
    address: "DecompilerExpression"
    width: int
    source: tuple[SourceRef, ...] = ()

@dataclass(frozen=True, slots=True)
class CallExpression:
    name: str
    target_address: int
    target_instruction_set: InstructionSet
    target_component: str | None
    arguments: tuple["DecompilerExpression", ...] = ()
    source: tuple[SourceRef, ...] = ()

@dataclass(frozen=True, slots=True)
class UnknownExpression:
    description: str
    source: tuple[SourceRef, ...] = ()

DecompilerExpression: TypeAlias = (
    ConstantExpression
    | AddressExpression
    | VariableExpression
    | RegisterExpression
    | UnaryExpression
    | BinaryExpression
    | CompareExpression
    | MemoryReadExpression
    | CallExpression
    | UnknownExpression
)
```

Statements and function/block models:

```python
@dataclass(frozen=True, slots=True)
class AssignmentStatement:
    target: VariableExpression | RegisterExpression
    value: DecompilerExpression
    source: tuple[SourceRef, ...]

@dataclass(frozen=True, slots=True)
class MemoryWriteStatement:
    address: DecompilerExpression
    value: DecompilerExpression
    width: int
    source: tuple[SourceRef, ...]

@dataclass(frozen=True, slots=True)
class CallStatement:
    call: CallExpression
    source: tuple[SourceRef, ...]

@dataclass(frozen=True, slots=True)
class ReturnStatement:
    value: DecompilerExpression | None
    source: tuple[SourceRef, ...]

@dataclass(frozen=True, slots=True)
class BranchStatement:
    condition: DecompilerExpression | None
    target_address: int
    target_instruction_set: InstructionSet
    source: tuple[SourceRef, ...]

@dataclass(frozen=True, slots=True)
class UnknownStatement:
    description: str
    source: tuple[SourceRef, ...]

DecompilerStatement: TypeAlias = (
    AssignmentStatement
    | MemoryWriteStatement
    | CallStatement
    | ReturnStatement
    | BranchStatement
    | UnknownStatement
)

@dataclass(frozen=True, slots=True)
class DecompiledBlock:
    address: int
    instruction_set: InstructionSet
    statements: tuple[DecompilerStatement, ...]
    edges: tuple[CFGEdge, ...]

@dataclass(frozen=True, slots=True)
class DecompiledFunction:
    component: str
    address: int
    instruction_set: InstructionSet
    name: str
    parameters: tuple[DecompilerVariable, ...]
    locals: tuple[DecompilerVariable, ...]
    blocks: tuple[DecompiledBlock, ...]
    warnings: tuple[str, ...] = ()
```

Structured nodes/result models:

```python
@dataclass(frozen=True, slots=True)
class StatementNode:
    statement: DecompilerStatement

@dataclass(frozen=True, slots=True)
class LabelNode:
    address: int

@dataclass(frozen=True, slots=True)
class GotoNode:
    target_address: int

@dataclass(frozen=True, slots=True)
class IfNode:
    condition: DecompilerExpression
    then_body: tuple["StructuredNode", ...]
    else_body: tuple["StructuredNode", ...] = ()

@dataclass(frozen=True, slots=True)
class LoopNode:
    condition: DecompilerExpression
    body: tuple["StructuredNode", ...]
    post_test: bool = False

StructuredNode: TypeAlias = StatementNode | LabelNode | GotoNode | IfNode | LoopNode

@dataclass(frozen=True, slots=True)
class StructuredFunction:
    function: DecompiledFunction
    body: tuple[StructuredNode, ...]
    fallback_used: bool

@dataclass(frozen=True, slots=True)
class DecompilationResult:
    ir: DecompiledFunction
    structured: StructuredFunction
    pseudo_c: str
```

Add:

```python
class DecompilerError(NdsToolkitError):
    """Raised when conservative decompilation cannot be completed safely."""
```

`analysis/decompiler/__init__.py` exports the result/model types and, once later tasks define them, `decompile_function` and `render_pseudo_c`. `analysis/__init__.py` re-exports the stable top-level decompiler API.

- [ ] **Step 1: Write RED model/error/export tests**

Create `tests/unit/test_analysis_decompiler_model.py` with validation/equality tests, including provenance and immutable tuple payloads:

```python
def test_source_ref_and_ir_nodes_are_immutable() -> None:
    source = SourceRef(0x02000000, InstructionSet.ARM)
    value = ConstantExpression(7, (source,))
    statement = ReturnStatement(value, (source,))
    assert statement.value == value
    assert statement.source == (source,)


def test_decompiler_error_uses_toolkit_boundary() -> None:
    assert issubclass(DecompilerError, NdsToolkitError)
```

Modify the export test so it asserts that `analysis.DecompilationResult`, `analysis.DecompilerError`, `analysis.DecompiledFunction`, and `analysis.StructuredFunction` resolve to the package-owned types.

- [ ] **Step 2: Run RED tests**

Run:

```bash
python -m pytest tests/unit/test_analysis_decompiler_model.py tests/unit/test_analysis_data_flow_exports.py -v
```

Expected: import/attribute failures because the decompiler package and models do not exist.

- [ ] **Step 3: Implement the models, validation, error, and exports**

Validation rules in `__post_init__`:

```python
if not 0 <= self.address <= 0xFFFFFFFF:
    raise ValueError("source address must be an unsigned 32-bit value")
```

Apply unsigned-32 validation to source/function/call/address/branch addresses, require memory width in `{1, 2, 4}`, require non-empty names/descriptions, require argument variables to carry either register or stack location evidence, require locals to carry a stack offset, and require temporary variables to carry neither stack nor argument location metadata.

- [ ] **Step 4: Run focused GREEN tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_model.py tests/unit/test_analysis_data_flow_exports.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/decompiler src/nds_disassembly_toolkit/errors.py tests/unit/test_analysis_decompiler_model.py
python -m mypy src/nds_disassembly_toolkit/analysis/decompiler src/nds_disassembly_toolkit/errors.py
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/decompiler src/nds_disassembly_toolkit/analysis/__init__.py src/nds_disassembly_toolkit/errors.py tests/unit/test_analysis_decompiler_model.py tests/unit/test_analysis_data_flow_exports.py
git commit -m "feat: add Phase 7I decompiler IR models"
```

---

### Task 2: Component-aware names, arguments, locals, and deterministic temporaries

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/decompiler/names.py`
- Create: `tests/unit/test_analysis_decompiler_names.py`

**Interfaces:**

```python
@dataclass(frozen=True, slots=True)
class NameContext:
    function_name: str
    parameters: tuple[DecompilerVariable, ...]
    locals: tuple[DecompilerVariable, ...]
    register_arguments: tuple[tuple[Register, DecompilerVariable], ...]
    stack_arguments: tuple[tuple[int, DecompilerVariable], ...]
    stack_locals: tuple[tuple[int, DecompilerVariable], ...]

class TemporaryAllocator:
    def for_definition(self, address: int, register: Register) -> DecompilerVariable: ...
    def variables(self) -> tuple[DecompilerVariable, ...]: ...

def sanitize_identifier(value: str) -> str: ...

def build_name_context(
    project: AnalysisProject,
    function: FunctionCandidate,
    flow: FunctionDataFlow,
) -> NameContext: ...

@dataclass(frozen=True, slots=True)
class ResolvedCallTarget:
    name: str
    address: int
    instruction_set: InstructionSet
    component: str | None
    parameter_registers: tuple[Register, ...]

def resolve_call_target(
    project: AnalysisProject,
    *,
    current_component: str,
    address: int,
    instruction_set: InstructionSet,
) -> ResolvedCallTarget: ...
```

Naming rules:

```text
function annotation name_override
  -> matching same-component function Symbol
  -> sub_XXXXXXXX

register arguments ordered by summary argument index -> arg0, arg1, ...
stack arguments ordered by entry-SP offset -> arg_stack_00, arg_stack_04, ...
LOCAL stack slots ordered by offset -> local_04, local_08, ...
temporaries allocated by deterministic block/instruction traversal -> tmp_0, tmp_1, ...
```

Sanitization:

```python
_IDENTIFIER = re.compile(r"[^0-9A-Za-z_]")

value = _IDENTIFIER.sub("_", value.strip())
if not value:
    value = "unnamed"
if value[0].isdigit():
    value = "_" + value
```

Use a small C keyword set (`if`, `else`, `while`, `return`, `goto`, `void`, `uint32_t`, `uint16_t`, `uint8_t`, `int32_t`) and append `_` when a sanitized name collides with one of them. Resolve collisions between parameter/local names by suffixing `_2`, `_3`, ... in stable creation order.

Call-target resolution must iterate `project.component_identities()` in returned stable order and exact-query each component with `project.function(component, address, instruction_set)`. Exactly one match may carry a component/symbol/annotation name. Zero or multiple matches return `component=None` and fallback `sub_XXXXXXXX`. If the unique target has persisted data flow with a summary, recover only register arguments whose summary kind is `REGISTER`; otherwise `parameter_registers=()`.

- [ ] **Step 1: Write RED naming tests**

Use a synthetic `.ndsre` fixture with `arm9`, `overlay_3`, and `overlay_7` sharing an overlay runtime address. Assert:

```python
def test_function_name_prefers_user_annotation(tmp_path: Path) -> None:
    with _named_project(tmp_path) as project:
        context = build_name_context(project, _function(), _flow())
    assert context.function_name == "UserEntry"


def test_ambiguous_overlay_call_target_is_not_guessed(tmp_path: Path) -> None:
    with _overlapping_project(tmp_path) as project:
        target = resolve_call_target(
            project,
            current_component="arm9",
            address=0x02200000,
            instruction_set=InstructionSet.THUMB,
        )
    assert target.component is None
    assert target.name == "sub_02200000"
```

Also assert deterministic argument/local/temp names and collision suffixes.

- [ ] **Step 2: Run RED tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_names.py -v
```

Expected: import failure for `analysis.decompiler.names`.

- [ ] **Step 3: Implement name resolution and temporary allocation**

Do not add SQL or new `AnalysisProject` APIs. Use only `annotation`, `symbols_at`, `component_identities`, `function`, and `data_flow`.

- [ ] **Step 4: Run focused GREEN tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_names.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/decompiler/names.py tests/unit/test_analysis_decompiler_names.py
python -m mypy src/nds_disassembly_toolkit/analysis/decompiler/names.py
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/decompiler/names.py tests/unit/test_analysis_decompiler_names.py
git commit -m "feat: add deterministic decompiler naming"
```

---

### Task 3: Core ARM/Thumb expression lifting and branch conditions

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/decompiler/lift.py`
- Create: `tests/unit/test_analysis_decompiler_lift.py`

**Interfaces:**

```python
def lift_function(
    project: AnalysisProject,
    function: FunctionCandidate,
    cfg: FunctionControlFlowGraph,
    flow: FunctionDataFlow,
    names: NameContext,
) -> DecompiledFunction: ...
```

Internal helpers:

```python
def _source(instruction: DecodedInstruction) -> tuple[SourceRef, ...]: ...
def _flow_state(flow: FunctionDataFlow, address: int) -> InstructionFlowState | None: ...
def _abstract_expression(value: AbstractValue, source: tuple[SourceRef, ...]) -> DecompilerExpression | None: ...
def _register_expression(..., state: InstructionFlowState, register: Register, names: NameContext, temporaries: TemporaryAllocator) -> DecompilerExpression: ...
def _operand_expression(..., operand: InstructionOperand, state: InstructionFlowState, ...) -> DecompilerExpression: ...
```

Initial supported scalar instructions:

```text
mov
mvn
add
sub
mul
and
orr
eor
lsl / lsl aliases represented by typed shifts
lsr
asr
cmp
tst
conditional/unconditional direct branch
```

Rules:

- Prefer a proven `AbstractValue.CONSTANT`/`ADDRESS` from `state.before` for register reads.
- At an address listed in a register `ArgumentEvidence.uses`, render that entry register as its recovered argument variable before falling back to raw register.
- Within one block, a supported write may allocate `tmp_N`; later reads in the same block may use that temp. Do not carry temp identity across CFG joins unless existing exact abstract-value evidence proves a constant/address.
- Destination register writes to known argument registers do not rename the argument itself; once overwritten, use a temp/raw-register target.
- `cmp` and `tst` do not emit standalone statements. Record a pending compare source for the next conditional branch in the same block.
- `tst lhs, rhs` becomes a comparison of `(lhs & rhs)` against zero.
- Branch conditions use `CompareExpression` with the branch instruction's persisted `ConditionCode`.
- If no safe compare source exists for a conditional branch, use `UnknownExpression("condition_<cc>", source)` rather than invent operands.
- Direct unconditional branches use `BranchStatement(condition=None, ...)`.

- [ ] **Step 1: Write RED scalar/branch tests**

Create synthetic ARM and Thumb fixtures by constructing persisted toolkit-owned instructions/flow directly. Required assertions:

```python
def test_arm_mov_add_cmp_branch_lifts_without_operand_string_parsing(...) -> None:
    lifted = lift_function(project, function, cfg, flow, names)
    assert isinstance(lifted.blocks[0].statements[0], AssignmentStatement)
    branch = lifted.blocks[0].statements[-1]
    assert isinstance(branch, BranchStatement)
    assert isinstance(branch.condition, CompareExpression)
    assert branch.condition.condition is ConditionCode.EQ


def test_thumb_scalar_lifting_uses_same_ir(...) -> None:
    assert lifted.instruction_set is InstructionSet.THUMB
    assert any(isinstance(item, AssignmentStatement) for item in lifted.blocks[0].statements)
```

Set deliberately misleading `DecodedInstruction.operands` strings in one fixture and assert output still follows `InstructionSemantics`, proving the lifter never parses display text.

- [ ] **Step 2: Run RED tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_lift.py -k "scalar or branch or thumb" -v
```

Expected: import failure for `lift_function`.

- [ ] **Step 3: Implement scalar lifting minimally**

Use a dispatch table keyed by normalized mnemonic base (`instruction.mnemonic.lower().split(".", 1)[0]`) only to select the transfer rule. Read operands exclusively from `instruction.semantics.operands`.

- [ ] **Step 4: Run focused GREEN tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_lift.py -k "scalar or branch or thumb" -v
python -m ruff check src/nds_disassembly_toolkit/analysis/decompiler/lift.py tests/unit/test_analysis_decompiler_lift.py
python -m mypy src/nds_disassembly_toolkit/analysis/decompiler/lift.py
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/decompiler/lift.py tests/unit/test_analysis_decompiler_lift.py
git commit -m "feat: lift scalar operations into decompiler IR"
```

---

### Task 4: Stack locals, memory operations, direct calls, returns, and fallback IR

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/decompiler/lift.py`
- Modify: `tests/unit/test_analysis_decompiler_lift.py`

**Interfaces:**

Add internal helpers:

```python
def _entry_stack_offset(
    operand: InstructionOperand,
    stack: StackState | None,
) -> int | None: ...

def _memory_address_expression(
    operand: InstructionOperand,
    state: InstructionFlowState,
    ...,
) -> DecompilerExpression: ...

def _return_expression(
    flow: FunctionDataFlow,
    state: InstructionFlowState,
    ...,
) -> DecompilerExpression | None: ...
```

Rules:

- Reuse the same entry-SP/frame-pointer arithmetic as existing stack evidence: SP base + `stack_before.offset` + displacement; frame-pointer base + `stack_before.frame_offset(base)` + displacement. Do not call `analyze_stack()` again.
- If that exact entry-relative offset matches a recovered local, `ldr` becomes assignment from `VariableExpression(local)` and `str` becomes assignment to the local variable.
- If it matches an incoming stack argument, reads become `VariableExpression(arg_stack_XX)`.
- Non-stack loads use `MemoryReadExpression(address, width)`; non-stack stores use `MemoryWriteStatement(address, value, width, source)`.
- Address calculation accepts base/index/displacement only from typed `MemoryOperand`; unsupported indexed/writeback combinations that cannot be represented conservatively become explicit fallback statements.
- Direct `CALL` instructions with `direct_target` use `resolve_call_target()`. Populate call arguments only for persisted target summaries that prove register parameters; read each argument from callsite `state.before`.
- An unresolved/indirect call becomes `UnknownStatement("unresolved call: <mnemonic> <operands>", source)`; this is the one fallback path allowed to include the original display string for human evidence, never for semantics.
- Return instructions use exact `FunctionSummary.returns` evidence at the same instruction address. Known value -> corresponding expression; unknown value -> `RegisterExpression(Register.R0)`; no return-value evidence -> `ReturnStatement(None, source)`.
- Any unsupported ordinary instruction becomes `UnknownStatement("unresolved instruction: <mnemonic> <operands>", source)`.
- Append one stable warning per unsupported instruction using lowercase canonical address text, sorted by instruction address.

- [ ] **Step 1: Extend RED lifting tests**

Add contracts for:

```python
def test_stack_local_load_store_uses_recovered_local_name(...): ...
def test_direct_call_uses_unique_target_symbol_and_proven_register_args(...): ...
def test_ambiguous_overlay_call_keeps_structural_fallback_name(...): ...
def test_return_uses_persisted_return_evidence(...): ...
def test_unsupported_instruction_remains_visible(...): ...
```

The unsupported fixture should assert both `UnknownStatement` and a warning containing the exact instruction address.

- [ ] **Step 2: Run RED tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_lift.py -k "stack or memory or call or return or unsupported" -v
```

Expected: failures because the current lifter does not implement these rules.

- [ ] **Step 3: Implement the memory/call/return/fallback rules**

Keep the lifter single-pass per block in deterministic CFG block order. No whole-program traversal is introduced.

- [ ] **Step 4: Run the complete lifter test file**

```bash
python -m pytest tests/unit/test_analysis_decompiler_lift.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/decompiler/lift.py tests/unit/test_analysis_decompiler_lift.py
python -m mypy src/nds_disassembly_toolkit/analysis/decompiler/lift.py
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/decompiler/lift.py tests/unit/test_analysis_decompiler_lift.py
git commit -m "feat: lift memory calls and returns conservatively"
```

---

### Task 5: Safe straight-line, if, if/else, and early-return structuring

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/decompiler/structure.py`
- Create: `tests/unit/test_analysis_decompiler_structure.py`

**Interfaces:**

```python
def structure_function(function: DecompiledFunction) -> StructuredFunction: ...
```

Internal graph helpers:

```python
def _block_map(function: DecompiledFunction) -> dict[int, DecompiledBlock]: ...
def _local_edges(block: DecompiledBlock, blocks: dict[int, DecompiledBlock]) -> tuple[CFGEdge, ...]: ...
def _incoming_counts(function: DecompiledFunction) -> dict[int, int]: ...
def _branch_statement(block: DecompiledBlock) -> BranchStatement | None: ...
```

Initial safe patterns:

1. **Straight line:** one local fallthrough edge and target has exactly one incoming edge -> emit current non-branch statements then continue target.
2. **If:** conditional block has `BRANCH -> then` and `FALLTHROUGH -> join`; `then` has one local successor `join`; `join` has no other predecessor from the candidate region.
3. **If/else:** conditional block has `BRANCH -> then`, `FALLTHROUGH -> else`; both `then` and `else` have exactly one local successor to the same `join`.
4. **Early return:** one conditional successor is a block that terminates in `ReturnStatement` with no local successors; the other successor continues normally.

The `CFGEdgeKind.BRANCH` edge is the taken branch. `CFGEdgeKind.FALLTHROUGH` is the not-taken path. Never infer path polarity from numeric addresses.

If a pattern fails these exact safety checks, emit:

```text
LabelNode(block.address)
StatementNode(non-branch statements...)
GotoNode(target) for each unresolved local transfer in deterministic target order
```

and set `fallback_used=True`.

- [ ] **Step 1: Write RED structuring tests**

Manually build tiny `DecompiledFunction` fixtures so the structurer is tested independently of lifting:

```python
def test_diamond_becomes_if_else() -> None:
    structured = structure_function(_diamond_function())
    node = next(item for item in structured.body if isinstance(item, IfNode))
    assert node.then_body
    assert node.else_body
    assert structured.fallback_used is False


def test_unstructured_multi_entry_region_uses_labels_and_gotos() -> None:
    structured = structure_function(_multi_entry_function())
    assert structured.fallback_used is True
    assert any(isinstance(item, GotoNode) for item in structured.body)
```

- [ ] **Step 2: Run RED tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_structure.py -k "straight or if or early or unstructured" -v
```

Expected: import failure for `structure_function`.

- [ ] **Step 3: Implement only the listed safe patterns**

Track consumed block addresses in a set. If any block would be emitted twice, abandon that local structure and use labels/gotos for the affected region.

- [ ] **Step 4: Run focused GREEN tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_structure.py -k "straight or if or early or unstructured" -v
python -m ruff check src/nds_disassembly_toolkit/analysis/decompiler/structure.py tests/unit/test_analysis_decompiler_structure.py
python -m mypy src/nds_disassembly_toolkit/analysis/decompiler/structure.py
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/decompiler/structure.py tests/unit/test_analysis_decompiler_structure.py
git commit -m "feat: structure conservative conditional control flow"
```

---

### Task 6: Natural simple-loop structuring with dominance checks

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/decompiler/structure.py`
- Modify: `tests/unit/test_analysis_decompiler_structure.py`

**Interfaces:**

Add:

```python
def _dominators(function: DecompiledFunction) -> dict[int, frozenset[int]]: ...
def _back_edges(function: DecompiledFunction) -> tuple[CFGEdge, ...]: ...
```

Compute dominators only over local branch/fallthrough edges; call edges are excluded. Entry dominator set is `{entry}`. Other blocks initialize to all local blocks and iterate intersections in sorted address order until stable.

An edge `latch -> header` is a natural back edge only when `header` dominates `latch`.

Supported loop shapes:

- **Pre-test loop:** header ends with conditional branch; one successor is loop exit, the other enters a body region whose single-exit path reaches a latch that returns to header. No body block may have an incoming edge from outside `{header + body + latch}`.
- **Post-test loop:** latch ends with conditional branch back to a dominating header and one fallthrough exit; the body region from header to latch is single-entry.

Render these as `LoopNode(condition, body, post_test=False/True)`. If a back edge exists but the region is multi-entry, has multiple back edges, or cannot prove one exit, keep labels/gotos and `fallback_used=True`.

- [ ] **Step 1: Add RED loop tests**

```python
def test_simple_pretest_loop_structures() -> None:
    structured = structure_function(_pretest_loop_function())
    loop = next(item for item in structured.body if isinstance(item, LoopNode))
    assert loop.post_test is False
    assert structured.fallback_used is False


def test_irreducible_back_edges_fall_back() -> None:
    structured = structure_function(_irreducible_function())
    assert structured.fallback_used is True
    assert any(isinstance(item, GotoNode) for item in structured.body)
```

- [ ] **Step 2: Run RED loop tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_structure.py -k "loop or irreducible" -v
```

Expected: failures because loop recognition is not implemented.

- [ ] **Step 3: Implement dominators and simple natural loops**

Do not generalize into a graph framework. Keep the algorithm local to Phase 7I structuring.

- [ ] **Step 4: Run the complete structurer tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_structure.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/decompiler/structure.py tests/unit/test_analysis_decompiler_structure.py
python -m mypy src/nds_disassembly_toolkit/analysis/decompiler/structure.py
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/decompiler/structure.py tests/unit/test_analysis_decompiler_structure.py
git commit -m "feat: structure simple natural loops"
```

---

### Task 7: Deterministic pseudo-C renderer and read-only decompilation service

**Files:**
- Create: `src/nds_disassembly_toolkit/analysis/decompiler/render.py`
- Create: `src/nds_disassembly_toolkit/analysis/decompiler/service.py`
- Modify: `src/nds_disassembly_toolkit/analysis/decompiler/__init__.py`
- Modify: `src/nds_disassembly_toolkit/analysis/__init__.py`
- Create: `tests/unit/test_analysis_decompiler_render.py`
- Create: `tests/unit/test_analysis_decompiler_service.py`

**Interfaces:**

```python
def render_pseudo_c(value: StructuredFunction | DecompilationResult) -> str: ...

def decompile_function(
    project: AnalysisProject,
    component: str,
    address: int,
    instruction_set: InstructionSet,
) -> DecompilationResult: ...
```

Service sequence:

```python
function = project.function(component, address, instruction_set)
if function is None:
    raise DecompilerError(...)
cfg = project.cfg(component, address, instruction_set)
if cfg is None:
    raise DecompilerError(...)
flow = project.data_flow(component, address, instruction_set)
if flow is None:
    raise DecompilerError(...)
names = build_name_context(project, function, flow)
ir = lift_function(project, function, cfg, flow, names)
structured = structure_function(ir)
pseudo_c = render_pseudo_c(structured)
return DecompilationResult(ir, structured, pseudo_c)
```

Renderer policy:

- Function return type is `uint32_t` if any rendered `ReturnStatement` has a value, otherwise `void`.
- Recovered parameters use `uint32_t <name>`; do not invent pointer/struct types for parameters.
- Locals/temporaries are declared as `uint32_t` in deterministic variable order.
- `ConstantExpression` renders decimal for `0..9`, otherwise lowercase hex `0x...`.
- `AddressExpression` renders canonical lowercase hex; memory reads/writes cast based only on persisted access width:
  - width 1 -> `uint8_t`
  - width 2 -> `uint16_t`
  - width 4 -> `uint32_t`
- Signed/unsigned branch semantics are explicit from `ConditionCode` rather than inferred types:
  - `eq/ne` -> `==` / `!=`
  - `hs/lo/hi/ls` -> cast both sides to `uint32_t`
  - `ge/lt/gt/le` -> cast both sides to `int32_t`
  - flag conditions without a safe scalar comparison render `condition_<cc>(...)`.
- Unknown expressions render `unknown_expr("...")`; unknown statements render comments with exact source address.
- Labels are `loc_XXXXXXXX:`; gotos are `goto loc_XXXXXXXX;`.
- Text ends with exactly one newline.
- Indent is four spaces; braces are stable K&R-style.

- [ ] **Step 1: Write RED renderer snapshots**

```python
def test_renderer_is_byte_deterministic() -> None:
    first = render_pseudo_c(_structured_fixture())
    second = render_pseudo_c(_structured_fixture())
    assert first == second
    assert first.endswith("\n")
    assert "uint32_t arg0" in first
    assert "if (" in first


def test_unknown_instruction_is_visible() -> None:
    rendered = render_pseudo_c(_structured_with_unknown())
    assert "unresolved instruction" in rendered
    assert "0x02000004" in rendered
```

- [ ] **Step 2: Write RED service/error/read-only tests**

Create a real temporary `.ndsre`, reopen it read-only, and call `decompile_function`. Also assert exact errors for missing function, missing CFG, and missing data flow.

```python
with AnalysisProject.open(root, read_only=True) as project:
    result = decompile_function(project, "arm9", BASE, InstructionSet.ARM)
assert result.pseudo_c
```

- [ ] **Step 3: Run RED tests**

```bash
python -m pytest tests/unit/test_analysis_decompiler_render.py tests/unit/test_analysis_decompiler_service.py -v
```

Expected: imports fail because renderer/service do not exist.

- [ ] **Step 4: Implement renderer and service**

Do not open/close projects inside `decompile_function`; ownership stays with the caller. This makes read-only behavior explicit and testable.

- [ ] **Step 5: Run focused GREEN tests and public exports**

```bash
python -m pytest tests/unit/test_analysis_decompiler_render.py tests/unit/test_analysis_decompiler_service.py tests/unit/test_analysis_data_flow_exports.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/decompiler tests/unit/test_analysis_decompiler_render.py tests/unit/test_analysis_decompiler_service.py
python -m mypy src/nds_disassembly_toolkit/analysis/decompiler
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/decompiler src/nds_disassembly_toolkit/analysis/__init__.py tests/unit/test_analysis_decompiler_render.py tests/unit/test_analysis_decompiler_service.py tests/unit/test_analysis_data_flow_exports.py
git commit -m "feat: render conservative pseudo-c decompilation"
```

---

### Task 8: `project decompile` text/JSON CLI integration

**Files:**
- Modify: `src/nds_disassembly_toolkit/analysis/project_cli.py`
- Modify: `tests/unit/test_analysis_project_cli.py`

**Interfaces:**

Parser:

```python
decompile_parser = commands.add_parser(
    "decompile", help="render conservative pseudo-C for one persisted function"
)
decompile_parser.add_argument("project", type=Path)
decompile_parser.add_argument("component")
decompile_parser.add_argument("address", type=_auto_int)
decompile_parser.add_argument("--mode", required=True, type=_instruction_set)
decompile_parser.add_argument(
    "--format",
    choices=("text", "json"),
    default="text",
)
_add_output_argument(decompile_parser)
```

Add atomic text writer beside the existing JSON writer:

```python
def _write_text(rendered: str, output: Path | None) -> None:
    if not rendered.endswith("\n"):
        rendered += "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(output)
```

Handler:

```python
def _run_decompile(arguments: argparse.Namespace) -> int:
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        result = decompile_function(
            project,
            arguments.component,
            arguments.address,
            arguments.mode,
        )
    if arguments.format == "text":
        _write_text(result.pseudo_c, arguments.output)
        return 0
    _write_json(_decompilation_json(result), arguments.output)
    return 0
```

JSON shape is intentionally small and stable rather than serializing every IR implementation detail:

```json
{
  "address": "0x02000000",
  "component": "arm9",
  "fallback_used": false,
  "instruction_set": "arm",
  "name": "UserEntry",
  "pseudo_c": "...\n",
  "warnings": []
}
```

`_decompilation_json()` derives these fields from `result.ir` / `result.structured`. Addresses use existing `_hex()`.

- [ ] **Step 1: Add RED parser/default-format tests**

Assert `--mode` is required, only ARM/Thumb accepted, only `text|json` accepted, and default is text.

- [ ] **Step 2: Add RED read-only/text/JSON/output tests**

Reuse `_deep_project()` or add a decompilable synthetic fixture with CFG+flow. Assert:

```python
assert main(["project", "decompile", str(root), "arm9", hex(BASE), "--mode", "arm"]) == 0
assert "UserEntry" in capsys.readouterr().out

assert main([
    "project", "decompile", str(root), "arm9", hex(BASE),
    "--mode", "arm", "--format", "json",
]) == 0
payload = json.loads(capsys.readouterr().out)
assert payload["component"] == "arm9"
assert payload["instruction_set"] == "arm"
assert payload["pseudo_c"].endswith("\n")
```

Monkeypatch `project_cli.AnalysisProject.open` as existing query tests do and assert the decompile handler calls it exactly once with `read_only=True`.

For `--output`, precreate a destination file, run text and JSON forms, and assert no `.tmp` file remains.

- [ ] **Step 3: Run RED CLI tests**

```bash
python -m pytest tests/unit/test_analysis_project_cli.py -k decompile -v
```

Expected: parser/dispatch failures because `decompile` is not registered.

- [ ] **Step 4: Implement the parser, text writer, serializer, handler, and dispatch**

Add to `run_project_command()`:

```python
if arguments.project_command == "decompile":
    return _run_decompile(arguments)
```

Do not change `src/nds_disassembly_toolkit/cli.py`; its existing project dispatch and `NdsToolkitError` mapping already cover `DecompilerError`.

- [ ] **Step 5: Run complete project CLI regression**

```bash
python -m pytest tests/unit/test_analysis_project_cli.py -v
python -m ruff check src/nds_disassembly_toolkit/analysis/project_cli.py tests/unit/test_analysis_project_cli.py
python -m mypy src/nds_disassembly_toolkit/analysis/project_cli.py
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/nds_disassembly_toolkit/analysis/project_cli.py tests/unit/test_analysis_project_cli.py
git commit -m "feat: expose pseudo-c through project cli"
```

---

### Task 9: Documentation, provenance, scope audit, final verification, PR, merge, and post-merge proof

**Files:**
- Modify: `docs/disassembly-and-analysis.md`
- Modify: `docs/provenance-and-licenses.md`
- Modify: `README.md`
- Audit only: `pyproject.toml`
- Audit only: `src/nds_disassembly_toolkit/analysis/project/schema.py`
- Audit only: `.github/workflows/ci.yml`

**Interfaces:**

Document the public workflow:

```bash
nds-toolkit project decompile GAME.ndsre arm9 0x02012340 --mode arm
nds-toolkit project decompile GAME.ndsre arm9 0x02012340 --mode arm --format json
nds-toolkit project decompile GAME.ndsre overlay_7 0x02200000 --mode thumb --output function.c
```

State explicitly that output is evidence-backed pseudo-C, not guaranteed recompilable C; unresolved instructions remain visible; overlays stay component-aware; no pseudo-C is persisted; Phase 7H runtime evidence remains separate; Phase 7J is the later broader investigation/evidence-fusion phase.

Provenance text must record:

- Phase 7I is independently authored from toolkit-owned models.
- Capstone remains confined to the existing decoder.
- angr remains reference material only.
- no Ghidra/RetDec/other decompiler source is copied/vendor incorporated.
- no new runtime dependency or `.ndsre` migration was added.

README capability bullet becomes materially similar to:

```text
- conservative evidence-backed ARM/Thumb pseudo-C generation from persisted CFG/data-flow/stack/ABI/symbol evidence, with safe control-flow structuring and visible fallback for uncertainty;
```

- [ ] **Step 1: Add documentation/provenance updates**

Make the above changes without changing implementation behavior.

- [ ] **Step 2: Run focused decompiler tests**

```bash
python -m pytest \
  tests/unit/test_analysis_decompiler_model.py \
  tests/unit/test_analysis_decompiler_names.py \
  tests/unit/test_analysis_decompiler_lift.py \
  tests/unit/test_analysis_decompiler_structure.py \
  tests/unit/test_analysis_decompiler_render.py \
  tests/unit/test_analysis_decompiler_service.py \
  tests/unit/test_analysis_project_cli.py -v
```

Expected: all pass.

- [ ] **Step 3: Run the full repository gate**

```bash
python -m pytest -v
python -m ruff check .
python -m mypy src/nds_disassembly_toolkit
```

Expected: all pass.

- [ ] **Step 4: Run scope/provenance/schema/dependency audit**

```bash
git diff main...HEAD -- pyproject.toml
git diff main...HEAD -- src/nds_disassembly_toolkit/analysis/project/schema.py
git diff main...HEAD -- src/nds_disassembly_toolkit/analysis/runtime
git grep -n -E "Bakugan|B6RE|G-Power|gates/" -- src tests docs ':!docs/superpowers/*'
git grep -n -E "import capstone|from capstone" -- src/nds_disassembly_toolkit/analysis/decompiler || true
git grep -n -E "import angr|from angr|ghidra|retdec" -- src/nds_disassembly_toolkit/analysis/decompiler || true
```

Expected:

```text
pyproject diff: empty
project/schema.py diff: empty
analysis/runtime diff: empty
game-specific production/test matches: none
Capstone imports in decompiler: none
angr/Ghidra/RetDec implementation imports in decompiler: none
```

Documentation may mention external projects only in provenance/history context; inspect any grep hit rather than deleting legitimate provenance text.

- [ ] **Step 5: Verify branch file scope**

```bash
git diff --name-status main...HEAD
```

Expected changed production files are limited to the new `analysis/decompiler/` package, `analysis/__init__.py`, `errors.py`, `analysis/project_cli.py`, tests, README/docs/spec/plan. No project schema, decoder, data-flow, runtime, compression, ROM, workspace, patch, or game-specific implementation file should be changed.

- [ ] **Step 6: Commit final documentation**

```bash
git add README.md docs/disassembly-and-analysis.md docs/provenance-and-licenses.md
git commit -m "docs: document Phase 7I pseudo-c workflow"
```

- [ ] **Step 7: Open/update the Phase 7I PR and require exact-head CI**

PR title:

```text
Phase 7I: conservative pseudo-C decompiler
```

PR body must summarize architecture, conservative fallback policy, no-schema/no-dependency boundary, ARM+Thumb coverage, control-flow structures, CLI formats, and exact verification results.

Do not mark ready or merge while the head SHA is changing or checks are pending.

- [ ] **Step 8: Require stock-melonDS CI to remain green**

The existing `phase-7h-live-smoke` job must pass unchanged. Phase 7I adds no live-emulator test behavior.

- [ ] **Step 9: Review exact PR diff before merge**

Confirm:

```text
no .ndsre schema migration
no runtime dependency change
no second decoder/Capstone integration
no runtime subsystem change
no game-specific policy
no pseudo-C persistence
no copied external decompiler implementation
```

- [ ] **Step 10: Squash merge with expected-head protection**

Use the exact verified PR head SHA. Squash title:

```text
Phase 7I: conservative pseudo-C decompiler (#<PR>)
```

- [ ] **Step 11: Require fresh post-merge `main` CI on the squash commit**

Verify the push-triggered workflow head SHA equals the new `main` squash SHA and that:

```text
pytest: success
Ruff: success
strict mypy: success
stock melonDS live smoke: success
```

Only after this exact squash commit is green is Phase 7I complete.
