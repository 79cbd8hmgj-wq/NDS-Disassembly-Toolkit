from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.lower import lower_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    BinaryExpression,
    BinaryOperator,
    BranchStatement,
    CallExpression,
    CallStatement,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    DecompilerVariable,
    DecompilerVariableKind,
    MemoryWriteStatement,
    RegisterExpression,
    ReturnStatement,
    SourceRef,
    UnknownStatement,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.simplify import simplify_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.ssa import build_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.structure import structure_function
from nds_disassembly_toolkit.analysis.model import (
    CFGEdge,
    CFGEdgeKind,
    InstructionSet,
    Register,
)

BASE = 0x02005000


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _pipeline(function: DecompiledFunction) -> DecompiledFunction:
    ssa = build_ssa_function(function)
    simplified = simplify_ssa_function(ssa).function
    return lower_ssa_function(simplified)


def test_lowering_removes_internal_ssa_versions_from_straight_line_code() -> None:
    arg = DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )
    source = _source()
    expression = BinaryExpression(
        BinaryOperator.ADD,
        VariableExpression(arg, source),
        ConstantExpression(4, source),
        source,
    )
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "lower_me",
        (arg,),
        (),
        (
            DecompiledBlock(
                BASE,
                InstructionSet.ARM,
                (
                    AssignmentStatement(
                        RegisterExpression(Register.R1, source),
                        expression,
                        source,
                    ),
                    ReturnStatement(
                        RegisterExpression(Register.R1, _source(BASE + 4)),
                        _source(BASE + 4),
                    ),
                ),
                (),
            ),
        ),
    )

    lowered = _pipeline(function)
    statements = lowered.blocks[0].statements

    assert len(statements) == 1
    returned = statements[0]
    assert isinstance(returned, ReturnStatement)
    assert isinstance(returned.value, BinaryExpression)
    assert isinstance(returned.value.left, VariableExpression)
    assert returned.value.left.variable.name == "arg0"
    assert ".0" not in repr(lowered)
    assert ".1" not in repr(lowered)


def test_residual_phi_lowers_back_to_storage_semantics() -> None:
    then_address = BASE + 4
    else_address = BASE + 8
    join = BASE + 12
    entry = DecompiledBlock(
        BASE,
        InstructionSet.ARM,
        (),
        (
            CFGEdge(BASE, BASE, then_address, InstructionSet.ARM, CFGEdgeKind.BRANCH),
            CFGEdge(BASE, BASE, else_address, InstructionSet.ARM, CFGEdgeKind.FALLTHROUGH),
        ),
    )

    def branch(address: int, value: int) -> DecompiledBlock:
        source = _source(address)
        return DecompiledBlock(
            address,
            InstructionSet.ARM,
            (
                AssignmentStatement(
                    RegisterExpression(Register.R0, source),
                    ConstantExpression(value, source),
                    source,
                ),
            ),
            (
                CFGEdge(
                    address,
                    address,
                    join,
                    InstructionSet.ARM,
                    CFGEdgeKind.FALLTHROUGH,
                ),
            ),
        )

    join_source = _source(join)
    joined = DecompiledBlock(
        join,
        InstructionSet.ARM,
        (
            ReturnStatement(
                RegisterExpression(Register.R0, join_source),
                join_source,
            ),
        ),
        (),
    )
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "phi_lower",
        (),
        (),
        (entry, branch(then_address, 1), branch(else_address, 2), joined),
    )

    lowered = _pipeline(function)

    assert isinstance(lowered.blocks[1].statements[0], AssignmentStatement)
    assert isinstance(lowered.blocks[2].statements[0], AssignmentStatement)
    returned = lowered.blocks[3].statements[0]
    assert isinstance(returned, ReturnStatement)
    assert isinstance(returned.value, RegisterExpression)
    assert returned.value.register is Register.R0


def test_loop_edges_survive_lowering_and_remain_structurable() -> None:
    header = BASE
    body = BASE + 4
    exit_address = BASE + 8
    source = _source(header)
    header_block = DecompiledBlock(
        header,
        InstructionSet.ARM,
        (
            BranchStatement(
                RegisterExpression(Register.R1, source),
                body,
                InstructionSet.ARM,
                source,
            ),
        ),
        (
            CFGEdge(header, header, body, InstructionSet.ARM, CFGEdgeKind.BRANCH),
            CFGEdge(
                header,
                header,
                exit_address,
                InstructionSet.ARM,
                CFGEdgeKind.FALLTHROUGH,
            ),
        ),
    )
    body_source = _source(body)
    body_block = DecompiledBlock(
        body,
        InstructionSet.ARM,
        (
            AssignmentStatement(
                RegisterExpression(Register.R0, body_source),
                BinaryExpression(
                    BinaryOperator.ADD,
                    RegisterExpression(Register.R0, body_source),
                    ConstantExpression(1, body_source),
                    body_source,
                ),
                body_source,
            ),
        ),
        (
            CFGEdge(
                body,
                body,
                header,
                InstructionSet.ARM,
                CFGEdgeKind.BRANCH,
            ),
        ),
    )
    exit_source = _source(exit_address)
    exit_block = DecompiledBlock(
        exit_address,
        InstructionSet.ARM,
        (ReturnStatement(RegisterExpression(Register.R0, exit_source), exit_source),),
        (),
    )
    function = DecompiledFunction(
        "arm9",
        header,
        InstructionSet.ARM,
        "loop_lower",
        (),
        (),
        (header_block, body_block, exit_block),
    )

    lowered = _pipeline(function)
    structured = structure_function(lowered)

    assert lowered.blocks[1].edges[0].target_address == header
    assert structured.function == lowered


def test_unknown_statement_survives_lowering() -> None:
    source = _source()
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "unknown_lower",
        (),
        (),
        (
            DecompiledBlock(
                BASE,
                InstructionSet.ARM,
                (
                    UnknownStatement("still unknown", source),
                    ReturnStatement(None, _source(BASE + 4)),
                ),
                (),
            ),
        ),
    )

    lowered = _pipeline(function)

    assert isinstance(lowered.blocks[0].statements[0], UnknownStatement)


def test_memory_side_effect_order_survives_lowering() -> None:
    source = _source()
    address = RegisterExpression(Register.R1, source)
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "memory_lower",
        (),
        (),
        (
            DecompiledBlock(
                BASE,
                InstructionSet.ARM,
                (
                    MemoryWriteStatement(
                        address,
                        ConstantExpression(1, source),
                        4,
                        source,
                    ),
                    MemoryWriteStatement(
                        address,
                        ConstantExpression(2, _source(BASE + 4)),
                        4,
                        _source(BASE + 4),
                    ),
                    ReturnStatement(None, _source(BASE + 8)),
                ),
                (),
            ),
        ),
    )

    lowered = _pipeline(function)
    statements = lowered.blocks[0].statements

    assert isinstance(statements[0], MemoryWriteStatement)
    assert isinstance(statements[1], MemoryWriteStatement)
    assert statements[0].value.value == 1  # type: ignore[union-attr]
    assert statements[1].value.value == 2  # type: ignore[union-attr]



def test_unknown_call_clobber_lowers_back_to_register_storage() -> None:
    source0 = _source(BASE)
    call_source = _source(BASE + 4)
    return_source = _source(BASE + 8)
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "call_return",
        (),
        (),
        (
            DecompiledBlock(
                BASE,
                InstructionSet.ARM,
                (
                    AssignmentStatement(
                        RegisterExpression(Register.R0, source0),
                        ConstantExpression(7, source0),
                        source0,
                    ),
                    CallStatement(
                        CallExpression(
                            "unknown_call",
                            0x02004000,
                            InstructionSet.ARM,
                            None,
                            (),
                            call_source,
                        ),
                        call_source,
                    ),
                    ReturnStatement(
                        RegisterExpression(Register.R0, return_source),
                        return_source,
                    ),
                ),
                (),
            ),
        ),
    )

    lowered = _pipeline(function)
    returned = lowered.blocks[0].statements[-1]

    assert isinstance(returned, ReturnStatement)
    assert isinstance(returned.value, RegisterExpression)
    assert returned.value.register is Register.R0
