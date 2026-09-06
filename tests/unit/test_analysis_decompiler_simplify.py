from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    BinaryExpression,
    BinaryOperator,
    CallExpression,
    CallStatement,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    DecompilerVariable,
    DecompilerVariableKind,
    MemoryReadExpression,
    MemoryWriteStatement,
    RegisterExpression,
    ReturnStatement,
    SourceRef,
    UnknownStatement,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.simplify import simplify_ssa_function
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSABinaryExpression,
    SSACallStatement,
    SSAMemoryReadExpression,
    SSAMemoryWriteStatement,
    SSAReferenceExpression,
    SSAReturnStatement,
    build_ssa_function,
)
from nds_disassembly_toolkit.analysis.model import (
    CFGEdge,
    CFGEdgeKind,
    InstructionSet,
    Register,
)

BASE = 0x02003000


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _assign(address: int, register: Register, value: object) -> AssignmentStatement:
    source = _source(address)
    return AssignmentStatement(
        RegisterExpression(register, source),
        value,  # type: ignore[arg-type]
        source,
    )


def _function(
    statements: tuple[object, ...],
    *,
    parameters: tuple[DecompilerVariable, ...] = (),
) -> DecompiledFunction:
    return DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "simplify",
        parameters,
        (),
        (
            DecompiledBlock(
                BASE,
                InstructionSet.ARM,
                statements,  # type: ignore[arg-type]
                (),
            ),
        ),
    )


def _simplify(function: DecompiledFunction):
    return simplify_ssa_function(build_ssa_function(function))


def test_copy_chain_and_constants_collapse_into_return() -> None:
    source = _source()
    function = _function(
        (
            _assign(BASE, Register.R0, ConstantExpression(5, source)),
            _assign(
                BASE + 4,
                Register.R1,
                RegisterExpression(Register.R0, _source(BASE + 4)),
            ),
            ReturnStatement(
                RegisterExpression(Register.R1, _source(BASE + 8)),
                _source(BASE + 8),
            ),
        )
    )

    result = _simplify(function)

    assert result.converged is True
    statements = result.function.blocks[0].statements
    assert len(statements) == 1
    returned = statements[0]
    assert isinstance(returned, SSAReturnStatement)
    assert isinstance(returned.value, ConstantExpression)
    assert returned.value.value == 5


def test_constant_expression_folds() -> None:
    source = _source()
    expression = BinaryExpression(
        BinaryOperator.ADD,
        ConstantExpression(1, source),
        ConstantExpression(2, source),
        source,
    )
    result = _simplify(
        _function(
            (
                _assign(BASE, Register.R0, expression),
                ReturnStatement(
                    RegisterExpression(Register.R0, _source(BASE + 4)),
                    _source(BASE + 4),
                ),
            )
        )
    )

    returned = result.function.blocks[0].statements[0]
    assert isinstance(returned, SSAReturnStatement)
    assert isinstance(returned.value, ConstantExpression)
    assert returned.value.value == 3


def test_single_use_add_chain_reassociates_constants() -> None:
    argument = DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )
    first_source = _source(BASE)
    first = BinaryExpression(
        BinaryOperator.ADD,
        RegisterExpression(Register.R0, first_source),
        ConstantExpression(4, first_source),
        first_source,
    )
    second_source = _source(BASE + 4)
    second = BinaryExpression(
        BinaryOperator.ADD,
        RegisterExpression(Register.R1, second_source),
        ConstantExpression(8, second_source),
        second_source,
    )
    result = _simplify(
        _function(
            (
                _assign(BASE, Register.R1, first),
                _assign(BASE + 4, Register.R2, second),
                ReturnStatement(
                    RegisterExpression(Register.R2, _source(BASE + 8)),
                    _source(BASE + 8),
                ),
            ),
            parameters=(argument,),
        )
    )

    statements = result.function.blocks[0].statements
    assert len(statements) == 1
    returned = statements[0]
    assert isinstance(returned, SSAReturnStatement)
    assert isinstance(returned.value, SSABinaryExpression)
    assert returned.value.operator is BinaryOperator.ADD
    assert isinstance(returned.value.left, SSAReferenceExpression)
    assert returned.value.left.value == result.function.entry_definitions[0]
    assert isinstance(returned.value.right, ConstantExpression)
    assert returned.value.right.value == 12


def test_copy_propagation_can_collapse_phi_with_same_incoming_value() -> None:
    argument = DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )
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

    def copy_block(address: int) -> DecompiledBlock:
        source = _source(address)
        return DecompiledBlock(
            address,
            InstructionSet.ARM,
            (
                AssignmentStatement(
                    RegisterExpression(Register.R1, source),
                    RegisterExpression(Register.R0, source),
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

    joined_source = _source(join)
    joined = DecompiledBlock(
        join,
        InstructionSet.ARM,
        (
            ReturnStatement(
                RegisterExpression(Register.R1, joined_source),
                joined_source,
            ),
        ),
        (),
    )
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "phi_copy",
        (argument,),
        (),
        (entry, copy_block(then_address), copy_block(else_address), joined),
    )

    result = simplify_ssa_function(build_ssa_function(function))
    join_block = result.function.block(join)

    assert join_block.phis == ()
    returned = join_block.statements[0]
    assert isinstance(returned, SSAReturnStatement)
    assert isinstance(returned.value, SSAReferenceExpression)
    assert returned.value.value == result.function.entry_definitions[0]


def test_dead_pure_assignment_is_removed() -> None:
    source = _source()
    temporary = DecompilerVariable("tmp_dead", DecompilerVariableKind.TEMPORARY)
    function = _function(
        (
            AssignmentStatement(
                VariableExpression(temporary, source),
                ConstantExpression(99, source),
                source,
            ),
            ReturnStatement(None, _source(BASE + 4)),
        )
    )

    result = _simplify(function)

    assert len(result.function.blocks[0].statements) == 1
    assert isinstance(result.function.blocks[0].statements[0], SSAReturnStatement)


def test_memory_write_is_never_removed_or_reordered() -> None:
    source = _source()
    address = RegisterExpression(Register.R1, source)
    function = _function(
        (
            MemoryWriteStatement(
                address,
                ConstantExpression(7, source),
                4,
                source,
            ),
            ReturnStatement(None, _source(BASE + 4)),
        )
    )

    result = _simplify(function)

    assert isinstance(result.function.blocks[0].statements[0], SSAMemoryWriteStatement)
    assert isinstance(result.function.blocks[0].statements[1], SSAReturnStatement)


def test_memory_read_is_not_propagated_across_call_barrier() -> None:
    source = _source()
    read = MemoryReadExpression(
        RegisterExpression(Register.R1, source),
        4,
        source,
    )
    call_source = _source(BASE + 4)
    call = CallExpression(
        "unknown_call",
        0x02004000,
        InstructionSet.ARM,
        "arm9",
        (),
        call_source,
    )
    function = _function(
        (
            _assign(BASE, Register.R0, read),
            CallStatement(call, call_source),
            ReturnStatement(
                RegisterExpression(Register.R0, _source(BASE + 8)),
                _source(BASE + 8),
            ),
        )
    )

    result = _simplify(function)
    statements = result.function.blocks[0].statements

    assert len(statements) == 3
    assert isinstance(statements[0].value, SSAMemoryReadExpression)  # type: ignore[union-attr]
    assert isinstance(statements[1], SSACallStatement)
    returned = statements[2]
    assert isinstance(returned, SSAReturnStatement)
    assert isinstance(returned.value, SSAReferenceExpression)


def test_unknown_statement_survives_simplification() -> None:
    source = _source()
    result = _simplify(
        _function(
            (
                UnknownStatement("unsupported opcode", source),
                ReturnStatement(None, _source(BASE + 4)),
            )
        )
    )

    assert isinstance(result.function.blocks[0].statements[0], UnknownStatement)


def test_iteration_cap_reports_nonconvergence_without_nondeterminism() -> None:
    argument = DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )
    source = _source()
    function = build_ssa_function(
        _function(
            (
                _assign(
                    BASE,
                    Register.R1,
                    BinaryExpression(
                        BinaryOperator.ADD,
                        RegisterExpression(Register.R0, source),
                        ConstantExpression(1, source),
                        source,
                    ),
                ),
                ReturnStatement(
                    RegisterExpression(Register.R1, _source(BASE + 4)),
                    _source(BASE + 4),
                ),
            ),
            parameters=(argument,),
        )
    )

    first = simplify_ssa_function(function, iteration_cap=1)
    second = simplify_ssa_function(function, iteration_cap=1)

    assert first == second
    assert first.iterations == 1
