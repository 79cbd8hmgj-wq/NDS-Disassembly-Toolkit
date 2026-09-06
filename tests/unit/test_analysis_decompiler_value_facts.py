from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    AssignmentStatement,
    BinaryExpression,
    BinaryOperator,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    RegisterExpression,
    ReturnStatement,
    SourceRef,
)
from nds_disassembly_toolkit.analysis.decompiler.ssa import (
    SSAAssignmentStatement,
    build_ssa_function,
)
from nds_disassembly_toolkit.analysis.decompiler.value_facts import (
    ValueFacts,
    analyze_value_facts,
)
from nds_disassembly_toolkit.analysis.model import (
    CFGEdge,
    CFGEdgeKind,
    InstructionSet,
    Register,
)

BASE = 0x02002000
MASK32 = 0xFFFFFFFF


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _assign(
    address: int,
    register: Register,
    expression: object,
) -> AssignmentStatement:
    source = _source(address)
    return AssignmentStatement(
        RegisterExpression(register, source),
        expression,  # type: ignore[arg-type]
        source,
    )


def _single_block(*statements: object) -> DecompiledFunction:
    return DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "facts",
        (),
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


def _facts_for_last_assignment(function: DecompiledFunction) -> ValueFacts:
    ssa = build_ssa_function(function)
    assignments = [
        statement
        for block in ssa.blocks
        for statement in block.statements
        if isinstance(statement, SSAAssignmentStatement)
    ]
    assert assignments
    return analyze_value_facts(ssa).facts_for(assignments[-1].target)


def test_constant_has_exact_32_bit_facts() -> None:
    source = _source()
    facts = _facts_for_last_assignment(
        _single_block(
            _assign(BASE, Register.R0, ConstantExpression(0x12, source)),
        )
    )

    assert facts.exact_value == 0x12
    assert facts.known_one_bits == 0x12
    assert facts.known_zero_bits == (MASK32 ^ 0x12)
    assert facts.unsigned_min == 0x12
    assert facts.unsigned_max == 0x12
    assert facts.is_nonzero is True


def test_and_mask_proves_upper_24_bits_zero() -> None:
    source = _source()
    expression = BinaryExpression(
        BinaryOperator.BITWISE_AND,
        RegisterExpression(Register.R1, source),
        ConstantExpression(0xFF, source),
        source,
    )
    facts = _facts_for_last_assignment(
        _single_block(_assign(BASE, Register.R0, expression))
    )

    assert facts.known_zero_bits & 0xFFFFFF00 == 0xFFFFFF00
    assert facts.unsigned_max <= 0xFF


def test_or_constant_proves_high_bit_one_and_nonzero() -> None:
    source = _source()
    expression = BinaryExpression(
        BinaryOperator.BITWISE_OR,
        RegisterExpression(Register.R1, source),
        ConstantExpression(0x80000000, source),
        source,
    )
    facts = _facts_for_last_assignment(
        _single_block(_assign(BASE, Register.R0, expression))
    )

    assert facts.known_one_bits & 0x80000000
    assert facts.is_nonzero is True
    assert facts.signed_max < 0


def test_xor_of_exact_values_is_exact() -> None:
    source = _source()
    expression = BinaryExpression(
        BinaryOperator.BITWISE_XOR,
        ConstantExpression(0xAA55, source),
        ConstantExpression(0x0F0F, source),
        source,
    )
    facts = _facts_for_last_assignment(
        _single_block(_assign(BASE, Register.R0, expression))
    )

    assert facts.exact_value == (0xAA55 ^ 0x0F0F)


def test_known_left_shift_updates_known_bits_and_range() -> None:
    source = _source()
    masked = BinaryExpression(
        BinaryOperator.BITWISE_AND,
        RegisterExpression(Register.R1, source),
        ConstantExpression(0xFF, source),
        source,
    )
    shifted = BinaryExpression(
        BinaryOperator.SHIFT_LEFT,
        masked,
        ConstantExpression(4, source),
        source,
    )
    facts = _facts_for_last_assignment(
        _single_block(_assign(BASE, Register.R0, shifted))
    )

    assert facts.known_zero_bits & 0xFFFFF00F == 0xFFFFF00F
    assert facts.unsigned_max <= 0xFF0


def test_phi_join_keeps_only_shared_known_bits() -> None:
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
    then_source = _source(then_address)
    else_source = _source(else_address)
    then_block = DecompiledBlock(
        then_address,
        InstructionSet.ARM,
        (_assign(then_address, Register.R0, ConstantExpression(0x12, then_source)),),
        (
            CFGEdge(
                then_address,
                then_address,
                join,
                InstructionSet.ARM,
                CFGEdgeKind.FALLTHROUGH,
            ),
        ),
    )
    else_block = DecompiledBlock(
        else_address,
        InstructionSet.ARM,
        (_assign(else_address, Register.R0, ConstantExpression(0x13, else_source)),),
        (
            CFGEdge(
                else_address,
                else_address,
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
        (ReturnStatement(RegisterExpression(Register.R0, join_source), join_source),),
        (),
    )
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "diamond",
        (),
        (),
        (entry, then_block, else_block, joined),
    )

    ssa = build_ssa_function(function)
    phi = ssa.block(join).phis[0]
    facts = analyze_value_facts(ssa).facts_for(phi.output)

    assert facts.exact_value is None
    assert facts.known_one_bits == 0x12
    assert facts.known_zero_bits & (MASK32 ^ 0x13) == (MASK32 ^ 0x13)
    assert facts.unsigned_min == 0x12
    assert facts.unsigned_max == 0x13


def test_proven_address_preserves_component_identity() -> None:
    source = _source()
    facts = _facts_for_last_assignment(
        _single_block(
            _assign(
                BASE,
                Register.R0,
                AddressExpression(0x02200000, "overlay_3", source),
            )
        )
    )

    assert facts.address == 0x02200000
    assert facts.component == "overlay_3"
    assert facts.is_address is True


def test_same_address_from_different_overlays_drops_component_ownership() -> None:
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

    def address_block(address: int, component: str) -> DecompiledBlock:
        source = _source(address)
        return DecompiledBlock(
            address,
            InstructionSet.ARM,
            (
                _assign(
                    address,
                    Register.R0,
                    AddressExpression(0x02200000, component, source),
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

    joined = DecompiledBlock(join, InstructionSet.ARM, (), ())
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "overlay_ambiguity",
        (),
        (),
        (
            entry,
            address_block(then_address, "overlay_3"),
            address_block(else_address, "overlay_7"),
            joined,
        ),
    )

    ssa = build_ssa_function(function)
    phi = ssa.block(join).phis[0]
    facts = analyze_value_facts(ssa).facts_for(phi.output)

    assert facts.address == 0x02200000
    assert facts.component is None
    assert facts.is_address is True


def test_naked_numeric_constant_is_not_guessed_to_be_an_address() -> None:
    source = _source()
    facts = _facts_for_last_assignment(
        _single_block(
            _assign(BASE, Register.R0, ConstantExpression(0x02200000, source))
        )
    )

    assert facts.exact_value == 0x02200000
    assert facts.is_address is False
    assert facts.address is None
    assert facts.component is None
