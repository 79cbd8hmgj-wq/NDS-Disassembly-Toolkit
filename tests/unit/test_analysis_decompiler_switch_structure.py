from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    BranchStatement,
    CompareExpression,
    ConstantExpression,
    DecompiledBlock,
    DecompiledFunction,
    DecompilerVariable,
    DecompilerVariableKind,
    ReturnStatement,
    SourceRef,
    StatementNode,
    SwitchNode,
    UnknownStatement,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.structure import structure_function
from nds_disassembly_toolkit.analysis.model import (
    CFGEdge,
    CFGEdgeKind,
    ConditionCode,
    InstructionSet,
    Register,
)

BASE = 0x02011000


def _source(address: int) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _arg() -> DecompilerVariable:
    return DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )


def _subject(address: int, variable: DecompilerVariable) -> VariableExpression:
    return VariableExpression(variable, _source(address))


def _compare(
    address: int,
    variable: DecompilerVariable,
    value: int,
    *,
    condition: ConditionCode = ConditionCode.EQ,
    reversed_operands: bool = False,
) -> CompareExpression:
    source = _source(address)
    subject = _subject(address, variable)
    constant = ConstantExpression(value, source)
    left, right = (
        (constant, subject)
        if reversed_operands
        else (subject, constant)
    )
    return CompareExpression(
        condition,
        left,
        right,
        source,
    )


def _edge(source: int, target: int, kind: CFGEdgeKind) -> CFGEdge:
    return CFGEdge(
        source,
        source,
        target,
        InstructionSet.ARM,
        kind,
    )


def _block(
    address: int,
    statements: tuple[object, ...],
    edges: tuple[CFGEdge, ...] = (),
) -> DecompiledBlock:
    return DecompiledBlock(
        address,
        InstructionSet.ARM,
        statements,  # type: ignore[arg-type]
        edges,
    )


def _effect(address: int, description: str) -> UnknownStatement:
    return UnknownStatement(description, _source(address))


def _return(address: int) -> ReturnStatement:
    return ReturnStatement(None, _source(address))


def _function(
    variable: DecompilerVariable,
    *blocks: DecompiledBlock,
) -> DecompiledFunction:
    return DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "dispatch",
        (variable,),
        (),
        tuple(blocks),
    )


def _switch_fixture(
    *,
    first_condition: ConditionCode = ConditionCode.EQ,
    second_condition: ConditionCode = ConditionCode.EQ,
    reversed_first: bool = False,
    shared_case_target: bool = False,
    first_case_returns: bool = False,
    first_subject: DecompilerVariable | None = None,
    second_subject: DecompilerVariable | None = None,
    extra_case_predecessor: bool = False,
    conflicting_joins: bool = False,
) -> DecompiledFunction:
    arg0 = _arg()
    subject0 = first_subject or arg0
    subject1 = second_subject or arg0

    compare0 = BASE
    compare1 = BASE + 4
    case1 = BASE + 0x20
    case2 = case1 if shared_case_target else BASE + 0x24
    default = BASE + 0x28
    join = BASE + 0x30
    other_join = BASE + 0x34
    extra = BASE + 0x40

    first_case_edge_kind = (
        CFGEdgeKind.BRANCH
        if first_condition is ConditionCode.EQ
        else CFGEdgeKind.FALLTHROUGH
    )
    first_next_edge_kind = (
        CFGEdgeKind.FALLTHROUGH
        if first_condition is ConditionCode.EQ
        else CFGEdgeKind.BRANCH
    )
    second_case_edge_kind = (
        CFGEdgeKind.BRANCH
        if second_condition is ConditionCode.EQ
        else CFGEdgeKind.FALLTHROUGH
    )
    second_next_edge_kind = (
        CFGEdgeKind.FALLTHROUGH
        if second_condition is ConditionCode.EQ
        else CFGEdgeKind.BRANCH
    )

    blocks: list[DecompiledBlock] = [
        _block(
            compare0,
            (
                BranchStatement(
                    _compare(
                        compare0,
                        subject0,
                        1,
                        condition=first_condition,
                        reversed_operands=reversed_first,
                    ),
                    case1
                    if first_case_edge_kind is CFGEdgeKind.BRANCH
                    else compare1,
                    InstructionSet.ARM,
                    _source(compare0),
                ),
            ),
            (
                _edge(
                    compare0,
                    case1,
                    first_case_edge_kind,
                ),
                _edge(
                    compare0,
                    compare1,
                    first_next_edge_kind,
                ),
            ),
        ),
        _block(
            compare1,
            (
                BranchStatement(
                    _compare(
                        compare1,
                        subject1,
                        2,
                        condition=second_condition,
                    ),
                    case2
                    if second_case_edge_kind is CFGEdgeKind.BRANCH
                    else default,
                    InstructionSet.ARM,
                    _source(compare1),
                ),
            ),
            (
                _edge(
                    compare1,
                    case2,
                    second_case_edge_kind,
                ),
                _edge(
                    compare1,
                    default,
                    second_next_edge_kind,
                ),
            ),
        ),
    ]

    if first_case_returns:
        blocks.append(
            _block(
                case1,
                (_effect(case1, "case_1"), _return(case1)),
            )
        )
    else:
        blocks.append(
            _block(
                case1,
                (_effect(case1, "case_1"),),
                (
                    _edge(
                        case1,
                        other_join if conflicting_joins else join,
                        CFGEdgeKind.FALLTHROUGH,
                    ),
                ),
            )
        )

    if not shared_case_target:
        blocks.append(
            _block(
                case2,
                (_effect(case2, "case_2"),),
                (_edge(case2, join, CFGEdgeKind.FALLTHROUGH),),
            )
        )

    blocks.extend(
        (
            _block(
                default,
                (_effect(default, "default"),),
                (_edge(default, join, CFGEdgeKind.FALLTHROUGH),),
            ),
            _block(join, (_return(join),)),
        )
    )

    if conflicting_joins:
        blocks.append(_block(other_join, (_return(other_join),)))

    if extra_case_predecessor:
        blocks.append(
            _block(
                extra,
                (_effect(extra, "external"),),
                (_edge(extra, case1, CFGEdgeKind.BRANCH),),
            )
        )

    return _function(arg0, *blocks)


def _switch(function: DecompiledFunction) -> SwitchNode:
    structured = structure_function(function)
    return next(
        node
        for node in structured.body
        if isinstance(node, SwitchNode)
    )


def test_two_case_equality_chain_becomes_switch() -> None:
    function = _switch_fixture()

    structured = structure_function(function)
    switch = _switch(function)

    assert structured.fallback_used is False
    assert tuple(case.values for case in switch.cases) == (
        (1,),
        (2,),
    )
    assert [
        node.statement.description
        for node in switch.default_body
        if isinstance(node, StatementNode)
        and isinstance(node.statement, UnknownStatement)
    ] == ["default"]


def test_reversed_constant_subject_comparison_is_supported() -> None:
    switch = _switch(
        _switch_fixture(reversed_first=True)
    )

    assert tuple(case.values for case in switch.cases) == (
        (1,),
        (2,),
    )


def test_ne_orientation_is_supported_when_case_is_fallthrough() -> None:
    switch = _switch(
        _switch_fixture(
            first_condition=ConditionCode.NE,
            second_condition=ConditionCode.NE,
        )
    )

    assert tuple(case.values for case in switch.cases) == (
        (1,),
        (2,),
    )


def test_multiple_values_with_same_target_share_case_body() -> None:
    switch = _switch(
        _switch_fixture(shared_case_target=True)
    )

    assert len(switch.cases) == 1
    assert switch.cases[0].values == (1, 2)


def test_case_that_returns_does_not_block_switch_recovery() -> None:
    function = _switch_fixture(first_case_returns=True)

    structured = structure_function(function)
    switch = _switch(function)

    assert structured.fallback_used is False
    assert any(
        isinstance(node, StatementNode)
        and isinstance(node.statement, ReturnStatement)
        for node in switch.cases[0].body
    )


def test_different_switch_subjects_fall_back() -> None:
    other = DecompilerVariable(
        "arg1",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R1,
    )
    function = _switch_fixture(second_subject=other)

    structured = structure_function(function)

    assert structured.fallback_used is True
    assert not any(
        isinstance(node, SwitchNode)
        for node in structured.body
    )


def test_non_equality_comparison_falls_back() -> None:
    function = _switch_fixture(
        second_condition=ConditionCode.GT,
    )

    structured = structure_function(function)

    assert structured.fallback_used is True


def test_external_case_predecessor_falls_back() -> None:
    function = _switch_fixture(
        extra_case_predecessor=True,
    )

    structured = structure_function(function)

    assert structured.fallback_used is True


def test_conflicting_case_joins_fall_back() -> None:
    function = _switch_fixture(
        conflicting_joins=True,
    )

    structured = structure_function(function)

    assert structured.fallback_used is True
