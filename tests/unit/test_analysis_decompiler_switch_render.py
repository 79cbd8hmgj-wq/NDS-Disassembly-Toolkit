from __future__ import annotations

import pytest

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    ConstantExpression,
    DecompiledFunction,
    DecompilerVariable,
    DecompilerVariableKind,
    IfNode,
    ReturnStatement,
    SourceRef,
    StatementNode,
    StructuredFunction,
    SwitchCase,
    SwitchNode,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.render import render_pseudo_c
from nds_disassembly_toolkit.analysis.model import (
    ConditionCode,
    InstructionSet,
    Register,
)
from nds_disassembly_toolkit.analysis.decompiler.model import CompareExpression

BASE = 0x02010000


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _function() -> tuple[DecompiledFunction, DecompilerVariable]:
    arg0 = DecompilerVariable(
        "arg0",
        DecompilerVariableKind.ARGUMENT,
        register=Register.R0,
    )
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "dispatch",
        (arg0,),
        (),
        (),
    )
    return function, arg0


def _assignment(
    variable: DecompilerVariable,
    value: int,
    address: int,
) -> StatementNode:
    source = _source(address)
    return StatementNode(
        AssignmentStatement(
            VariableExpression(variable, source),
            ConstantExpression(value, source),
            source,
        )
    )


def _return(value: int, address: int) -> StatementNode:
    source = _source(address)
    return StatementNode(
        ReturnStatement(
            ConstantExpression(value, source),
            source,
        )
    )


def test_switch_case_values_are_normalized_and_cases_are_ordered() -> None:
    function, arg0 = _function()
    source = _source()
    switch = SwitchNode(
        VariableExpression(arg0, source),
        (
            SwitchCase((7, 3, 7), (_return(1, BASE + 4),)),
            SwitchCase((2,), (_return(2, BASE + 8),)),
        ),
        (_return(0, BASE + 12),),
    )

    assert tuple(case.values for case in switch.cases) == (
        (2,),
        (3, 7),
    )


def test_switch_rejects_duplicate_values_across_case_bodies() -> None:
    function, arg0 = _function()
    del function
    source = _source()

    with pytest.raises(ValueError, match="duplicate switch case value"):
        SwitchNode(
            VariableExpression(arg0, source),
            (
                SwitchCase((1,), (_return(1, BASE + 4),)),
                SwitchCase((1, 2), (_return(2, BASE + 8),)),
            ),
        )


def test_switch_renderer_emits_stacked_labels_and_breaks() -> None:
    function, arg0 = _function()
    local = DecompilerVariable(
        "result",
        DecompilerVariableKind.LOCAL,
        stack_offset=-4,
    )
    function = DecompiledFunction(
        function.component,
        function.address,
        function.instruction_set,
        function.name,
        function.parameters,
        (local,),
        (),
    )
    source = _source()
    structured = StructuredFunction(
        function,
        (
            SwitchNode(
                VariableExpression(arg0, source),
                (
                    SwitchCase(
                        (1, 3),
                        (_assignment(local, 0x11, BASE + 4),),
                    ),
                    SwitchCase(
                        (2,),
                        (_return(0x22, BASE + 8),),
                    ),
                ),
                (_assignment(local, 0, BASE + 12),),
            ),
            StatementNode(
                ReturnStatement(
                    VariableExpression(local, _source(BASE + 16)),
                    _source(BASE + 16),
                )
            ),
        ),
        False,
    )

    rendered = render_pseudo_c(structured)

    assert "switch (arg0) {" in rendered
    assert "case 1:" in rendered
    assert "case 3:" in rendered
    assert "result = 0x11;" in rendered
    assert "case 2:" in rendered
    assert "return 0x22;" in rendered
    assert "default:" in rendered
    assert "result = 0;" in rendered

    case_1 = rendered.index("case 1:")
    case_3 = rendered.index("case 3:")
    assignment = rendered.index("result = 0x11;")
    first_break = rendered.index("break;", assignment)
    case_2 = rendered.index("case 2:")
    default = rendered.index("default:")

    assert case_1 < case_3 < assignment < first_break < case_2 < default
    # The return case is already terminal; it should not gain an unreachable break.
    return_line = rendered.index("return 0x22;")
    assert "break;" not in rendered[return_line:default]


def test_switch_renderer_supports_nested_structured_nodes() -> None:
    function, arg0 = _function()
    source = _source()
    condition = CompareExpression(
        ConditionCode.NE,
        VariableExpression(arg0, source),
        ConstantExpression(0, source),
        source,
    )
    structured = StructuredFunction(
        function,
        (
            SwitchNode(
                VariableExpression(arg0, source),
                (
                    SwitchCase(
                        (4,),
                        (
                            IfNode(
                                condition,
                                (_return(4, BASE + 4),),
                            ),
                        ),
                    ),
                ),
                (),
            ),
        ),
        False,
    )

    rendered = render_pseudo_c(structured)

    assert "case 4:" in rendered
    assert "if (arg0 != 0) {" in rendered
    assert "return 4;" in rendered


def test_switch_without_default_omits_default_label() -> None:
    function, arg0 = _function()
    source = _source()
    structured = StructuredFunction(
        function,
        (
            SwitchNode(
                VariableExpression(arg0, source),
                (
                    SwitchCase((1,), (_return(1, BASE + 4),)),
                ),
            ),
        ),
        False,
    )

    rendered = render_pseudo_c(structured)

    assert "case 1:" in rendered
    assert "default:" not in rendered
