from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    BreakNode,
    ConstantExpression,
    ContinueNode,
    DecompiledFunction,
    LoopNode,
    SourceRef,
    StructuredFunction,
)
from nds_disassembly_toolkit.analysis.decompiler.render import render_pseudo_c
from nds_disassembly_toolkit.analysis.model import InstructionSet

BASE = 0x02012000


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _function() -> DecompiledFunction:
    return DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "loop_control",
        (),
        (),
        (),
    )


def test_break_and_continue_render_inside_pretest_loop() -> None:
    structured = StructuredFunction(
        _function(),
        (
            LoopNode(
                ConstantExpression(1, _source()),
                (
                    ContinueNode(),
                    BreakNode(),
                ),
            ),
        ),
        False,
    )

    rendered = render_pseudo_c(structured)

    assert "while (1) {" in rendered
    assert "continue;" in rendered
    assert "break;" in rendered


def test_break_and_continue_render_inside_posttest_loop() -> None:
    structured = StructuredFunction(
        _function(),
        (
            LoopNode(
                ConstantExpression(1, _source()),
                (
                    ContinueNode(),
                    BreakNode(),
                ),
                post_test=True,
            ),
        ),
        False,
    )

    rendered = render_pseudo_c(structured)

    assert "do {" in rendered
    assert "continue;" in rendered
    assert "break;" in rendered
    assert "} while (1);" in rendered
