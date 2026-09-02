from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AssignmentStatement,
    CompareExpression,
    ConstantExpression,
    DecompiledFunction,
    DecompilerVariable,
    DecompilerVariableKind,
    GotoNode,
    IfNode,
    LabelNode,
    MemoryReadExpression,
    MemoryWriteStatement,
    ReturnStatement,
    SourceRef,
    StatementNode,
    StructuredFunction,
    UnknownStatement,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.render import render_pseudo_c
from nds_disassembly_toolkit.analysis.model import ConditionCode, InstructionSet, Register

BASE = 0x02000000


def _source(address: int = BASE) -> tuple[SourceRef, ...]:
    return (SourceRef(address, InstructionSet.ARM),)


def _variable(
    name: str,
    kind: DecompilerVariableKind,
    *,
    register: Register | None = None,
    stack_offset: int | None = None,
) -> DecompilerVariable:
    return DecompilerVariable(name, kind, register=register, stack_offset=stack_offset)


def _structured_fixture(condition: ConditionCode = ConditionCode.EQ) -> StructuredFunction:
    arg0 = _variable("arg0", DecompilerVariableKind.ARGUMENT, register=Register.R0)
    local = _variable("local_04", DecompilerVariableKind.LOCAL, stack_offset=-4)
    temporary = _variable("tmp_0", DecompilerVariableKind.TEMPORARY)
    source = _source()
    comparison = CompareExpression(
        condition,
        VariableExpression(arg0, source),
        ConstantExpression(5, source),
        source,
    )
    assignment = AssignmentStatement(
        VariableExpression(temporary, source),
        ConstantExpression(0x20, source),
        source,
    )
    ret = ReturnStatement(VariableExpression(temporary, source), source)
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "UserEntry",
        (arg0,),
        (local, temporary),
        (),
    )
    return StructuredFunction(
        function,
        (
            IfNode(comparison, (StatementNode(assignment),)),
            StatementNode(ret),
        ),
        False,
    )


def test_renderer_is_byte_deterministic() -> None:
    first = render_pseudo_c(_structured_fixture())
    second = render_pseudo_c(_structured_fixture())

    assert first == second
    assert first.endswith("\n")
    assert not first.endswith("\n\n")
    assert "uint32_t UserEntry(uint32_t arg0)" in first
    assert "uint32_t local_04;" in first
    assert "uint32_t tmp_0;" in first
    assert "if (arg0 == 5)" in first
    assert "tmp_0 = 0x20;" in first
    assert "return tmp_0;" in first


def test_renderer_uses_explicit_signed_and_unsigned_conditions() -> None:
    unsigned = render_pseudo_c(_structured_fixture(ConditionCode.HI))
    signed = render_pseudo_c(_structured_fixture(ConditionCode.GT))

    assert "(uint32_t)arg0 > (uint32_t)5" in unsigned
    assert "(int32_t)arg0 > (int32_t)5" in signed


def test_memory_widths_drive_casts_only() -> None:
    local = _variable("local_04", DecompilerVariableKind.LOCAL, stack_offset=-4)
    source = _source()
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "memory_demo",
        (),
        (local,),
        (),
    )
    structured = StructuredFunction(
        function,
        (
            StatementNode(
                AssignmentStatement(
                    VariableExpression(local, source),
                    MemoryReadExpression(ConstantExpression(0x02001000, source), 1, source),
                    source,
                )
            ),
            StatementNode(
                MemoryWriteStatement(
                    ConstantExpression(0x02002000, source),
                    VariableExpression(local, source),
                    2,
                    source,
                )
            ),
            StatementNode(ReturnStatement(None, source)),
        ),
        False,
    )

    rendered = render_pseudo_c(structured)

    assert "*(uint8_t *)0x02001000" in rendered
    assert "*(uint16_t *)0x02002000 = local_04;" in rendered
    assert rendered.startswith("void memory_demo(void)")


def test_labels_and_gotos_are_canonical() -> None:
    source = _source()
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "fallback_demo",
        (),
        (),
        (),
    )
    structured = StructuredFunction(
        function,
        (
            LabelNode(BASE),
            GotoNode(BASE + 0x20),
            LabelNode(BASE + 0x20),
            StatementNode(ReturnStatement(None, source)),
        ),
        True,
    )

    rendered = render_pseudo_c(structured)

    assert "loc_02000000:" in rendered
    assert "goto loc_02000020;" in rendered
    assert "loc_02000020:" in rendered


def test_unknown_instruction_is_visible_with_exact_source_address() -> None:
    source = _source(BASE + 4)
    function = DecompiledFunction(
        "arm9",
        BASE,
        InstructionSet.ARM,
        "unknown_demo",
        (),
        (),
        (),
    )
    structured = StructuredFunction(
        function,
        (
            StatementNode(
                UnknownStatement(
                    "unresolved instruction: udf misleading display text",
                    source,
                )
            ),
        ),
        False,
    )

    rendered = render_pseudo_c(structured)

    assert "unresolved instruction" in rendered
    assert "0x02000004" in rendered
