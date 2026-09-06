from __future__ import annotations

from nds_disassembly_toolkit.analysis.decompiler.model import (
    AddressExpression,
    AssignmentStatement,
    BinaryExpression,
    BinaryOperator,
    BranchStatement,
    CallExpression,
    CallStatement,
    CompareExpression,
    ConstantExpression,
    DecompilationResult,
    DecompilerExpression,
    FieldAddressExpression,
    GotoNode,
    IfNode,
    LabelNode,
    LoopNode,
    MemoryReadExpression,
    MemoryWriteStatement,
    RegisterExpression,
    ReturnStatement,
    StatementNode,
    StructuredFunction,
    StructuredNode,
    SwitchNode,
    UnaryExpression,
    UnaryOperator,
    UnknownExpression,
    UnknownStatement,
    VariableExpression,
)
from nds_disassembly_toolkit.analysis.decompiler.type_propagation import (
    RenderTypeContext,
)
from nds_disassembly_toolkit.analysis.model import ConditionCode

_BINARY_SYMBOLS = {
    BinaryOperator.ADD: "+",
    BinaryOperator.SUBTRACT: "-",
    BinaryOperator.MULTIPLY: "*",
    BinaryOperator.BITWISE_AND: "&",
    BinaryOperator.BITWISE_OR: "|",
    BinaryOperator.BITWISE_XOR: "^",
    BinaryOperator.SHIFT_LEFT: "<<",
    BinaryOperator.SHIFT_RIGHT_LOGICAL: ">>",
    BinaryOperator.SHIFT_RIGHT_ARITHMETIC: ">>",
}
_UNSIGNED_COMPARISONS = {
    ConditionCode.HS: ">=",
    ConditionCode.LO: "<",
    ConditionCode.HI: ">",
    ConditionCode.LS: "<=",
}
_SIGNED_COMPARISONS = {
    ConditionCode.GE: ">=",
    ConditionCode.LT: "<",
    ConditionCode.GT: ">",
    ConditionCode.LE: "<=",
}
_MEMORY_TYPES = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t"}


def _hex_address(value: int) -> str:
    return f"0x{value:08x}"


def _constant(value: int) -> str:
    if 0 <= value <= 9:
        return str(value)
    return f"0x{value:x}"


def _quoted(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _address_expression(expression: DecompilerExpression) -> str:
    if isinstance(expression, ConstantExpression):
        return _hex_address(expression.value)
    return _render_expression(expression)


def _cast(type_name: str, expression: DecompilerExpression) -> str:
    rendered = _render_expression(expression)
    if isinstance(
        expression,
        (BinaryExpression, CompareExpression, UnaryExpression),
    ):
        rendered = f"({rendered})"
    return f"({type_name}){rendered}"


def _render_compare(expression: CompareExpression) -> str:
    condition = expression.condition
    left = _render_expression(expression.left)
    right = _render_expression(expression.right)
    if condition is ConditionCode.EQ:
        return f"{left} == {right}"
    if condition is ConditionCode.NE:
        return f"{left} != {right}"
    unsigned = _UNSIGNED_COMPARISONS.get(condition)
    if unsigned is not None:
        return (
            f"{_cast('uint32_t', expression.left)} {unsigned} "
            f"{_cast('uint32_t', expression.right)}"
        )
    signed = _SIGNED_COMPARISONS.get(condition)
    if signed is not None:
        return (
            f"{_cast('int32_t', expression.left)} {signed} "
            f"{_cast('int32_t', expression.right)}"
        )
    return f"condition_{condition.value}({left}, {right})"


def _render_call(expression: CallExpression) -> str:
    arguments = ", ".join(_render_expression(argument) for argument in expression.arguments)
    return f"{expression.name}({arguments})"


def _render_expression(expression: DecompilerExpression) -> str:
    if isinstance(expression, ConstantExpression):
        return _constant(expression.value)
    if isinstance(expression, AddressExpression):
        return _hex_address(expression.address)
    if isinstance(expression, VariableExpression):
        return expression.variable.name
    if isinstance(expression, RegisterExpression):
        return expression.register.value
    if isinstance(expression, UnaryExpression):
        symbol = "-" if expression.operator is UnaryOperator.NEGATE else "~"
        return f"{symbol}({_render_expression(expression.operand)})"
    if isinstance(expression, BinaryExpression):
        symbol = _BINARY_SYMBOLS[expression.operator]
        return (
            f"({_render_expression(expression.left)} {symbol} "
            f"{_render_expression(expression.right)})"
        )
    if isinstance(expression, CompareExpression):
        return _render_compare(expression)
    if isinstance(expression, FieldAddressExpression):
        return f"{_render_expression(expression.base)}->{expression.field_name}"
    if isinstance(expression, MemoryReadExpression):
        if isinstance(expression.address, FieldAddressExpression):
            return _render_expression(expression.address)
        type_name = _MEMORY_TYPES[expression.width]
        return f"*({type_name} *){_address_expression(expression.address)}"
    if isinstance(expression, CallExpression):
        return _render_call(expression)
    if isinstance(expression, UnknownExpression):
        return f"unknown_expr({_quoted(expression.description)})"
    raise TypeError(f"unsupported decompiler expression: {type(expression).__name__}")


def _source_address(statement: UnknownStatement) -> str:
    if not statement.source:
        return "unknown"
    return _hex_address(statement.source[0].address)


def _statement_line(statement: object) -> str:
    if isinstance(statement, AssignmentStatement):
        return (
            f"{_render_expression(statement.target)} = "
            f"{_render_expression(statement.value)};"
        )
    if isinstance(statement, MemoryWriteStatement):
        if isinstance(statement.address, FieldAddressExpression):
            return (
                f"{_render_expression(statement.address)} = "
                f"{_render_expression(statement.value)};"
            )
        type_name = _MEMORY_TYPES[statement.width]
        return (
            f"*({type_name} *){_address_expression(statement.address)} = "
            f"{_render_expression(statement.value)};"
        )
    if isinstance(statement, CallStatement):
        return f"{_render_call(statement.call)};"
    if isinstance(statement, ReturnStatement):
        if statement.value is None:
            return "return;"
        return f"return {_render_expression(statement.value)};"
    if isinstance(statement, BranchStatement):
        target = f"loc_{statement.target_address:08x}"
        if statement.condition is None:
            return f"goto {target};"
        return f"if ({_render_expression(statement.condition)}) goto {target};"
    if isinstance(statement, UnknownStatement):
        return f"/* {_source_address(statement)}: {statement.description} */"
    raise TypeError(f"unsupported decompiler statement: {type(statement).__name__}")


def _node_terminates(node: StructuredNode) -> bool:
    if isinstance(node, StatementNode):
        return isinstance(node.statement, ReturnStatement)
    return isinstance(node, GotoNode)


def _body_terminates(nodes: tuple[StructuredNode, ...]) -> bool:
    return bool(nodes) and _node_terminates(nodes[-1])


def _render_nodes(
    nodes: tuple[StructuredNode, ...],
    *,
    indent: int,
) -> list[str]:
    lines: list[str] = []
    prefix = "    " * indent
    for node in nodes:
        if isinstance(node, StatementNode):
            lines.append(f"{prefix}{_statement_line(node.statement)}")
            continue
        if isinstance(node, LabelNode):
            lines.append(f"{prefix}loc_{node.address:08x}:")
            continue
        if isinstance(node, GotoNode):
            lines.append(f"{prefix}goto loc_{node.target_address:08x};")
            continue
        if isinstance(node, IfNode):
            lines.append(f"{prefix}if ({_render_expression(node.condition)}) {{")
            lines.extend(_render_nodes(node.then_body, indent=indent + 1))
            if node.else_body:
                lines.append(f"{prefix}}} else {{")
                lines.extend(_render_nodes(node.else_body, indent=indent + 1))
            lines.append(f"{prefix}}}")
            continue
        if isinstance(node, LoopNode):
            condition = _render_expression(node.condition)
            if node.post_test:
                lines.append(f"{prefix}do {{")
                lines.extend(_render_nodes(node.body, indent=indent + 1))
                lines.append(f"{prefix}}} while ({condition});")
            else:
                lines.append(f"{prefix}while ({condition}) {{")
                lines.extend(_render_nodes(node.body, indent=indent + 1))
                lines.append(f"{prefix}}}")
            continue
        if isinstance(node, SwitchNode):
            lines.append(
                f"{prefix}switch ({_render_expression(node.expression)}) {{"
            )
            case_prefix = "    " * (indent + 1)
            body_indent = indent + 2
            body_prefix = "    " * body_indent
            for case in node.cases:
                for value in case.values:
                    lines.append(
                        f"{case_prefix}case {_constant(value)}:"
                    )
                lines.extend(
                    _render_nodes(
                        case.body,
                        indent=body_indent,
                    )
                )
                if not _body_terminates(case.body):
                    lines.append(f"{body_prefix}break;")
            if node.default_body:
                lines.append(f"{case_prefix}default:")
                lines.extend(
                    _render_nodes(
                        node.default_body,
                        indent=body_indent,
                    )
                )
                if not _body_terminates(node.default_body):
                    lines.append(f"{body_prefix}break;")
            lines.append(f"{prefix}}}")
            continue
        raise TypeError(f"unsupported structured node: {type(node).__name__}")
    return lines


def _contains_value_return(nodes: tuple[StructuredNode, ...]) -> bool:
    for node in nodes:
        if isinstance(node, StatementNode):
            if isinstance(node.statement, ReturnStatement) and node.statement.value is not None:
                return True
            continue
        if isinstance(node, IfNode):
            if _contains_value_return(node.then_body) or _contains_value_return(node.else_body):
                return True
            continue
        if isinstance(node, LoopNode) and _contains_value_return(node.body):
            return True
        if isinstance(node, SwitchNode):
            if any(
                _contains_value_return(case.body)
                for case in node.cases
            ):
                return True
            if _contains_value_return(node.default_body):
                return True
    return False


def _typed_declaration(type_name: str, variable_name: str) -> str:
    if type_name.endswith("*"):
        return f"{type_name}{variable_name}"
    return f"{type_name} {variable_name}"


def render_pseudo_c(
    value: StructuredFunction | DecompilationResult,
    *,
    type_context: RenderTypeContext | None = None,
) -> str:
    structured = value.structured if isinstance(value, DecompilationResult) else value
    function = structured.function
    fallback_return_type = (
        "uint32_t"
        if _contains_value_return(structured.body)
        else "void"
    )
    return_type = (
        fallback_return_type
        if type_context is None or type_context.return_type is None
        else type_context.return_type
    )

    parameter_types = (
        {}
        if type_context is None
        else dict(type_context.parameter_types)
    )
    parameters = ", ".join(
        _typed_declaration(
            parameter_types.get(item.name, "uint32_t"),
            item.name,
        )
        for item in function.parameters
    )
    if not parameters:
        parameters = "void"

    lines: list[str] = []
    if type_context is not None:
        defined_structures = {
            structure.name
            for structure in type_context.structures
        }
        forward_structs = tuple(
            name
            for name in type_context.forward_structs
            if name not in defined_structures
        )
        if forward_structs:
            lines.extend(
                f"struct {name};"
                for name in forward_structs
            )
            lines.append("")
        for structure in type_context.structures:
            lines.append(f"struct {structure.name} {{")
            lines.extend(
                f"    {field.type_name} {field.name};"
                for field in structure.fields
            )
            lines.append("};")
            lines.append("")

    lines.append(f"{return_type} {function.name}({parameters}) {{")
    if function.locals:
        local_types = (
            {}
            if type_context is None
            else dict(type_context.local_types)
        )
        lines.extend(
            "    "
            + _typed_declaration(
                local_types.get(variable.name, "uint32_t"),
                variable.name,
            )
            + ";"
            for variable in function.locals
        )
        if structured.body:
            lines.append("")
    lines.extend(_render_nodes(structured.body, indent=1))
    lines.append("}")
    return "\n".join(lines) + "\n"
