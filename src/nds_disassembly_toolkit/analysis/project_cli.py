from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from nds_disassembly_toolkit.analysis.decompiler import (
    DecompilationResult,
    decompile_function,
)
from nds_disassembly_toolkit.analysis.model import (
    AbstractValue,
    ArgumentEvidence,
    BasicBlock,
    BlockFlowState,
    CFGEdge,
    CrossReference,
    DecodedInstruction,
    FunctionCandidate,
    FunctionControlFlowGraph,
    FunctionDataFlow,
    FunctionSummary,
    InstructionFlowState,
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    MemoryOperand,
    OperandAccess,
    OperandShift,
    RegisterState,
    ReturnEvidence,
    StackAccess,
    StackFrame,
    StackSlot,
    StackState,
    StringRecord,
    Symbol,
    UnresolvedTransfer,
)
from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    AnalysisProjectMetadata,
    ComponentAnalysisIdentity,
    LocationAnnotation,
)
from nds_disassembly_toolkit.errors import AnalysisProjectError


def _auto_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer/address: {value}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError(f"address must be non-negative: {value}")
    return parsed


def _instruction_set(value: str) -> InstructionSet:
    try:
        return InstructionSet(value.lower())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "instruction set must be 'arm' or 'thumb'"
        ) from exc


def _hex(value: int) -> str:
    if value < 0:
        raise ValueError("unsigned hexadecimal value cannot be negative")
    return f"0x{value:08x}"


def _signed_hex(value: int) -> str:
    prefix = "-" if value < 0 else ""
    return f"{prefix}0x{abs(value):08x}"


def _numeric_hex(value: int) -> str:
    return _signed_hex(value) if value < 0 else _hex(value)


def _operand_access_json(access: OperandAccess) -> list[str]:
    result: list[str] = []
    if access & OperandAccess.READ:
        result.append("read")
    if access & OperandAccess.WRITE:
        result.append("write")
    return result


def _write_json(payload: object, output: Path | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(output)


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


def _metadata_json(metadata: AnalysisProjectMetadata) -> dict[str, object]:
    return {
        "analysis_model_version": metadata.analysis_model_version,
        "project_format_version": metadata.project_format_version,
        "read_only": metadata.read_only,
        "schema_version": metadata.schema_version,
    }


def _component_identity_json(
    identity: ComponentAnalysisIdentity,
) -> dict[str, object]:
    return {
        "base_address": _hex(identity.base_address),
        "name": identity.name,
        "sha256": identity.sha256,
        "size": _hex(identity.size),
    }


def _function_candidate_json(function: FunctionCandidate) -> dict[str, object]:
    return {
        "address": _hex(function.address),
        "component": function.component,
        "confidence": function.confidence,
        "evidence": list(function.evidence),
        "instruction_set": function.instruction_set.value,
        "offset": _hex(function.offset),
    }


def _string_json(record: StringRecord) -> dict[str, object]:
    return {
        "address": _hex(record.address),
        "component": record.component,
        "offset": _hex(record.offset),
        "text": record.text,
    }


def _shift_json(shift: OperandShift) -> dict[str, object]:
    return {"kind": shift.kind.value, "value": shift.value}


def _memory_json(memory: MemoryOperand) -> dict[str, object]:
    return {
        "base": None if memory.base is None else memory.base.value,
        "displacement": _signed_hex(memory.displacement),
        "index": None if memory.index is None else memory.index.value,
        "scale": memory.scale,
        "subtract_index": memory.subtract_index,
    }


def _instruction_operand_json(operand: InstructionOperand) -> dict[str, object]:
    return {
        "access": _operand_access_json(operand.access),
        "access_width": operand.access_width,
        "immediate": (
            None if operand.immediate is None else _numeric_hex(operand.immediate)
        ),
        "kind": operand.kind.value,
        "memory": None if operand.memory is None else _memory_json(operand.memory),
        "register": None if operand.register is None else operand.register.value,
        "registers": [register.value for register in operand.registers],
        "shift": _shift_json(operand.shift),
    }


def _instruction_semantics_json(
    semantics: InstructionSemantics,
) -> dict[str, object]:
    return {
        "condition": semantics.condition.value,
        "operands": [
            _instruction_operand_json(operand) for operand in semantics.operands
        ],
        "registers_read": [register.value for register in semantics.registers_read],
        "registers_written": [
            register.value for register in semantics.registers_written
        ],
        "writeback": semantics.writeback,
    }


def _instruction_json(instruction: DecodedInstruction) -> dict[str, object]:
    return {
        "address": _hex(instruction.address),
        "conditional": instruction.conditional,
        "control_flow": instruction.control_flow.value,
        "data": instruction.data.hex(),
        "direct_target": (
            None
            if instruction.direct_target is None
            else _hex(instruction.direct_target)
        ),
        "instruction_set": instruction.instruction_set.value,
        "mnemonic": instruction.mnemonic,
        "operands": instruction.operands,
        "semantics": _instruction_semantics_json(instruction.semantics),
        "size": instruction.size,
        "target_instruction_set": (
            None
            if instruction.target_instruction_set is None
            else instruction.target_instruction_set.value
        ),
    }


def _basic_block_json(block: BasicBlock) -> dict[str, object]:
    return {
        "address": _hex(block.address),
        "component": block.component,
        "end_address": _hex(block.end_address),
        "instruction_set": block.instruction_set.value,
        "instructions": [
            _instruction_json(instruction) for instruction in block.instructions
        ],
        "offset": _hex(block.offset),
        "size": _hex(block.size),
    }


def _cfg_edge_json(edge: CFGEdge) -> dict[str, object]:
    return {
        "kind": edge.kind.value,
        "source_address": _hex(edge.source_address),
        "source_instruction_address": _hex(edge.source_instruction_address),
        "target_address": _hex(edge.target_address),
        "target_instruction_set": edge.target_instruction_set.value,
    }


def _unresolved_transfer_json(transfer: UnresolvedTransfer) -> dict[str, object]:
    return {
        "control_flow": transfer.control_flow.value,
        "instruction_set": transfer.instruction_set.value,
        "mnemonic": transfer.mnemonic,
        "operands": transfer.operands,
        "source_address": _hex(transfer.source_address),
    }


def _cfg_json(cfg: FunctionControlFlowGraph | None) -> dict[str, object] | None:
    if cfg is None:
        return None
    return {
        "blocks": [_basic_block_json(block) for block in cfg.blocks],
        "decode_failures": [_hex(address) for address in cfg.decode_failures],
        "edges": [_cfg_edge_json(edge) for edge in cfg.edges],
        "function": _function_candidate_json(cfg.function),
        "unresolved_transfers": [
            _unresolved_transfer_json(transfer)
            for transfer in cfg.unresolved_transfers
        ],
    }


def _abstract_value_json(value: AbstractValue) -> dict[str, object]:
    return {
        "component": value.component,
        "kind": value.kind.value,
        "provenance": [_hex(address) for address in value.provenance],
        "value": None if value.value is None else _hex(value.value),
    }


def _register_state_json(state: RegisterState) -> list[dict[str, object]]:
    return [
        {"register": register.value, "value": _abstract_value_json(value)}
        for register, value in state.values
    ]


def _stack_state_json(state: StackState | None) -> dict[str, object] | None:
    if state is None:
        return None
    return {
        "frame_pointers": [
            {"offset": _signed_hex(offset), "register": register.value}
            for register, offset in state.frame_pointers
        ],
        "offset": None if state.offset is None else _signed_hex(state.offset),
    }


def _instruction_flow_json(state: InstructionFlowState) -> dict[str, object]:
    return {
        "after": _register_state_json(state.after),
        "before": _register_state_json(state.before),
        "instruction": _instruction_json(state.instruction),
        "stack_after": _stack_state_json(state.stack_after),
        "stack_before": _stack_state_json(state.stack_before),
    }


def _block_flow_json(state: BlockFlowState) -> dict[str, object]:
    return {
        "address": _hex(state.address),
        "entry": _register_state_json(state.entry),
        "exit": _register_state_json(state.exit),
        "instruction_set": state.instruction_set.value,
        "stack_entry": _stack_state_json(state.stack_entry),
        "stack_exit": _stack_state_json(state.stack_exit),
    }


def _stack_access_json(access: StackAccess) -> dict[str, object]:
    return {
        "instruction_address": _hex(access.instruction_address),
        "kind": access.kind.value,
        "width": access.width,
    }


def _stack_slot_json(slot: StackSlot) -> dict[str, object]:
    return {
        "accesses": [_stack_access_json(access) for access in slot.accesses],
        "kind": slot.kind.value,
        "offset": _signed_hex(slot.offset),
    }


def _stack_frame_json(frame: StackFrame) -> dict[str, object]:
    return {
        "frame_pointer": (
            None if frame.frame_pointer is None else frame.frame_pointer.value
        ),
        "frame_size": None if frame.frame_size is None else _hex(frame.frame_size),
        "stack_depth_known": frame.stack_depth_known,
    }


def _argument_json(argument: ArgumentEvidence) -> dict[str, object]:
    return {
        "index": argument.index,
        "kind": argument.kind.value,
        "register": None if argument.register is None else argument.register.value,
        "stack_offset": (
            None
            if argument.stack_offset is None
            else _signed_hex(argument.stack_offset)
        ),
        "uses": [_hex(address) for address in argument.uses],
    }


def _return_json(evidence: ReturnEvidence) -> dict[str, object]:
    return {
        "return_address": _hex(evidence.return_address),
        "value": _abstract_value_json(evidence.value),
    }


def _summary_json(summary: FunctionSummary | None) -> dict[str, object] | None:
    if summary is None:
        return None
    return {
        "arguments": [_argument_json(argument) for argument in summary.arguments],
        "returns": [_return_json(evidence) for evidence in summary.returns],
        "stack_frame": _stack_frame_json(summary.stack_frame),
        "stack_slots": [_stack_slot_json(slot) for slot in summary.stack_slots],
    }


def _data_flow_json(flow: FunctionDataFlow | None) -> dict[str, object] | None:
    if flow is None:
        return None
    return {
        "blocks": [_block_flow_json(block) for block in flow.blocks],
        "function": _function_candidate_json(flow.function),
        "instructions": [
            _instruction_flow_json(instruction) for instruction in flow.instructions
        ],
        "summary": _summary_json(flow.summary),
        "warnings": list(flow.warnings),
    }


def _symbol_json(symbol: Symbol) -> dict[str, object]:
    return {
        "address": _hex(symbol.address),
        "component": symbol.component,
        "confidence": symbol.confidence,
        "evidence": list(symbol.evidence),
        "instruction_set": (
            None if symbol.instruction_set is None else symbol.instruction_set.value
        ),
        "kind": symbol.kind.value,
        "name": symbol.name,
        "offset": _hex(symbol.offset),
    }


def _xref_json(reference: CrossReference) -> dict[str, object]:
    return {
        "kind": reference.kind.value,
        "source_address": _hex(reference.source_address),
        "source_component": reference.source_component,
        "source_function_address": (
            None
            if reference.source_function_address is None
            else _hex(reference.source_function_address)
        ),
        "source_instruction_set": (
            None
            if reference.source_instruction_set is None
            else reference.source_instruction_set.value
        ),
        "target_address": _hex(reference.target_address),
        "target_instruction_set": (
            None
            if reference.target_instruction_set is None
            else reference.target_instruction_set.value
        ),
    }


def _annotation_json(
    annotation: LocationAnnotation | None,
) -> dict[str, object] | None:
    if annotation is None:
        return None
    return {
        "address": _hex(annotation.address),
        "bookmarked": annotation.bookmarked,
        "comment": annotation.comment,
        "component": annotation.component,
        "name_override": annotation.name_override,
        "tags": list(annotation.tags),
    }


def _decompilation_json(result: DecompilationResult) -> dict[str, object]:
    return {
        "address": _hex(result.ir.address),
        "component": result.ir.component,
        "fallback_used": result.structured.fallback_used,
        "instruction_set": result.ir.instruction_set.value,
        "name": result.ir.name,
        "pseudo_c": result.pseudo_c,
        "warnings": list(result.ir.warnings),
    }


def _add_output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path)


def add_project_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "project",
        help="create and query persistent .ndsre analysis projects",
    )
    commands = parser.add_subparsers(dest="project_command")

    create_parser = commands.add_parser("create", help="create an analysis project")
    create_parser.add_argument("project", type=Path)
    _add_output_argument(create_parser)

    info_parser = commands.add_parser("info", help="show project metadata")
    info_parser.add_argument("project", type=Path)
    _add_output_argument(info_parser)

    functions_parser = commands.add_parser("functions", help="list persisted functions")
    functions_parser.add_argument("project", type=Path)
    functions_parser.add_argument("--component")
    _add_output_argument(functions_parser)

    function_parser = commands.add_parser("function", help="inspect one persisted function")
    function_parser.add_argument("project", type=Path)
    function_parser.add_argument("component")
    function_parser.add_argument("address", type=_auto_int)
    function_parser.add_argument("instruction_set", type=_instruction_set)
    _add_output_argument(function_parser)

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

    strings_parser = commands.add_parser("strings", help="list persisted strings")
    strings_parser.add_argument("project", type=Path)
    strings_parser.add_argument("--component")
    strings_parser.add_argument("--contains")
    _add_output_argument(strings_parser)

    symbols_parser = commands.add_parser("symbols", help="query persisted symbols")
    symbols_parser.add_argument("project", type=Path)
    symbol_selector = symbols_parser.add_mutually_exclusive_group(required=True)
    symbol_selector.add_argument("--name")
    symbol_selector.add_argument("--address", type=_auto_int)
    symbols_parser.add_argument("--component")
    _add_output_argument(symbols_parser)

    xrefs_from_parser = commands.add_parser(
        "xrefs-from", help="list cross-references from one source address"
    )
    xrefs_from_parser.add_argument("project", type=Path)
    xrefs_from_parser.add_argument("component")
    xrefs_from_parser.add_argument("address", type=_auto_int)
    _add_output_argument(xrefs_from_parser)

    xrefs_to_parser = commands.add_parser(
        "xrefs-to", help="list cross-references targeting one address"
    )
    xrefs_to_parser.add_argument("project", type=Path)
    xrefs_to_parser.add_argument("address", type=_auto_int)
    xrefs_to_parser.add_argument("--source-component")
    _add_output_argument(xrefs_to_parser)

    annotations_parser = commands.add_parser(
        "annotations", help="list persistent user annotations"
    )
    annotations_parser.add_argument("project", type=Path)
    annotations_parser.add_argument("--component")
    _add_output_argument(annotations_parser)

    annotate_parser = commands.add_parser(
        "annotate", help="update a persistent user annotation"
    )
    annotate_parser.add_argument("project", type=Path)
    annotate_parser.add_argument("component")
    annotate_parser.add_argument("address", type=_auto_int)

    name_group = annotate_parser.add_mutually_exclusive_group()
    name_group.add_argument("--name")
    name_group.add_argument("--clear-name", action="store_true")

    comment_group = annotate_parser.add_mutually_exclusive_group()
    comment_group.add_argument("--comment")
    comment_group.add_argument("--clear-comment", action="store_true")

    tag_group = annotate_parser.add_mutually_exclusive_group()
    tag_group.add_argument("--tag", action="append")
    tag_group.add_argument("--clear-tags", action="store_true")

    bookmark_group = annotate_parser.add_mutually_exclusive_group()
    bookmark_group.add_argument(
        "--bookmark", dest="bookmark", action="store_const", const=True
    )
    bookmark_group.add_argument(
        "--unbookmark", dest="bookmark", action="store_const", const=False
    )
    annotate_parser.set_defaults(bookmark=None)
    _add_output_argument(annotate_parser)


def _run_create(arguments: argparse.Namespace) -> int:
    with AnalysisProject.create(arguments.project) as project:
        payload = {
            "components": [],
            "metadata": _metadata_json(project.metadata),
            "project": str(project.root),
        }
    _write_json(payload, arguments.output)
    return 0


def _run_info(arguments: argparse.Namespace) -> int:
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        payload = {
            "components": [
                _component_identity_json(identity)
                for identity in project.component_identities()
            ],
            "metadata": _metadata_json(project.metadata),
            "project": str(project.root),
        }
    _write_json(payload, arguments.output)
    return 0


def _run_functions(arguments: argparse.Namespace) -> int:
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        functions = project.functions(component=arguments.component)
    payload: dict[str, object] = {
        "functions": [_function_candidate_json(function) for function in functions]
    }
    if arguments.component is not None:
        payload["component"] = arguments.component
    _write_json(payload, arguments.output)
    return 0


def _run_function(arguments: argparse.Namespace) -> int:
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        function = project.function(
            arguments.component,
            arguments.address,
            arguments.instruction_set,
        )
        if function is None:
            raise AnalysisProjectError(
                "analysis function not found: "
                f"{arguments.component} {_hex(arguments.address)} "
                f"{arguments.instruction_set.value}"
            )
        payload = {
            "annotation": _annotation_json(
                project.annotation(arguments.component, arguments.address)
            ),
            "cfg": _cfg_json(
                project.cfg(
                    arguments.component,
                    arguments.address,
                    arguments.instruction_set,
                )
            ),
            "data_flow": _data_flow_json(
                project.data_flow(
                    arguments.component,
                    arguments.address,
                    arguments.instruction_set,
                )
            ),
            "function": _function_candidate_json(function),
        }
    _write_json(payload, arguments.output)
    return 0


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


def _run_strings(arguments: argparse.Namespace) -> int:
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        records = project.strings(component=arguments.component)
    if arguments.contains is not None:
        needle = arguments.contains.casefold()
        records = tuple(record for record in records if needle in record.text.casefold())
    payload: dict[str, object] = {
        "strings": [_string_json(record) for record in records]
    }
    if arguments.component is not None:
        payload["component"] = arguments.component
    if arguments.contains is not None:
        payload["contains"] = arguments.contains
    _write_json(payload, arguments.output)
    return 0


def _run_symbols(arguments: argparse.Namespace) -> int:
    if arguments.address is not None and arguments.component is None:
        raise ValueError("--component is required with --address")
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        if arguments.name is not None:
            symbols = project.symbols_named(
                arguments.name,
                component=arguments.component,
            )
        else:
            symbols = project.symbols_at(arguments.component, arguments.address)
    payload = {"symbols": [_symbol_json(symbol) for symbol in symbols]}
    _write_json(payload, arguments.output)
    return 0


def _run_xrefs_from(arguments: argparse.Namespace) -> int:
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        references = project.xrefs_from(arguments.component, arguments.address)
    _write_json(
        {"xrefs": [_xref_json(reference) for reference in references]},
        arguments.output,
    )
    return 0


def _run_xrefs_to(arguments: argparse.Namespace) -> int:
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        references = project.xrefs_to(
            arguments.address,
            source_component=arguments.source_component,
        )
    _write_json(
        {"xrefs": [_xref_json(reference) for reference in references]},
        arguments.output,
    )
    return 0


def _run_annotations(arguments: argparse.Namespace) -> int:
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        annotations = project.annotations(component=arguments.component)
    payload: dict[str, object] = {
        "annotations": [_annotation_json(annotation) for annotation in annotations]
    }
    if arguments.component is not None:
        payload["component"] = arguments.component
    _write_json(payload, arguments.output)
    return 0


def _run_annotate(arguments: argparse.Namespace) -> int:
    has_mutation = (
        arguments.name is not None
        or arguments.clear_name
        or arguments.comment is not None
        or arguments.clear_comment
        or arguments.tag is not None
        or arguments.clear_tags
        or arguments.bookmark is not None
    )
    if not has_mutation:
        raise ValueError("at least one annotation field must be changed")

    with AnalysisProject.open(arguments.project, read_only=False) as project:
        current = project.annotation(arguments.component, arguments.address)
        if current is None:
            current = LocationAnnotation(arguments.component, arguments.address)

        if arguments.clear_name:
            name_override = None
        elif arguments.name is not None:
            name_override = arguments.name
        else:
            name_override = current.name_override

        if arguments.clear_comment:
            comment = None
        elif arguments.comment is not None:
            comment = arguments.comment
        else:
            comment = current.comment

        if arguments.clear_tags:
            tags: tuple[str, ...] = ()
        elif arguments.tag is not None:
            tags = tuple(arguments.tag)
        else:
            tags = current.tags

        bookmarked = (
            current.bookmarked
            if arguments.bookmark is None
            else arguments.bookmark
        )

        updated = LocationAnnotation(
            component=arguments.component,
            address=arguments.address,
            name_override=name_override,
            comment=comment,
            tags=tags,
            bookmarked=bookmarked,
        )
        project.set_annotation(updated)

    _write_json({"annotation": _annotation_json(updated)}, arguments.output)
    return 0


def run_project_command(arguments: argparse.Namespace) -> int:
    if arguments.project_command is None:
        print("usage: nds-toolkit project <subcommand> ...", file=sys.stderr)
        return 2
    if arguments.project_command == "create":
        return _run_create(arguments)
    if arguments.project_command == "info":
        return _run_info(arguments)
    if arguments.project_command == "functions":
        return _run_functions(arguments)
    if arguments.project_command == "function":
        return _run_function(arguments)
    if arguments.project_command == "decompile":
        return _run_decompile(arguments)
    if arguments.project_command == "strings":
        return _run_strings(arguments)
    if arguments.project_command == "symbols":
        return _run_symbols(arguments)
    if arguments.project_command == "xrefs-from":
        return _run_xrefs_from(arguments)
    if arguments.project_command == "xrefs-to":
        return _run_xrefs_to(arguments)
    if arguments.project_command == "annotations":
        return _run_annotations(arguments)
    if arguments.project_command == "annotate":
        return _run_annotate(arguments)
    raise AnalysisProjectError(
        f"project command is not implemented: {arguments.project_command}"
    )