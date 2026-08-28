from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from nds_disassembly_toolkit.analysis.model import InstructionSet, OperandAccess
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


def run_project_command(arguments: argparse.Namespace) -> int:
    if arguments.project_command is None:
        print("usage: nds-toolkit project <subcommand> ...", file=sys.stderr)
        return 2
    raise AnalysisProjectError(
        f"project command is not implemented: {arguments.project_command}"
    )
