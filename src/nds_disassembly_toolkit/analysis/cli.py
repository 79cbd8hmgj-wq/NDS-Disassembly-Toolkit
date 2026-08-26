from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

from nds_disassembly_toolkit.analysis.model import Component
from nds_disassembly_toolkit.analysis.report import analyze_components, write_report


def _auto_int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer/address: {value}") from exc


def add_analysis_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "analyze",
        help="scan flat executable components for strings, pointers, and numeric rows",
    )
    parser.add_argument(
        "--component",
        action="append",
        nargs=3,
        metavar=("NAME", "PATH", "BASE"),
        required=True,
        help="repeatable component specification",
    )
    parser.add_argument("--keyword", action="append", default=[])
    parser.add_argument("--minimum-string-length", type=int, default=4)
    parser.add_argument("--numeric-records", type=Path)
    parser.add_argument("--numeric-values-key")
    parser.add_argument("--numeric-divisor", type=int)
    parser.add_argument("--output", type=Path)


def _load_components(specs: list[list[str]]) -> tuple[Component, ...]:
    components: list[Component] = []
    for name, path_text, base_text in specs:
        path = Path(path_text)
        components.append(
            Component(
                name=name,
                path=path,
                base_address=_auto_int(base_text),
                data=path.read_bytes(),
            )
        )
    return tuple(components)


def _load_numeric_records(path: Path | None) -> tuple[dict[str, object], ...]:
    if path is None:
        return ()
    payload: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("numeric records JSON must be an array")
    rows: list[dict[str, object]] = []
    for index, value in enumerate(payload):
        if not isinstance(value, dict):
            raise ValueError(f"numeric records entry {index} must be an object")
        rows.append(cast(dict[str, object], value))
    return tuple(rows)


def run_analysis_command(arguments: argparse.Namespace) -> int:
    records = _load_numeric_records(arguments.numeric_records)
    numeric_options = (
        arguments.numeric_records,
        arguments.numeric_values_key,
        arguments.numeric_divisor,
    )
    if any(value is not None for value in numeric_options) and arguments.numeric_records is None:
        raise ValueError("numeric scan options require --numeric-records")

    report = analyze_components(
        _load_components(arguments.component),
        keywords=tuple(arguments.keyword),
        minimum_string_length=arguments.minimum_string_length,
        numeric_records=records,
        numeric_values_key=arguments.numeric_values_key,
        numeric_divisor=arguments.numeric_divisor,
    )
    if arguments.output is None:
        sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        write_report(arguments.output, report)
    return 0
