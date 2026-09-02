from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Callable

from nds_disassembly_toolkit.analysis.investigation import (
    InvestigationCandidate,
    InvestigationReport,
    InvestigationRequest,
    investigate_project,
)
from nds_disassembly_toolkit.analysis.project import AnalysisProject

_JsonWriter = Callable[[object, Path | None], None]
_TextWriter = Callable[[str, Path | None], None]


def _unsigned_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer/address: {value}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError(f"address must be non-negative: {value}")
    return parsed


def _signed_int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc


def _hex(value: int) -> str:
    return f"0x{value:08x}"


def add_investigate_parser(commands: Any) -> None:
    parser = commands.add_parser(
        "investigate",
        help="rank persisted functions by static and runtime evidence",
    )
    parser.add_argument("project", type=Path)
    parser.add_argument("--text")
    parser.add_argument("--constant", dest="constants", type=_signed_int, action="append", default=[])
    parser.add_argument("--address", dest="addresses", type=_unsigned_int, action="append", default=[])
    parser.add_argument("--component")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--decompile", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", type=Path)


def _annotation_json(candidate: InvestigationCandidate) -> dict[str, object] | None:
    annotation = candidate.annotation
    if annotation is None:
        return None
    return {
        "comment": annotation.comment,
        "name_override": annotation.name_override,
        "tags": list(annotation.tags),
    }


def _candidate_json(rank: int, candidate: InvestigationCandidate) -> dict[str, object]:
    return {
        "address": _hex(candidate.function.address),
        "annotation": _annotation_json(candidate),
        "component": candidate.function.component,
        "evidence": [
            {
                "addresses": [_hex(address) for address in evidence.addresses],
                "contribution": evidence.contribution,
                "kind": evidence.kind.value,
                "reasons": list(evidence.reasons),
                "value": evidence.value,
                "weight": evidence.weight,
            }
            for evidence in candidate.evidence
        ],
        "instruction_set": candidate.function.instruction_set.value,
        "name": candidate.name,
        "pseudo_c": candidate.pseudo_c,
        "pseudo_c_error": candidate.pseudo_c_error,
        "rank": rank,
        "score": candidate.score,
        "symbols": [
            {
                "address": _hex(symbol.address),
                "confidence": symbol.confidence,
                "instruction_set": (
                    None
                    if symbol.instruction_set is None
                    else symbol.instruction_set.value
                ),
                "kind": symbol.kind.value,
                "name": symbol.name,
            }
            for symbol in candidate.symbols
        ],
    }


def _report_json(report: InvestigationReport) -> dict[str, object]:
    request = report.request
    return {
        "candidates": [
            _candidate_json(rank, candidate)
            for rank, candidate in enumerate(report.candidates, start=1)
        ],
        "request": {
            "addresses": [_hex(address) for address in request.addresses],
            "baseline": (
                None if request.baseline_trace is None else str(request.baseline_trace)
            ),
            "component": request.component,
            "constants": list(request.constants),
            "include_pseudo_c": request.include_pseudo_c,
            "target": None if request.target_trace is None else str(request.target_trace),
            "text": request.text,
            "top": request.top,
        },
    }


def _report_text(report: InvestigationReport) -> str:
    lines: list[str] = []
    for rank, candidate in enumerate(report.candidates, start=1):
        function = candidate.function
        lines.append(
            f"{rank}. {candidate.score:.6f} {function.component}:"
            f"{_hex(function.address)} ({function.instruction_set.value}) {candidate.name}"
        )
        for evidence in candidate.evidence:
            lines.append(
                f"   - {evidence.kind.value} +{evidence.contribution:.6f}"
            )
            lines.extend(f"     {reason}" for reason in evidence.reasons)
        if candidate.pseudo_c is not None:
            lines.append("")
            lines.extend(f"   {line}" for line in candidate.pseudo_c.rstrip().splitlines())
        elif candidate.pseudo_c_error is not None:
            lines.append(f"   pseudo-c unavailable: {candidate.pseudo_c_error}")
    if not lines:
        return "No matching investigation candidates.\n"
    return "\n".join(lines) + "\n"


def run_investigate_command(
    arguments: argparse.Namespace,
    write_json: _JsonWriter,
    write_text: _TextWriter,
) -> int:
    request = InvestigationRequest(
        text=arguments.text,
        constants=tuple(arguments.constants),
        addresses=tuple(arguments.addresses),
        component=arguments.component,
        baseline_trace=arguments.baseline,
        target_trace=arguments.target,
        top=arguments.top,
        include_pseudo_c=arguments.decompile,
    )
    request.validate()
    with AnalysisProject.open(arguments.project, read_only=True) as project:
        report = investigate_project(project, request)
    if arguments.json:
        write_json(_report_json(report), arguments.output)
    else:
        write_text(_report_text(report), arguments.output)
    return 0
