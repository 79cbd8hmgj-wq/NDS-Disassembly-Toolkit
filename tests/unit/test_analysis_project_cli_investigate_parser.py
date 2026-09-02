from pathlib import Path

from nds_disassembly_toolkit.analysis.model import InstructionSet
from nds_disassembly_toolkit.cli import build_parser


def test_project_investigate_parser_accepts_complete_selector_set() -> None:
    arguments = build_parser().parse_args(
        [
            "project",
            "investigate",
            "game.ndsre",
            "--text",
            "score",
            "--constant",
            "0x1f4",
            "--constant=-1",
            "--address",
            "0x04000208",
            "--component",
            "arm9",
            "--baseline",
            "idle.ndstrace",
            "--target",
            "attack.ndstrace",
            "--top",
            "10",
            "--decompile",
            "--json",
            "--output",
            "report.json",
        ]
    )

    assert arguments.project_command == "investigate"
    assert arguments.project == Path("game.ndsre")
    assert arguments.text == "score"
    assert arguments.constants == [500, -1]
    assert arguments.addresses == [0x04000208]
    assert arguments.component == "arm9"
    assert arguments.baseline == Path("idle.ndstrace")
    assert arguments.target == Path("attack.ndstrace")
    assert arguments.top == 10
    assert arguments.decompile is True
    assert arguments.json is True
    assert arguments.output == Path("report.json")


def test_existing_instruction_set_parser_remains_publicly_usable() -> None:
    assert InstructionSet.ARM.value == "arm"
