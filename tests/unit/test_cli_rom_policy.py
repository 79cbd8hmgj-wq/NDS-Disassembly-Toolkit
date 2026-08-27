from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from nds_disassembly_toolkit import cli


def _parser_and_subparsers() -> tuple[
    argparse.ArgumentParser,
    argparse._SubParsersAction[argparse.ArgumentParser],
]:
    parser = argparse.ArgumentParser()
    return parser, parser.add_subparsers(dest="command")


def test_rom_parsers_can_apply_strict_consumer_policy(tmp_path: Path) -> None:
    default_profile = tmp_path / "profile.json"
    parser, subparsers = _parser_and_subparsers()

    cli.add_rom_parsers(
        subparsers,
        default_profile=default_profile,
        supported_by_default=True,
        allow_unsupported_commands={"inspect"},
    )

    inspect_args = parser.parse_args(["inspect", "game.nds"])
    assert inspect_args.profile == default_profile
    assert inspect_args.require_supported is True

    relaxed = parser.parse_args(["inspect", "game.nds", "--allow-unsupported"])
    assert relaxed.require_supported is False

    extract_args = parser.parse_args(["extract", "game.nds", "workspace"])
    assert extract_args.profile == default_profile
    assert extract_args.require_supported is True

    rebuild_args = parser.parse_args(
        ["rebuild", "game.nds", "workspace", "rebuilt.nds"]
    )
    assert rebuild_args.profile == default_profile
    assert rebuild_args.require_supported is True

    with pytest.raises(SystemExit):
        parser.parse_args(
            ["extract", "game.nds", "workspace", "--allow-unsupported"]
        )


def test_rom_parsers_keep_toolkit_defaults_profile_optional() -> None:
    parser, subparsers = _parser_and_subparsers()
    cli.add_rom_parsers(subparsers)

    arguments = parser.parse_args(["inspect", "game.nds"])
    assert arguments.profile is None
    assert arguments.require_supported is False

    arguments = parser.parse_args(
        ["inspect", "game.nds", "--require-supported"]
    )
    assert arguments.require_supported is True


def test_rom_parser_rejects_unknown_unsupported_escape_command() -> None:
    _, subparsers = _parser_and_subparsers()

    with pytest.raises(ValueError, match="unknown ROM command"):
        cli.add_rom_parsers(
            subparsers,
            supported_by_default=True,
            allow_unsupported_commands={"patch"},
        )
