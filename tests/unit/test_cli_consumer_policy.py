from __future__ import annotations

import argparse
from pathlib import Path

from nds_disassembly_toolkit import assets_cli, disassembly_cli, source_patch_cli


def _subparsers() -> argparse._SubParsersAction[argparse.ArgumentParser]:
    parser = argparse.ArgumentParser()
    return parser.add_subparsers(dest="command")


def test_assets_parser_can_require_supported_profile_by_default(tmp_path: Path) -> None:
    default_profile = tmp_path / "profile.json"
    subparsers = _subparsers()

    assets_cli.add_assets_parser(
        subparsers,
        default_profile=default_profile,
        supported_by_default=True,
    )

    parser = subparsers.container
    arguments = parser.parse_args(["assets", "inventory", "game.nds"])
    assert arguments.profile == default_profile
    assert arguments.require_supported is True

    arguments = parser.parse_args(
        ["assets", "inventory", "game.nds", "--allow-unsupported"]
    )
    assert arguments.require_supported is False


def test_disassembly_parser_can_require_supported_profile_by_default(tmp_path: Path) -> None:
    default_profile = tmp_path / "profile.json"
    subparsers = _subparsers()

    disassembly_cli.add_disassembly_parser(
        subparsers,
        default_profile=default_profile,
        supported_by_default=True,
    )

    parser = subparsers.container
    arguments = parser.parse_args(["disasm", "overlay-map", "game.nds"])
    assert arguments.profile == default_profile
    assert arguments.require_supported is True

    arguments = parser.parse_args(
        ["disasm", "overlay-map", "game.nds", "--allow-unsupported"]
    )
    assert arguments.require_supported is False


def test_source_patch_parser_can_supply_consumer_default_profile(tmp_path: Path) -> None:
    default_profile = tmp_path / "profile.json"
    subparsers = _subparsers()

    source_patch_cli.add_source_patch_parser(
        subparsers,
        default_profile=default_profile,
    )

    parser = subparsers.container
    arguments = parser.parse_args(["source-patch", "build", "workspace", "patch.json"])
    assert arguments.profile == default_profile
