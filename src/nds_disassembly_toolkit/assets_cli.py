from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from nds_disassembly_toolkit.assets import inventory_assets
from nds_disassembly_toolkit.errors import NdsToolkitError
from nds_disassembly_toolkit.inspection import inspect_rom
from nds_disassembly_toolkit.profile import RomProfile, load_profile


def add_assets_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    assets_parser = subparsers.add_parser("assets", help="inspect Nintendo DS game assets")
    asset_subparsers = assets_parser.add_subparsers(dest="assets_command")

    inventory_parser = asset_subparsers.add_parser(
        "inventory",
        help="inventory recognized NitroFS asset formats",
    )
    inventory_parser.add_argument("rom", type=Path)
    inventory_parser.add_argument("--profile", type=Path)
    inventory_parser.add_argument("--require-supported", action="store_true")
    inventory_parser.add_argument("--output", type=Path)
    inventory_parser.add_argument(
        "--include-unknown",
        action="store_true",
        help="include unrecognized NitroFS files in the detailed record list",
    )


def _write_report(report: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(report)
        return
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        prefix=f".{output.name}.tmp-",
        dir=output.parent,
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(report.encode("utf-8"))
            handle.flush()
        temporary.replace(output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _optional_profile(path: Path | None) -> RomProfile | None:
    return None if path is None else load_profile(path)


def run_assets_command(arguments: argparse.Namespace) -> int:
    if arguments.assets_command != "inventory":
        raise NdsToolkitError("an assets subcommand is required")

    profile = _optional_profile(arguments.profile)
    if arguments.require_supported and profile is None:
        raise ValueError("--require-supported requires --profile")
    inspection = inspect_rom(
        arguments.rom,
        profile=profile,
        require_supported=arguments.require_supported,
    )
    rom_data = arguments.rom.read_bytes()
    inventory = inventory_assets(
        rom_data,
        inspection,
        include_unknown=arguments.include_unknown,
    )
    _write_report(inventory.to_json(), arguments.output)
    return 0
