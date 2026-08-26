from __future__ import annotations

import argparse
import sys
from pathlib import Path

from nds_disassembly_toolkit.analysis.cli import add_analysis_parser, run_analysis_command
from nds_disassembly_toolkit.assets_cli import add_assets_parser, run_assets_command
from nds_disassembly_toolkit.disassembly_cli import (
    add_disassembly_parser,
    run_disassembly_command,
)
from nds_disassembly_toolkit.errors import NdsToolkitError
from nds_disassembly_toolkit.inspection import inspect_rom
from nds_disassembly_toolkit.profile import RomProfile, load_profile
from nds_disassembly_toolkit.workspace.extract import ExtractionOptions, extract_workspace
from nds_disassembly_toolkit.workspace.rebuild import RebuildOptions, rebuild_rom


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nds-toolkit",
        description="NDS Disassembly Toolkit",
    )
    subparsers = parser.add_subparsers(dest="command")

    inspect_parser = subparsers.add_parser("inspect", help="inspect Nintendo DS ROM structures")
    inspect_parser.add_argument("rom", type=Path)
    inspect_parser.add_argument("--profile", type=Path)
    inspect_parser.add_argument("--require-supported", action="store_true")
    inspect_parser.add_argument("--output", type=Path)

    extract_parser = subparsers.add_parser(
        "extract", help="extract a deterministic editable ROM workspace"
    )
    extract_parser.add_argument("rom", type=Path)
    extract_parser.add_argument("workspace", type=Path)
    extract_parser.add_argument("--profile", type=Path)
    extract_parser.add_argument("--require-supported", action="store_true")
    extract_parser.add_argument("--force", action="store_true")

    rebuild_parser = subparsers.add_parser(
        "rebuild", help="rebuild a Nintendo DS ROM from an extracted workspace"
    )
    rebuild_parser.add_argument("rom", type=Path)
    rebuild_parser.add_argument("workspace", type=Path)
    rebuild_parser.add_argument("output", type=Path)
    rebuild_parser.add_argument("--profile", type=Path)
    rebuild_parser.add_argument("--require-supported", action="store_true")
    rebuild_parser.add_argument("--force", action="store_true")

    add_disassembly_parser(subparsers)
    add_analysis_parser(subparsers)
    add_assets_parser(subparsers)
    return parser


def _write_report(report: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(report)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(report, encoding="utf-8")
    temporary.replace(output)


def _optional_profile(path: Path | None) -> RomProfile | None:
    return None if path is None else load_profile(path)


def _require_profile_if_requested(profile: RomProfile | None, require_supported: bool) -> None:
    if require_supported and profile is None:
        raise ValueError("--require-supported requires --profile")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    if not args:
        parser.print_help()
        return 0
    arguments = parser.parse_args(args)
    if arguments.command is None:
        parser.print_help()
        return 0

    try:
        if arguments.command == "disasm":
            return run_disassembly_command(arguments)
        if arguments.command == "analyze":
            return run_analysis_command(arguments)
        if arguments.command == "assets":
            return run_assets_command(arguments)

        profile = _optional_profile(arguments.profile)
        _require_profile_if_requested(profile, arguments.require_supported)
        if arguments.command == "inspect":
            inspection = inspect_rom(
                arguments.rom,
                profile=profile,
                require_supported=arguments.require_supported,
            )
            _write_report(inspection.to_json(), arguments.output)
            return 0
        if arguments.command == "extract":
            workspace = arguments.workspace.expanduser().resolve()
            manifest = extract_workspace(
                arguments.rom,
                ExtractionOptions(workspace=workspace, force=arguments.force),
                profile=profile,
                require_supported=arguments.require_supported,
            )
            print(
                f"Extracted workspace {workspace} "
                f"({len(manifest.files)} files, {len(manifest.overlays)} overlays); "
                f"manifest: {workspace / 'manifests/workspace.json'}"
            )
            return 0
        if arguments.command == "rebuild":
            output = arguments.output.expanduser().resolve()
            report = rebuild_rom(
                arguments.rom,
                arguments.workspace,
                RebuildOptions(output=output, force=arguments.force),
                profile=profile,
                require_supported=arguments.require_supported,
            )
            report_path = output.with_suffix(output.suffix + ".build.json")
            print(
                f"Rebuilt ROM {output} ({len(report.changes)} changes, "
                f"sha256 {report.output_sha256}); report: {report_path}"
            )
            return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except NdsToolkitError as exc:
        print(str(exc), file=sys.stderr)
        return 4
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 5
    parser.print_usage(sys.stderr)
    return 2
