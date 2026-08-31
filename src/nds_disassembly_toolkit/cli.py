from __future__ import annotations

import argparse
import sys
from collections.abc import Collection
from pathlib import Path

from nds_disassembly_toolkit.analysis.cli import add_analysis_parser, run_analysis_command
from nds_disassembly_toolkit.analysis.project_cli import (
    add_project_parser,
    run_project_command,
)
from nds_disassembly_toolkit.assets_cli import add_assets_parser, run_assets_command
from nds_disassembly_toolkit.disassembly_cli import (
    add_disassembly_parser,
    run_disassembly_command,
)
from nds_disassembly_toolkit.errors import NdsToolkitError
from nds_disassembly_toolkit.inspection import inspect_rom
from nds_disassembly_toolkit.patches.apply import apply_patch_set
from nds_disassembly_toolkit.profile import RomProfile, load_profile
from nds_disassembly_toolkit.source_patch_cli import (
    add_source_patch_parser,
    run_source_patch_command,
)
from nds_disassembly_toolkit.workspace.extract import ExtractionOptions, extract_workspace
from nds_disassembly_toolkit.workspace.rebuild import RebuildOptions, rebuild_rom

_ROM_COMMANDS = frozenset({"inspect", "extract", "rebuild"})


def _add_profile_policy(
    parser: argparse.ArgumentParser,
    *,
    supported_by_default: bool,
    allow_unsupported: bool,
) -> None:
    if supported_by_default:
        parser.set_defaults(require_supported=True)
        if allow_unsupported:
            parser.add_argument(
                "--allow-unsupported",
                dest="require_supported",
                action="store_false",
                help="use a ROM that does not match the selected profile",
            )
        return
    parser.add_argument("--require-supported", action="store_true")


def add_rom_parsers(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    *,
    default_profile: Path | None = None,
    supported_by_default: bool = False,
    allow_unsupported_commands: Collection[str] = (),
) -> None:
    allow_unsupported = set(allow_unsupported_commands)
    unknown_commands = allow_unsupported - _ROM_COMMANDS
    if unknown_commands:
        names = ", ".join(sorted(unknown_commands))
        raise ValueError(f"unknown ROM command(s) in allow_unsupported_commands: {names}")

    inspect_parser = subparsers.add_parser("inspect", help="inspect Nintendo DS ROM structures")
    inspect_parser.add_argument("rom", type=Path)
    inspect_parser.add_argument("--profile", type=Path, default=default_profile)
    _add_profile_policy(
        inspect_parser,
        supported_by_default=supported_by_default,
        allow_unsupported="inspect" in allow_unsupported,
    )
    inspect_parser.add_argument("--output", type=Path)

    extract_parser = subparsers.add_parser(
        "extract", help="extract a deterministic editable ROM workspace"
    )
    extract_parser.add_argument("rom", type=Path)
    extract_parser.add_argument("workspace", type=Path)
    extract_parser.add_argument("--profile", type=Path, default=default_profile)
    _add_profile_policy(
        extract_parser,
        supported_by_default=supported_by_default,
        allow_unsupported="extract" in allow_unsupported,
    )
    extract_parser.add_argument("--force", action="store_true")

    rebuild_parser = subparsers.add_parser(
        "rebuild", help="rebuild a Nintendo DS ROM from an extracted workspace"
    )
    rebuild_parser.add_argument("rom", type=Path)
    rebuild_parser.add_argument("workspace", type=Path)
    rebuild_parser.add_argument("output", type=Path)
    rebuild_parser.add_argument("--profile", type=Path, default=default_profile)
    _add_profile_policy(
        rebuild_parser,
        supported_by_default=supported_by_default,
        allow_unsupported="rebuild" in allow_unsupported,
    )
    rebuild_parser.add_argument("--force", action="store_true")


def add_patch_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    patch_parser = subparsers.add_parser(
        "patch", help="apply guarded binary replacements to a workspace"
    )
    patch_parser.add_argument("workspace", type=Path)
    patch_parser.add_argument("patch_file", type=Path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nds-toolkit",
        description="NDS Disassembly Toolkit",
    )
    subparsers = parser.add_subparsers(dest="command")

    add_rom_parsers(subparsers)
    add_patch_parser(subparsers)
    add_disassembly_parser(subparsers)
    add_analysis_parser(subparsers)
    add_project_parser(subparsers)
    add_assets_parser(subparsers)
    add_source_patch_parser(subparsers)
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


def run_rom_command(arguments: argparse.Namespace) -> int:
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
    raise NdsToolkitError("an inspect, extract, or rebuild command is required")


def run_patch_command(arguments: argparse.Namespace) -> int:
    workspace = arguments.workspace.expanduser().resolve()
    patch_file = arguments.patch_file.expanduser().resolve()
    report = apply_patch_set(workspace, patch_file)
    report_path = workspace / "manifests" / f"patch-{patch_file.stem}.json"
    print(
        f"Applied {len(report.applied)} patches to {workspace}; "
        f"report: {report_path}"
    )
    return 0


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
        if arguments.command == "project":
            return run_project_command(arguments)
        if arguments.command == "assets":
            return run_assets_command(arguments)
        if arguments.command == "source-patch":
            return run_source_patch_command(arguments)
        if arguments.command == "patch":
            return run_patch_command(arguments)
        if arguments.command in _ROM_COMMANDS:
            return run_rom_command(arguments)
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
