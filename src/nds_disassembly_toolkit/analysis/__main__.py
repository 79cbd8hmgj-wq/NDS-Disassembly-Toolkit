from __future__ import annotations

import argparse
import sys

from nds_disassembly_toolkit.analysis.cli import add_analysis_parser, run_analysis_command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m nds_disassembly_toolkit.analysis")
    subparsers = parser.add_subparsers(dest="command")
    add_analysis_parser(subparsers)
    args = sys.argv[1:] if argv is None else argv
    if not args:
        parser.print_help()
        return 0
    arguments = parser.parse_args(["analyze", *args] if args[0] != "analyze" else args)
    try:
        return run_analysis_command(arguments)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
