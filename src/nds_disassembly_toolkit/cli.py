from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="nds-toolkit",
        description="NDS Disassembly Toolkit",
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    if not args:
        parser.print_help()
        return 0
    parser.parse_args(args)
    return 0
