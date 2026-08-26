from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.source_compile import (
    SourceToolchain,
    build_compile_command,
    build_link_command,
    build_linker_script,
    compile_source_patch,
    parse_nm_symbols,
)
from nds_disassembly_toolkit.source_patch import load_source_patch_manifest


def _payload() -> dict[str, object]:
    return {
        "format_version": 1,
        "target": "overlay:7",
        "runtime_address": 0x0221A000,
        "max_size": 0x100,
        "mode": "arm",
        "expected_runtime_sha256": hashlib.sha256(b"target").hexdigest(),
        "sources": ["src/injected.c"],
        "definitions": {"known_helper": 0x02065BF4},
        "hooks": [],
    }


def _manifest(tmp_path: Path):
    path = tmp_path / "source-patch.json"
    path.write_text(json.dumps(_payload()), encoding="utf-8")
    return path, load_source_patch_manifest(path)


def test_compile_and_link_commands_remain_explicit_and_deterministic() -> None:
    toolchain = SourceToolchain(clang="clang-custom", ld="lld-custom", nm="nm-custom")
    compile_command = build_compile_command(
        toolchain, Path("entry.c"), Path("entry.o"), mode="arm"
    )
    assert compile_command[:4] == (
        "clang-custom",
        "--target=arm-none-eabi",
        "-mcpu=arm946e-s",
        "-marm",
    )
    assert "-ffreestanding" in compile_command

    script = build_linker_script(0x0221A000, 0x100)
    assert ". = 0x0221A000;" in script
    assert 'ASSERT(SIZEOF(.bss) == 0, "BSS forbidden")' in script
    assert "0x0221A100" in script

    link_command = build_link_command(
        toolchain,
        objects=(Path("b.o"), Path("a.o")),
        linker_script=Path("link.ld"),
        output=Path("out.bin"),
        definitions=(("zeta", 0x30), ("alpha", 0x20)),
        binary=True,
    )
    assert link_command.index("--defsym=alpha=0x00000020") < link_command.index(
        "--defsym=zeta=0x00000030"
    )
    assert link_command.index("a.o") < link_command.index("b.o")
    assert "--oformat=binary" in link_command


def test_nm_symbols_are_sorted_and_duplicate_names_rejected() -> None:
    assert parse_nm_symbols(
        "0221a010 T second\n0221a000 T entry\n02065bf4 A known_helper\n"
    ) == (
        ("known_helper", 0x02065BF4),
        ("entry", 0x0221A000),
        ("second", 0x0221A010),
    )
    with pytest.raises(WorkspaceError, match="duplicate symbol"):
        parse_nm_symbols("0221a000 T entry\n0221a004 T entry\n")


def test_compile_source_patch_returns_binary_symbols_hashes_and_normalized_commands(
    tmp_path: Path,
) -> None:
    manifest_path, manifest = _manifest(tmp_path)
    source = tmp_path / "src" / "injected.c"
    source.parent.mkdir(parents=True)
    source.write_text("int entry(int x) { return x + 1; }\n", encoding="utf-8")

    def fake_run(command: tuple[str, ...]) -> str:
        if command[0] == "clang":
            Path(command[command.index("-o") + 1]).write_bytes(b"object")
        elif command[0] == "ld.lld":
            output = Path(command[command.index("-o") + 1])
            output.write_bytes(bytes.fromhex("0100a0e3") if "--oformat=binary" in command else b"elf")
        elif command[0] == "nm":
            return "0221a000 T entry\n02065bf4 A known_helper\n"
        return ""

    result = compile_source_patch(
        manifest_path,
        manifest,
        SourceToolchain(),
        runner=fake_run,
    )

    assert result.image == bytes.fromhex("0100a0e3")
    assert result.symbol_address("entry") == 0x0221A000
    assert result.source_hashes == (
        ("src/injected.c", hashlib.sha256(source.read_bytes()).hexdigest()),
    )
    assert len(result.commands) == 4
    assert all("bakugan" not in " ".join(command).lower() for command in result.commands)
