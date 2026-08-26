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
        "target": "overlay:3",
        "runtime_address": 0x02200100,
        "max_size": 0x100,
        "mode": "arm",
        "expected_runtime_sha256": hashlib.sha256(b"target").hexdigest(),
        "sources": ["src/injected.c"],
        "definitions": {"helper": 0x02001000},
        "hooks": [],
    }


def _write_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "source-patch.json"
    path.write_text(json.dumps(_payload()), encoding="utf-8")
    return path


def test_build_compile_command_is_explicit_arm946e_s() -> None:
    command = build_compile_command(
        SourceToolchain(clang="clang-custom"),
        Path("src/injected.c"),
        Path("build/injected.o"),
        mode="arm",
    )

    assert command[:4] == (
        "clang-custom",
        "--target=arm-none-eabi",
        "-mcpu=arm946e-s",
        "-marm",
    )
    assert "-ffreestanding" in command
    assert "-fno-stack-protector" in command


def test_build_compile_command_switches_to_thumb() -> None:
    command = build_compile_command(
        SourceToolchain(), Path("entry.s"), Path("entry.o"), mode="thumb"
    )

    assert "-mthumb" in command
    assert "-marm" not in command


def test_linker_script_binds_approved_range_and_forbids_bss() -> None:
    script = build_linker_script(0x02200100, 0x100)

    assert ". = 0x02200100;" in script
    assert 'ASSERT(SIZEOF(.bss) == 0, "BSS forbidden")' in script
    assert 'ASSERT(. <= 0x02200200, "source patch exceeds approved byte budget")' in script


def test_build_link_command_is_deterministic() -> None:
    command = build_link_command(
        SourceToolchain(ld="lld-custom"),
        objects=(Path("b.o"), Path("a.o")),
        linker_script=Path("link.ld"),
        output=Path("out.bin"),
        definitions=(("zeta", 0x30), ("alpha", 0x20)),
        binary=True,
    )

    assert command.index("--defsym=alpha=0x00000020") < command.index(
        "--defsym=zeta=0x00000030"
    )
    assert command.index("a.o") < command.index("b.o")
    assert "--oformat=binary" in command


def test_parse_nm_symbols_sorts_and_rejects_duplicates() -> None:
    symbols = parse_nm_symbols("02200110 T second\n02200100 T entry\n02001000 A helper\n")
    assert symbols == (
        ("helper", 0x02001000),
        ("entry", 0x02200100),
        ("second", 0x02200110),
    )
    with pytest.raises(WorkspaceError, match="duplicate symbol"):
        parse_nm_symbols("02200100 T entry\n02200104 T entry\n")


def test_compile_source_patch_returns_deterministic_image_and_hashes(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    source = tmp_path / "src" / "injected.c"
    source.parent.mkdir(parents=True)
    source.write_text("int entry(int x) { return x + 1; }\n", encoding="utf-8")
    manifest = load_source_patch_manifest(manifest_path)

    def fake_run(command: tuple[str, ...]) -> str:
        if command[0] == "clang":
            Path(command[command.index("-o") + 1]).write_bytes(b"object")
            return ""
        if command[0] == "ld.lld":
            output = Path(command[command.index("-o") + 1])
            binary = bytes.fromhex("0100a0e3") if "--oformat=binary" in command else b"elf"
            output.write_bytes(binary)
            return ""
        if command[0] == "nm":
            return "02200100 T entry\n02001000 A helper\n"
        raise AssertionError(command)

    result = compile_source_patch(
        manifest_path,
        manifest,
        SourceToolchain(),
        runner=fake_run,
    )

    assert result.image == bytes.fromhex("0100a0e3")
    assert result.source_hashes == (
        ("src/injected.c", hashlib.sha256(source.read_bytes()).hexdigest()),
    )
    assert len(result.commands) == 4
