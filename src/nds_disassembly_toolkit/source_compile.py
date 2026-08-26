from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.workspace.manifest import sha256_bytes


class SourcePatchLike(Protocol):
    @property
    def runtime_address(self) -> int: ...

    @property
    def max_size(self) -> int: ...

    @property
    def mode(self) -> str: ...

    @property
    def sources(self) -> tuple[str, ...]: ...

    @property
    def definitions(self) -> tuple[tuple[str, int], ...]: ...


@dataclass(frozen=True)
class SourceToolchain:
    clang: str = "clang"
    ld: str = "ld.lld"
    nm: str = "nm"


@dataclass(frozen=True)
class CompiledSource:
    image: bytes
    symbols: tuple[tuple[str, int], ...]
    source_hashes: tuple[tuple[str, str], ...]
    commands: tuple[tuple[str, ...], ...]

    def symbol_address(self, name: str) -> int:
        for symbol_name, address in self.symbols:
            if symbol_name == name:
                return address
        raise WorkspaceError(f"compiled source is missing symbol: {name}")


def build_compile_command(
    toolchain: SourceToolchain,
    source: Path,
    output: Path,
    *,
    mode: str,
) -> tuple[str, ...]:
    if mode not in {"arm", "thumb"}:
        raise WorkspaceError(f"unsupported source compile mode: {mode!r}")
    mode_flag = "-marm" if mode == "arm" else "-mthumb"
    return (
        toolchain.clang,
        "--target=arm-none-eabi",
        "-mcpu=arm946e-s",
        mode_flag,
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        "-c",
        str(source),
        "-o",
        str(output),
    )


def build_linker_script(runtime_address: int, max_size: int) -> str:
    end_address = runtime_address + max_size
    return (
        "SECTIONS\n"
        "{\n"
        f"  . = 0x{runtime_address:08X};\n"
        "  .text : { *(.text*) *(.rodata*) *(.data*) }\n"
        "  .bss : { *(.bss*) *(COMMON) }\n"
        "  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) "
        "*(.note*) *(.eh_frame*) }\n"
        '  ASSERT(SIZEOF(.bss) == 0, "BSS forbidden")\n'
        f'  ASSERT(. <= 0x{end_address:08X}, "source patch exceeds approved byte budget")\n'
        "}\n"
    )


def build_link_command(
    toolchain: SourceToolchain,
    *,
    objects: tuple[Path, ...],
    linker_script: Path,
    output: Path,
    definitions: tuple[tuple[str, int], ...],
    binary: bool,
) -> tuple[str, ...]:
    command: list[str] = [toolchain.ld, "--entry=0", "-T", str(linker_script)]
    for name, address in sorted(definitions):
        command.append(f"--defsym={name}=0x{address:08X}")
    command.extend(str(path) for path in sorted(objects, key=lambda item: str(item)))
    if binary:
        command.append("--oformat=binary")
    command.extend(("-o", str(output)))
    return tuple(command)


def parse_nm_symbols(output: str) -> tuple[tuple[str, int], ...]:
    symbols: dict[str, int] = {}
    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=2)
        if len(parts) != 3:
            raise WorkspaceError(f"cannot parse nm output line {line_number}: {raw_line!r}")
        raw_address, _symbol_type, name = parts
        try:
            address = int(raw_address, 16)
        except ValueError as exc:
            raise WorkspaceError(
                f"cannot parse nm symbol address on line {line_number}: {raw_address!r}"
            ) from exc
        if name in symbols:
            raise WorkspaceError(f"duplicate symbol in nm output: {name}")
        symbols[name] = address
    return tuple(sorted(symbols.items(), key=lambda item: (item[1], item[0])))


def run_command(command: tuple[str, ...]) -> str:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as exc:
        raise WorkspaceError(f"cannot execute source patch tool {command[0]!r}: {exc}") from exc
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise WorkspaceError(
            f"source patch command failed ({command[0]}, exit {result.returncode}): {diagnostic}"
        )
    return result.stdout


def _resolve_source(manifest_path: Path, relative: str) -> Path:
    base = manifest_path.parent.resolve()
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise WorkspaceError(f"source file escapes manifest directory: {relative}") from exc
    if not candidate.is_file():
        raise WorkspaceError(f"source file does not exist: {relative}")
    return candidate


def _normalized_command(
    command: tuple[str, ...], *, manifest_dir: Path, build_dir: Path
) -> tuple[str, ...]:
    normalized: list[str] = []
    manifest_prefix = str(manifest_dir.resolve())
    build_prefix = str(build_dir.resolve())
    for argument in command:
        if argument.startswith(build_prefix):
            suffix = argument[len(build_prefix) :].lstrip("/")
            normalized.append(f"<build>/{suffix}")
        elif argument.startswith(manifest_prefix):
            suffix = argument[len(manifest_prefix) :].lstrip("/")
            normalized.append(suffix or ".")
        else:
            normalized.append(argument)
    return tuple(normalized)


def compile_source_patch(
    manifest_path: Path,
    manifest: SourcePatchLike,
    toolchain: SourceToolchain,
    *,
    runner: Callable[[tuple[str, ...]], str] = run_command,
) -> CompiledSource:
    manifest_dir = manifest_path.parent.resolve()
    sources = tuple(_resolve_source(manifest_path, source) for source in manifest.sources)
    source_hashes = tuple(
        (relative, sha256_bytes(path.read_bytes()))
        for relative, path in zip(manifest.sources, sources, strict=True)
    )

    commands: list[tuple[str, ...]] = []
    with tempfile.TemporaryDirectory(prefix="nds-source-patch-") as temporary:
        build_dir = Path(temporary)
        objects: list[Path] = []
        for index, source in enumerate(sources):
            output = build_dir / f"source_{index:03d}.o"
            command = build_compile_command(toolchain, source, output, mode=manifest.mode)
            runner(command)
            if not output.is_file():
                source_name = manifest.sources[index]
                raise WorkspaceError(f"compiler did not produce object file for {source_name}")
            commands.append(
                _normalized_command(command, manifest_dir=manifest_dir, build_dir=build_dir)
            )
            objects.append(output)

        linker_script = build_dir / "source-patch.ld"
        linker_script.write_text(
            build_linker_script(manifest.runtime_address, manifest.max_size), encoding="utf-8"
        )
        elf_output = build_dir / "source-patch.elf"
        elf_command = build_link_command(
            toolchain,
            objects=tuple(objects),
            linker_script=linker_script,
            output=elf_output,
            definitions=manifest.definitions,
            binary=False,
        )
        runner(elf_command)
        if not elf_output.is_file():
            raise WorkspaceError("linker did not produce source patch ELF")
        commands.append(
            _normalized_command(elf_command, manifest_dir=manifest_dir, build_dir=build_dir)
        )

        nm_command = (toolchain.nm, "-n", "--defined-only", str(elf_output))
        symbols = parse_nm_symbols(runner(nm_command))
        commands.append(
            _normalized_command(nm_command, manifest_dir=manifest_dir, build_dir=build_dir)
        )

        binary_output = build_dir / "source-patch.bin"
        binary_command = build_link_command(
            toolchain,
            objects=tuple(objects),
            linker_script=linker_script,
            output=binary_output,
            definitions=manifest.definitions,
            binary=True,
        )
        runner(binary_command)
        if not binary_output.is_file():
            raise WorkspaceError("linker did not produce source patch binary")
        commands.append(
            _normalized_command(binary_command, manifest_dir=manifest_dir, build_dir=build_dir)
        )
        image = binary_output.read_bytes()

    if not image:
        raise WorkspaceError("compiled source patch binary is empty")
    if len(image) > manifest.max_size:
        raise WorkspaceError(
            f"compiled source patch size {len(image)} exceeds max_size {manifest.max_size}"
        )
    return CompiledSource(
        image=image,
        symbols=symbols,
        source_hashes=source_hashes,
        commands=tuple(commands),
    )
