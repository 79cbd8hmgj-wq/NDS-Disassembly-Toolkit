from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.compression.blz import compress_blz, decompress_blz, parse_blz_footer
from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.source_apply import build_patched_runtime, encode_target_storage
from nds_disassembly_toolkit.source_compile import CompiledSource
from nds_disassembly_toolkit.source_patch import SourceHook, SourcePatchManifest, SourceTarget


def _manifest(
    *, hooks: tuple[SourceHook, ...] = (), mode: str = "arm"
) -> SourcePatchManifest:
    return SourcePatchManifest(
        format_version=1,
        profile_id=None,
        target="overlay:3",
        runtime_address=0x02200100,
        max_size=0x20,
        mode=mode,
        expected_runtime_sha256="0" * 64,
        sources=("src/injected.c",),
        definitions=(),
        hooks=hooks,
        blz_passthrough_length=None,
    )


def _target(runtime: bytes, *, encoding: str = "decoded-overlay") -> SourceTarget:
    return SourceTarget(
        target="overlay:3",
        path=Path("overlay_003.bin"),
        runtime_base=0x02200000,
        runtime_image=runtime,
        placement_offset=0x100,
        storage_encoding=encoding,
        stored_size=len(runtime),
        passthrough_length=None,
    )


def _compiled(image: bytes, symbols: tuple[tuple[str, int], ...] = ()) -> CompiledSource:
    return CompiledSource(
        image=image,
        symbols=symbols,
        source_hashes=(("src/injected.c", "1" * 64),),
        commands=(("clang", "..."),),
    )


def test_build_patched_runtime_places_image_without_touching_unused_budget() -> None:
    runtime = b"\xAA" * 0x400

    patched, hooks = build_patched_runtime(
        _target(runtime), _manifest(), _compiled(b"\x01\x02\x03\x04")
    )

    assert patched[0x100:0x104] == b"\x01\x02\x03\x04"
    assert patched[0x104:0x120] == b"\xAA" * 0x1C
    assert hooks == ()


def test_hook_guards_are_checked_before_mutation() -> None:
    runtime = bytearray(b"\x00" * 0x400)
    hook = SourceHook(
        hook_id="entry",
        runtime_address=0x02200040,
        expected=b"\xFF" * 4,
        symbol="entry",
        link=True,
        mode="arm",
    )

    with pytest.raises(WorkspaceError, match="guard mismatch"):
        build_patched_runtime(
            _target(bytes(runtime)),
            _manifest(hooks=(hook,)),
            _compiled(b"\x00" * 4, (("entry", 0x02200100),)),
        )

    assert runtime[0x100:0x104] == b"\x00" * 4


def test_hook_symbol_must_resolve_inside_emitted_image() -> None:
    hook = SourceHook(
        hook_id="entry",
        runtime_address=0x02200040,
        expected=b"\x00" * 4,
        symbol="entry",
        link=True,
        mode="arm",
    )

    with pytest.raises(WorkspaceError, match="outside emitted image"):
        build_patched_runtime(
            _target(b"\x00" * 0x400),
            _manifest(hooks=(hook,)),
            _compiled(b"\x00" * 4, (("entry", 0x02001000),)),
        )


def test_thumb_hook_canonicalizes_elf_thumb_symbol_bit() -> None:
    hook = SourceHook(
        hook_id="entry",
        runtime_address=0x02200040,
        expected=b"\x00" * 4,
        symbol="entry",
        link=True,
        mode="thumb",
    )

    patched, reports = build_patched_runtime(
        _target(b"\x00" * 0x400),
        _manifest(hooks=(hook,), mode="thumb"),
        _compiled(b"\x00" * 4, (("entry", 0x02200101),)),
    )

    assert patched[0x40:0x44] != b"\x00" * 4
    assert reports[0].destination == 0x02200100


def test_hook_overlap_with_injected_code_is_rejected() -> None:
    hook = SourceHook(
        hook_id="overlap",
        runtime_address=0x02200100,
        expected=b"\x00" * 4,
        symbol="entry",
        link=True,
        mode="arm",
    )

    with pytest.raises(WorkspaceError, match="overlaps injected code"):
        build_patched_runtime(
            _target(b"\x00" * 0x400),
            _manifest(hooks=(hook,)),
            _compiled(b"\x00" * 8, (("entry", 0x02200100),)),
        )


def test_blz_target_reencodes_to_exact_stored_size() -> None:
    decoded = (b"ABCD" * 0x200) + (b"\x00" * 0x1000)
    minimal = compress_blz(decoded)
    stored = compress_blz(decoded, target_size=len(minimal) + 32)
    footer = parse_blz_footer(stored)
    target = SourceTarget(
        target="arm9",
        path=Path("arm9.bin"),
        runtime_base=0x02000000,
        runtime_image=decoded,
        placement_offset=0,
        storage_encoding="blz",
        stored_size=len(stored),
        passthrough_length=len(stored) - footer.compressed_length,
    )
    patched = bytearray(decoded)
    patched[0] ^= 1

    encoded = encode_target_storage(target, bytes(patched))

    assert len(encoded) == len(stored)
    assert decompress_blz(encoded) == bytes(patched)


def test_encode_target_storage_rejects_runtime_length_change() -> None:
    target = _target(b"\x00" * 0x400)

    with pytest.raises(WorkspaceError, match="runtime size"):
        encode_target_storage(target, b"\x00" * 0x3FF)
