from __future__ import annotations

import struct
from pathlib import Path

import pytest

from nds_disassembly_toolkit.disassembly import (
    ModuleParams,
    build_objdump_command,
    disassemble_binary,
    find_module_params,
    overlay_layout_report,
    render_labelled_bytes,
    unified_disassembly_diff,
)
from nds_disassembly_toolkit.errors import DisassemblyError
from nds_disassembly_toolkit.nds.overlays import OverlayEntry


def _module_params_values() -> tuple[int, ...]:
    return (
        0x020C0100,
        0x020C0118,
        0x020BAF00,
        0x020BAF00,
        0x02219440,
        0x0206D6C0,
        0x04027539,
        0xDEC00621,
    )


def _module_params_bytes() -> bytes:
    return (
        b"\x00" * 0x20
        + struct.pack("<8I", *_module_params_values())
        + struct.pack("<I", 0x2106C0DE)
        + b"\x00" * 0x20
    )


def test_find_module_params_parses_aligned_nitro_block() -> None:
    params = find_module_params(_module_params_bytes(), base_address=0x02000000)

    assert params == ModuleParams(
        offset=0x20,
        address=0x02000020,
        autoload_list_start=0x020C0100,
        autoload_list_end=0x020C0118,
        autoload_start=0x020BAF00,
        static_bss_start=0x020BAF00,
        static_bss_end=0x02219440,
        compressed_static_end=0x0206D6C0,
        sdk_version=0x04027539,
    )


def test_find_module_params_ignores_unaligned_magic_false_positive() -> None:
    data = bytearray(_module_params_bytes())
    data.extend(b"\x00" * 3 + b"\x21\x06\xc0\xde")

    params = find_module_params(data)

    assert params is not None
    assert params.offset == 0x20


def test_find_module_params_uses_full_signature_pair_to_ignore_aligned_decoy() -> None:
    data = bytearray(_module_params_bytes())
    data.extend(struct.pack("<8I", *_module_params_values()))
    data.extend(struct.pack("<I", 0x12345678))

    params = find_module_params(data)

    assert params is not None
    assert params.offset == 0x20


def test_find_module_params_rejects_magic_without_little_endian_signature() -> None:
    data = b"\x00" * 0x20 + struct.pack("<8I", *_module_params_values())

    assert find_module_params(data) is None


def test_overlay_layout_report_marks_shared_static_boundary() -> None:
    overlays = (
        OverlayEntry(0, 0x02219440, 0x1000, 0x100, 0, 0, 0, 0),
        OverlayEntry(1, 0x02219440, 0x2000, 0x100, 0, 0, 1, 0),
        OverlayEntry(2, 0x0221A540, 0x0800, 0, 0, 0, 2, 0),
    )

    report = overlay_layout_report(overlays, static_end=0x02219440)

    assert report["after_static"] == [0, 1]
    assert report["shared_start_groups"] == [
        {"ram_address": 0x02219440, "overlay_ids": [0, 1]}
    ]
    assert report["load_relations"] == [{"overlay_id": 2, "after_overlay_id": 0}]


def test_render_labelled_bytes_preserves_prefix_and_splits_at_labels() -> None:
    rendered = render_labelled_bytes(
        bytes(range(20)),
        labels=(0x02000004, 0x02000010),
        base_address=0x02000000,
    )

    assert rendered.startswith("_02000000:\n")
    assert "_02000004:\n" in rendered
    assert "_02000010:\n" in rendered
    assert "0x00, 0x01, 0x02, 0x03" in rendered


def test_render_labelled_bytes_rejects_label_outside_component() -> None:
    with pytest.raises(ValueError, match="outside component"):
        render_labelled_bytes(b"\x00" * 8, labels=(0x1FFF,), base_address=0x2000)


def test_build_objdump_command_uses_ds_vma_and_thumb_mode() -> None:
    command = build_objdump_command(
        "candidate.bin",
        base_address=0x02219440,
        start_address=0x0223CFE8,
        stop_address=0x0223D000,
        thumb=True,
    )

    assert command == (
        "arm-none-eabi-objdump",
        "-D",
        "-r",
        "-z",
        "-b",
        "binary",
        "-m",
        "armv5te",
        "-Mforce-thumb",
        "--adjust-vma=0x2219440",
        "--start-address=0x223cfe8",
        "--stop-address=0x223d000",
        "candidate.bin",
    )


def test_disassemble_binary_executes_requested_objdump(tmp_path: Path) -> None:
    tool = tmp_path / "fake-objdump"
    tool.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print(' '.join(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    binary = tmp_path / "component.bin"
    binary.write_bytes(b"\x00\x00\xa0\xe1")

    output = disassemble_binary(binary, base_address=0x02000000, executable=str(tool))

    assert "--adjust-vma=0x2000000" in output
    assert str(binary) in output


def test_disassemble_binary_wraps_objdump_failure(tmp_path: Path) -> None:
    tool = tmp_path / "failing-objdump"
    tool.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('bad binary', file=sys.stderr)\n"
        "raise SystemExit(3)\n",
        encoding="utf-8",
    )
    tool.chmod(0o755)
    binary = tmp_path / "component.bin"
    binary.write_bytes(b"\x00" * 4)

    with pytest.raises(DisassemblyError, match="exit code 3: bad binary"):
        disassemble_binary(binary, base_address=0x02000000, executable=str(tool))


def test_unified_disassembly_diff_is_deterministic() -> None:
    diff = unified_disassembly_diff(
        "0000: mov r0, r0\n0004: bx lr\n",
        "0000: mov r0, r1\n0004: bx lr\n",
        reference_name="original",
        candidate_name="rebuilt",
    )

    assert diff == (
        "--- original\n"
        "+++ rebuilt\n"
        "@@ -1,2 +1,2 @@\n"
        "-0000: mov r0, r0\n"
        "+0000: mov r0, r1\n"
        " 0004: bx lr\n"
    )
