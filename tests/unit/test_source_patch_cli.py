from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit import cli, source_patch_cli
from nds_disassembly_toolkit.source_apply import SourcePatchReport


def _report() -> SourcePatchReport:
    return SourcePatchReport(
        format_version=1,
        profile_id=None,
        target="overlay:3",
        manifest_file="patch.json",
        runtime_address=0x02200100,
        compiled_size=4,
        compiled_sha256="4" * 64,
        target_storage_encoding="decoded-overlay",
        target_stored_size=0x400,
        passthrough_length=None,
        before_runtime_sha256="1" * 64,
        after_runtime_sha256="2" * 64,
        before_stored_sha256="1" * 64,
        after_stored_sha256="2" * 64,
        source_hashes=(("src/injected.c", "3" * 64),),
        commands=(("clang", "..."),),
        hooks=(),
    )


def test_source_patch_build_dispatches_without_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = []
    monkeypatch.setattr(cli, "run_source_patch_command", lambda args: calls.append(args) or 0)

    result = cli.main(
        [
            "source-patch",
            "build",
            str(tmp_path / "workspace"),
            str(tmp_path / "patch.json"),
            "--clang",
            "clang-custom",
        ]
    )

    assert result == 0
    assert calls[0].source_patch_command == "build"
    assert calls[0].profile is None
    assert calls[0].clang == "clang-custom"


def test_source_patch_command_passes_profile_optional_toolchain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = []
    monkeypatch.setattr(
        source_patch_cli,
        "apply_source_patch",
        lambda workspace, manifest, profile, toolchain: calls.append(
            (workspace, manifest, profile, toolchain)
        )
        or _report(),
    )

    parser = cli.build_parser()
    arguments = parser.parse_args(
        [
            "source-patch",
            "build",
            str(tmp_path / "workspace"),
            str(tmp_path / "patch.json"),
            "--clang",
            "clang-custom",
            "--ld",
            "ld-custom",
            "--nm",
            "nm-custom",
        ]
    )

    result = source_patch_cli.run_source_patch_command(arguments)

    assert result == 0
    assert calls[0][2] is None
    assert calls[0][3].clang == "clang-custom"
    assert calls[0][3].ld == "ld-custom"
    assert calls[0][3].nm == "nm-custom"
