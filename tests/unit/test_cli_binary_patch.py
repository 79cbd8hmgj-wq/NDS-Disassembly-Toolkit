from pathlib import Path
from types import SimpleNamespace

import pytest

from nds_disassembly_toolkit import cli
from nds_disassembly_toolkit.errors import WorkspaceError


def test_top_level_cli_registers_binary_patch_command(tmp_path: Path) -> None:
    arguments = cli.build_parser().parse_args(
        ["patch", str(tmp_path / "workspace"), str(tmp_path / "changes.json")]
    )

    assert arguments.command == "patch"
    assert arguments.workspace == tmp_path / "workspace"
    assert arguments.patch_file == tmp_path / "changes.json"


def test_binary_patch_runner_is_reusable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    patch_file = tmp_path / "changes.json"
    report = SimpleNamespace(applied=(1, 2, 3))
    monkeypatch.setattr(cli, "apply_patch_set", lambda workspace, patch_path: report, raising=False)
    arguments = SimpleNamespace(
        command="patch",
        workspace=workspace,
        patch_file=patch_file,
    )

    result = cli.run_patch_command(arguments)

    assert result == 0
    text = capsys.readouterr().out
    assert "3 patches" in text
    assert str((workspace / "manifests/patch-changes.json").resolve()) in text


def test_top_level_patch_command_uses_toolkit_error_mapping(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        cli,
        "apply_patch_set",
        lambda workspace, patch_path: (_ for _ in ()).throw(
            WorkspaceError("expected bytes did not match")
        ),
        raising=False,
    )

    result = cli.main(["patch", str(tmp_path / "work"), str(tmp_path / "p.json")])

    assert result == 4
    assert "expected bytes" in capsys.readouterr().err
