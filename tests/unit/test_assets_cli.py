from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit import assets_cli, cli


def test_assets_inventory_dispatches_without_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls = []
    monkeypatch.setattr(cli, "run_assets_command", lambda args: calls.append(args) or 0)

    result = cli.main(
        [
            "assets",
            "inventory",
            str(tmp_path / "game.nds"),
            "--include-unknown",
        ]
    )

    assert result == 0
    assert calls[0].assets_command == "inventory"
    assert calls[0].include_unknown is True
    assert calls[0].profile is None
    assert calls[0].require_supported is False


def test_assets_inventory_writes_deterministic_profile_free_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    rom_path = tmp_path / "game.nds"
    rom_path.write_bytes(b"rom")
    output = tmp_path / "assets.json"
    inspection_calls = []

    class FakeInventory:
        def to_json(self) -> str:
            return '{"format_version": 1}\n'

    monkeypatch.setattr(
        assets_cli,
        "inspect_rom",
        lambda path, profile=None, require_supported=False: inspection_calls.append(
            (path, profile, require_supported)
        )
        or object(),
    )
    monkeypatch.setattr(
        assets_cli,
        "inventory_assets",
        lambda data, inspection, include_unknown: FakeInventory(),
    )

    parser = cli.build_parser()
    arguments = parser.parse_args(
        [
            "assets",
            "inventory",
            str(rom_path),
            "--output",
            str(output),
        ]
    )
    result = assets_cli.run_assets_command(arguments)

    assert result == 0
    assert inspection_calls == [(rom_path, None, False)]
    assert output.read_text(encoding="utf-8") == '{"format_version": 1}\n'


def test_assets_require_supported_requires_profile(tmp_path: Path, capsys) -> None:
    result = cli.main(
        [
            "assets",
            "inventory",
            str(tmp_path / "game.nds"),
            "--require-supported",
        ]
    )

    assert result == 2
    assert "requires --profile" in capsys.readouterr().err
