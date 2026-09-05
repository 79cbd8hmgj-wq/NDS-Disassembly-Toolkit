from __future__ import annotations

import os
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration.x11 import (
    allocate_display_number,
    find_x11_helpers,
    sanitize_x11_environment,
)


def test_sanitize_x11_environment_overrides_dummy_sdl() -> None:
    env = sanitize_x11_environment(
        {"SDL_VIDEODRIVER": "dummy", "KEEP_ME": "yes"},
        display=":104",
    )
    assert env["DISPLAY"] == ":104"
    assert env["SDL_VIDEODRIVER"] == "x11"
    assert env["KEEP_ME"] == "yes"


def test_allocate_display_number_skips_existing_x11_socket(tmp_path: Path) -> None:
    socket_dir = tmp_path / ".X11-unix"
    socket_dir.mkdir()
    (socket_dir / "X100").touch()
    assert allocate_display_number(socket_dir=socket_dir, start=100, stop=103) == 101


def test_find_x11_helpers_reports_missing_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.x11.shutil.which",
        lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None,
    )
    helpers = find_x11_helpers()
    assert helpers.xvfb == Path("/usr/bin/Xvfb")
    assert helpers.xdotool is None
