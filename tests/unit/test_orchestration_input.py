from __future__ import annotations

import pytest

from nds_disassembly_toolkit.analysis.orchestration.input import (
    DSButton,
    DSPoint,
    ScreenLayoutProfile,
    ScreenViewport,
    WindowGeometry,
    TouchDrag,
    TouchFlick,
    TouchTap,
    map_touch_point,
)


def test_ds_button_surface_is_complete() -> None:
    assert {button.value for button in DSButton} == {
        "a",
        "b",
        "x",
        "y",
        "l",
        "r",
        "start",
        "select",
        "up",
        "down",
        "left",
        "right",
    }


@pytest.mark.parametrize(
    ("x", "y"),
    [(-1, 0), (256, 0), (0, -1), (0, 192)],
)
def test_ds_point_rejects_coordinates_outside_touchscreen(x: int, y: int) -> None:
    with pytest.raises(ValueError, match="touch"):
        DSPoint(x, y)


def test_native_touch_mapping_is_identity_inside_lower_viewport() -> None:
    viewport = ScreenViewport(x=0, y=192, width=256, height=192)
    assert map_touch_point(DSPoint(0, 0), viewport) == (0, 192)
    assert map_touch_point(DSPoint(255, 191), viewport) == (255, 383)


def test_scaled_touch_mapping_keeps_endpoints_inside_viewport() -> None:
    viewport = ScreenViewport(x=10, y=20, width=512, height=384)
    assert map_touch_point(DSPoint(0, 0), viewport) == (10, 20)
    assert map_touch_point(DSPoint(255, 191), viewport) == (521, 403)


def test_touch_actions_validate_duration() -> None:
    point = DSPoint(100, 100)
    assert TouchTap(point).point == point
    assert TouchDrag(point, DSPoint(120, 120), duration=0.25).duration == 0.25
    assert TouchFlick(point, DSPoint(120, 80), duration=0.05).duration == 0.05
    with pytest.raises(ValueError, match="duration"):
        TouchDrag(point, point, duration=0)



def test_layout_profile_requires_supported_geometry() -> None:
    geometry = WindowGeometry(x=100, y=50, width=512, height=768)
    lower = ScreenViewport(x=0, y=384, width=512, height=384)

    profile = ScreenLayoutProfile(
        window=geometry,
        lower_screen=lower,
        rotation=0,
        separated_screens=False,
    )

    assert profile.lower_screen == lower


def test_layout_profile_rejects_unsupported_rotation_and_out_of_bounds_viewport() -> None:
    geometry = WindowGeometry(x=0, y=0, width=512, height=768)

    with pytest.raises(ValueError, match="rotation"):
        ScreenLayoutProfile(
            window=geometry,
            lower_screen=ScreenViewport(0, 384, 512, 384),
            rotation=90,
        )

    with pytest.raises(ValueError, match="window"):
        ScreenLayoutProfile(
            window=geometry,
            lower_screen=ScreenViewport(1, 384, 512, 384),
        )
