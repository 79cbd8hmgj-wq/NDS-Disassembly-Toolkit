from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DSButton(StrEnum):
    A = "a"
    B = "b"
    X = "x"
    Y = "y"
    L = "l"
    R = "r"
    START = "start"
    SELECT = "select"
    UP = "up"
    DOWN = "down"
    LEFT = "left"
    RIGHT = "right"


@dataclass(frozen=True, slots=True)
class DSPoint:
    x: int
    y: int

    def __post_init__(self) -> None:
        if not 0 <= self.x <= 255 or not 0 <= self.y <= 191:
            raise ValueError("touch coordinates must be within x=0..255 and y=0..191")


@dataclass(frozen=True, slots=True)
class ScreenViewport:
    x: int
    y: int
    width: int
    height: int

    def __post_init__(self) -> None:
        if self.width <= 0 or self.height <= 0:
            raise ValueError("viewport dimensions must be positive")


@dataclass(frozen=True, slots=True)
class TouchTap:
    point: DSPoint


@dataclass(frozen=True, slots=True)
class TouchDrag:
    start: DSPoint
    end: DSPoint
    duration: float

    def __post_init__(self) -> None:
        if self.duration <= 0:
            raise ValueError("duration must be positive")


@dataclass(frozen=True, slots=True)
class TouchFlick:
    start: DSPoint
    end: DSPoint
    duration: float

    def __post_init__(self) -> None:
        if self.duration <= 0:
            raise ValueError("duration must be positive")


def map_touch_point(point: DSPoint, viewport: ScreenViewport) -> tuple[int, int]:
    mapped_x = viewport.x + round(point.x * (viewport.width - 1) / 255)
    mapped_y = viewport.y + round(point.y * (viewport.height - 1) / 191)
    return mapped_x, mapped_y
