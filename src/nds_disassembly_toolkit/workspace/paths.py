from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath


def safe_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value:
        raise ValueError(f"unsafe workspace path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) in {"", "."}:
        raise ValueError(f"unsafe workspace path: {value!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe workspace path: {value!r}")
    return path


def ensure_unique_relative_paths(values: Iterable[str]) -> tuple[PurePosixPath, ...]:
    paths: list[PurePosixPath] = []
    seen: set[str] = set()
    for value in values:
        path = safe_relative_path(value)
        normalized = path.as_posix()
        if normalized in seen:
            raise ValueError(f"duplicate workspace path: {normalized}")
        seen.add(normalized)
        paths.append(path)
    return tuple(paths)
