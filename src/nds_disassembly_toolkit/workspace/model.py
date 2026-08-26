from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkspaceLayout:
    root: Path
    original: Path
    original_raw: Path
    original_raw_overlays: Path
    original_raw_nitrofs: Path
    original_decoded: Path
    original_decoded_overlays: Path
    original_decoded_nitrofs: Path
    modified: Path
    modified_raw: Path
    modified_raw_nitrofs: Path
    modified_overlays: Path
    modified_nitrofs: Path
    manifests: Path
    build_overrides: Path

    @classmethod
    def from_root(cls, root: Path) -> WorkspaceLayout:
        normalized = root.expanduser().resolve()
        original = normalized / "original"
        original_raw = original / "raw"
        original_decoded = original / "decoded"
        modified = normalized / "modified"
        modified_raw = modified / "raw"
        manifests = normalized / "manifests"
        return cls(
            root=normalized,
            original=original,
            original_raw=original_raw,
            original_raw_overlays=original_raw / "overlays",
            original_raw_nitrofs=original_raw / "nitrofs",
            original_decoded=original_decoded,
            original_decoded_overlays=original_decoded / "overlays",
            original_decoded_nitrofs=original_decoded / "nitrofs",
            modified=modified,
            modified_raw=modified_raw,
            modified_raw_nitrofs=modified_raw / "nitrofs",
            modified_overlays=modified / "overlays",
            modified_nitrofs=modified / "nitrofs",
            manifests=manifests,
            build_overrides=manifests / "build-overrides.json",
        )

    def all_directories(self) -> tuple[Path, ...]:
        return (
            self.root,
            self.original,
            self.original_raw,
            self.original_raw_overlays,
            self.original_raw_nitrofs,
            self.original_decoded,
            self.original_decoded_overlays,
            self.original_decoded_nitrofs,
            self.modified,
            self.modified_raw,
            self.modified_raw_nitrofs,
            self.modified_overlays,
            self.modified_nitrofs,
            self.manifests,
        )
