from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.inspection import RomInspection, inspect_rom
from nds_disassembly_toolkit.profile import RomProfile, sha256_file
from nds_disassembly_toolkit.workspace.manifest import (
    WorkspaceManifest,
    load_workspace_manifest,
    sha256_bytes,
)
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout
from nds_disassembly_toolkit.workspace.overrides import BuildOverrides, load_build_overrides
from nds_disassembly_toolkit.workspace.paths import safe_relative_path


@dataclass(frozen=True)
class WorkspaceChange:
    kind: str
    identifier: str
    original_sha256: str
    modified_sha256: str


@dataclass(frozen=True)
class ValidatedWorkspace:
    layout: WorkspaceLayout
    manifest: WorkspaceManifest
    inspection: RomInspection
    changes: tuple[WorkspaceChange, ...]
    overrides: BuildOverrides | None

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)


def _read_verified(path: Path, size: int, digest: str, label: str) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise WorkspaceError(f"missing {label}: {path}") from exc
    if len(data) != size:
        raise WorkspaceError(f"{label} size mismatch: expected {size}, got {len(data)}")
    actual = sha256_bytes(data)
    if actual != digest:
        raise WorkspaceError(f"{label} SHA-256 mismatch: expected {digest}, got {actual}")
    return data


def _scan_relative_files(root: Path) -> set[str]:
    if not root.is_dir():
        raise WorkspaceError(f"missing modified directory: {root}")
    return {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}


def validate_workspace(
    source_rom: Path,
    workspace: Path,
    *,
    profile: RomProfile | None = None,
    require_supported: bool = False,
) -> ValidatedWorkspace:
    layout = WorkspaceLayout.from_root(workspace)
    manifest = load_workspace_manifest(layout.manifests / "workspace.json")
    overrides = load_build_overrides(layout.build_overrides)
    if profile is not None and manifest.profile_id not in {None, profile.id}:
        raise WorkspaceError(
            f"workspace profile mismatch: expected {profile.id}, got {manifest.profile_id}"
        )
    if overrides is not None and overrides.profile_id != manifest.profile_id:
        raise WorkspaceError(
            "build override profile does not match workspace manifest: "
            f"expected {manifest.profile_id!r}, got {overrides.profile_id!r}"
        )
    try:
        source_size = source_rom.stat().st_size
        source_hash = sha256_file(source_rom)
    except OSError as exc:
        raise WorkspaceError(f"cannot read source ROM {source_rom}: {exc}") from exc
    if source_size != manifest.rom_size or source_hash != manifest.rom_sha256:
        raise WorkspaceError(
            "source ROM does not match workspace manifest: "
            f"expected {manifest.rom_size} bytes/{manifest.rom_sha256}, "
            f"got {source_size} bytes/{source_hash}"
        )

    inspection = inspect_rom(
        source_rom,
        profile=profile,
        require_supported=require_supported,
    )
    source_paths = {item.file_id: item.path for item in inspection.fnt.files}
    manifest_paths = {item.file_id: item.path for item in manifest.files}
    if source_paths != manifest_paths:
        raise WorkspaceError("workspace file mapping does not match source ROM FNT")
    source_overlays = {
        item.overlay_id: item.file_id
        for item in (*inspection.arm9_overlays, *inspection.arm7_overlays)
    }
    manifest_overlays = {item.overlay_id: item.file_id for item in manifest.overlays}
    if source_overlays != manifest_overlays:
        raise WorkspaceError("workspace overlay mapping does not match source ROM")

    _read_verified(
        layout.original / "arm9.bin",
        inspection.header.arm9_size,
        manifest.arm9_sha256,
        "original ARM9",
    )
    _read_verified(
        layout.original / "arm7.bin",
        inspection.header.arm7_size,
        manifest.arm7_sha256,
        "original ARM7",
    )

    changes: list[WorkspaceChange] = []
    for name, expected_size, original_hash in (
        ("arm9", inspection.header.arm9_size, manifest.arm9_sha256),
        ("arm7", inspection.header.arm7_size, manifest.arm7_sha256),
    ):
        path = layout.modified / f"{name}.bin"
        try:
            modified = path.read_bytes()
        except OSError as exc:
            raise WorkspaceError(f"missing modified {name.upper()}: {path}") from exc
        if len(modified) != expected_size:
            raise WorkspaceError(
                f"modified {name.upper()} size mismatch: expected {expected_size}, "
                f"got {len(modified)}"
            )
        modified_hash = sha256_bytes(modified)
        if modified_hash != original_hash:
            changes.append(WorkspaceChange(name, name, original_hash, modified_hash))

    raw_override_items = overrides.raw_nitrofs if overrides else ()
    overlay_override_items = overrides.overlays if overrides else ()
    raw_by_id = {item.file_id: item for item in raw_override_items}
    raw_by_path = {item.path: item for item in raw_override_items}
    overlay_by_id = {item.overlay_id: item for item in overlay_override_items}

    expected_modified_files: set[str] = set()
    expected_raw_override_files: set[str] = set()
    matched_raw_override_paths: set[str] = set()
    for entry in manifest.files:
        relative = safe_relative_path(entry.path)
        relative_path = Path(*relative.parts)
        _read_verified(
            layout.original_raw_nitrofs / relative_path,
            entry.raw_size,
            entry.raw_sha256,
            f"original raw NitroFS file {entry.path}",
        )
        _read_verified(
            layout.original_decoded_nitrofs / relative_path,
            entry.decoded_size,
            entry.decoded_sha256,
            f"original decoded NitroFS file {entry.path}",
        )
        modified_path = layout.modified_nitrofs / relative_path
        try:
            modified = modified_path.read_bytes()
        except OSError as exc:
            raise WorkspaceError(f"missing modified NitroFS file: {entry.path}") from exc
        modified_hash = sha256_bytes(modified)
        raw_override = raw_by_path.get(entry.path)
        if raw_override is not None:
            if raw_override.file_id != entry.file_id or raw_by_id.get(entry.file_id) != raw_override:
                raise WorkspaceError(
                    f"raw override mapping does not match manifest for {entry.path}"
                )
            _read_verified(
                layout.original_raw_nitrofs / relative_path,
                raw_override.expected_size,
                raw_override.expected_sha256,
                f"original raw override NitroFS file {entry.path}",
            )
            _read_verified(
                layout.modified_raw_nitrofs / relative_path,
                raw_override.replacement_size,
                raw_override.replacement_sha256,
                f"modified raw override NitroFS file {entry.path}",
            )
            if modified_hash != entry.decoded_sha256:
                raise WorkspaceError(
                    f"simultaneous decoded and raw override for NitroFS file {entry.path}"
                )
            changes.append(
                WorkspaceChange(
                    "nitrofs_raw",
                    entry.path,
                    raw_override.expected_sha256,
                    raw_override.replacement_sha256,
                )
            )
            expected_raw_override_files.add(relative.as_posix())
            matched_raw_override_paths.add(entry.path)
        elif modified_hash != entry.decoded_sha256:
            changes.append(
                WorkspaceChange("nitrofs", entry.path, entry.decoded_sha256, modified_hash)
            )
        expected_modified_files.add(relative.as_posix())
    unmatched_raw_overrides = sorted(set(raw_by_path) - matched_raw_override_paths)
    if unmatched_raw_overrides:
        raise WorkspaceError(
            f"raw overrides do not match workspace manifest: {unmatched_raw_overrides}"
        )
    actual_modified_files = _scan_relative_files(layout.modified_nitrofs)
    extra_files = sorted(actual_modified_files - expected_modified_files)
    missing_files = sorted(expected_modified_files - actual_modified_files)
    if extra_files:
        raise WorkspaceError(f"unmanifested modified NitroFS files: {extra_files}")
    if missing_files:
        raise WorkspaceError(f"missing modified NitroFS files: {missing_files}")
    actual_raw_override_files = _scan_relative_files(layout.modified_raw_nitrofs)
    extra_raw_override_files = sorted(actual_raw_override_files - expected_raw_override_files)
    missing_raw_override_files = sorted(expected_raw_override_files - actual_raw_override_files)
    if extra_raw_override_files:
        raise WorkspaceError(f"unmanifested modified raw NitroFS files: {extra_raw_override_files}")
    if missing_raw_override_files:
        raise WorkspaceError(f"missing modified raw NitroFS files: {missing_raw_override_files}")

    expected_overlay_files: set[str] = set()
    matched_overlay_ids: set[int] = set()
    for overlay_entry in manifest.overlays:
        filename = f"overlay_{overlay_entry.overlay_id:03d}.bin"
        _read_verified(
            layout.original_raw_overlays / filename,
            overlay_entry.raw_size,
            overlay_entry.raw_sha256,
            f"original raw overlay {overlay_entry.overlay_id}",
        )
        _read_verified(
            layout.original_decoded_overlays / filename,
            overlay_entry.decoded_size,
            overlay_entry.decoded_sha256,
            f"original decoded overlay {overlay_entry.overlay_id}",
        )
        modified_path = layout.modified_overlays / filename
        try:
            modified = modified_path.read_bytes()
        except OSError as exc:
            raise WorkspaceError(
                f"missing modified overlay {overlay_entry.overlay_id}: {modified_path}"
            ) from exc
        overlay_override = overlay_by_id.get(overlay_entry.overlay_id)
        expected_size = overlay_entry.ram_size
        if overlay_override is not None:
            if (
                overlay_override.expected_ram_size != overlay_entry.ram_size
                or overlay_override.expected_bss_size != overlay_entry.bss_size
            ):
                raise WorkspaceError(
                    f"overlay override {overlay_entry.overlay_id} original geometry mismatch"
                )
            expected_size = overlay_override.replacement_ram_size
            matched_overlay_ids.add(overlay_entry.overlay_id)
        if len(modified) != expected_size:
            raise WorkspaceError(
                f"modified overlay {overlay_entry.overlay_id} size mismatch: "
                f"expected {expected_size}, got {len(modified)}"
            )
        modified_hash = sha256_bytes(modified)
        if modified_hash != overlay_entry.decoded_sha256:
            changes.append(
                WorkspaceChange(
                    "overlay",
                    str(overlay_entry.overlay_id),
                    overlay_entry.decoded_sha256,
                    modified_hash,
                )
            )
        expected_overlay_files.add(filename)
    unmatched_overlay_ids = sorted(set(overlay_by_id) - matched_overlay_ids)
    if unmatched_overlay_ids:
        raise WorkspaceError(
            f"overlay overrides do not match workspace manifest: {unmatched_overlay_ids}"
        )
    actual_overlay_files = _scan_relative_files(layout.modified_overlays)
    extra_overlays = sorted(actual_overlay_files - expected_overlay_files)
    missing_overlays = sorted(expected_overlay_files - actual_overlay_files)
    if extra_overlays:
        raise WorkspaceError(f"unmanifested modified overlays: {extra_overlays}")
    if missing_overlays:
        raise WorkspaceError(f"missing modified overlays: {missing_overlays}")

    order = {"arm9": 0, "arm7": 1, "nitrofs": 2, "nitrofs_raw": 3, "overlay": 4}
    return ValidatedWorkspace(
        layout=layout,
        manifest=manifest,
        inspection=inspection,
        changes=tuple(sorted(changes, key=lambda item: (order[item.kind], item.identifier))),
        overrides=overrides,
    )
