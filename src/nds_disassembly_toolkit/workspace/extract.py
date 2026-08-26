from __future__ import annotations

import shutil
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.compression.blz import decompress_blz, is_blz
from nds_disassembly_toolkit.compression.lz10 import decompress_lz10, is_lz10
from nds_disassembly_toolkit.errors import RomFormatError, WorkspaceError
from nds_disassembly_toolkit.inspection import inspect_rom
from nds_disassembly_toolkit.profile import RomProfile
from nds_disassembly_toolkit.workspace.manifest import (
    ExtractedFile,
    ExtractedOverlay,
    WorkspaceManifest,
    sha256_bytes,
    write_json_atomic,
)
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout
from nds_disassembly_toolkit.workspace.paths import ensure_unique_relative_paths


@dataclass(frozen=True)
class ExtractionOptions:
    workspace: Path
    force: bool = False


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _make_tree_read_only(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file():
            path.chmod(0o444)
    for path in sorted((item for item in root.rglob("*") if item.is_dir()), reverse=True):
        path.chmod(0o555)
    root.chmod(0o555)


def _make_tree_writable(root: Path) -> None:
    if not root.exists():
        return
    for path in root.rglob("*"):
        with suppress(OSError):
            path.chmod(0o755 if path.is_dir() else 0o644)
    with suppress(OSError):
        root.chmod(0o755)


def _remove_tree(root: Path) -> None:
    if not root.exists():
        return
    _make_tree_writable(root)
    shutil.rmtree(root)


def _populate_workspace(
    rom_path: Path,
    layout: WorkspaceLayout,
    *,
    profile: RomProfile | None,
    require_supported: bool,
) -> WorkspaceManifest:
    inspection = inspect_rom(
        rom_path,
        profile=profile,
        require_supported=require_supported,
    )
    rom_data = rom_path.read_bytes()

    try:
        safe_paths = ensure_unique_relative_paths(item.path for item in inspection.fnt.files)
    except ValueError as exc:
        raise WorkspaceError(str(exc)) from exc
    path_by_file_id = {
        item.file_id: safe_path
        for item, safe_path in zip(inspection.fnt.files, safe_paths, strict=True)
    }

    for directory in layout.all_directories():
        directory.mkdir(parents=True, exist_ok=True)

    arm9 = bytes(
        rom_data[
            inspection.header.arm9_offset : inspection.header.arm9_offset
            + inspection.header.arm9_size
        ]
    )
    arm7 = bytes(
        rom_data[
            inspection.header.arm7_offset : inspection.header.arm7_offset
            + inspection.header.arm7_size
        ]
    )
    _write_bytes(layout.original / "arm9.bin", arm9)
    _write_bytes(layout.original / "arm7.bin", arm7)
    _write_bytes(layout.modified / "arm9.bin", arm9)
    _write_bytes(layout.modified / "arm7.bin", arm7)

    extracted_files: list[ExtractedFile] = []
    for file_id, relative in sorted(path_by_file_id.items()):
        if file_id >= len(inspection.fat):
            raise WorkspaceError(f"FNT file ID {file_id} is outside the FAT")
        fat_entry = inspection.fat[file_id]
        raw = bytes(rom_data[fat_entry.start : fat_entry.end])
        if is_lz10(raw):
            decoded = decompress_lz10(raw)
            compression = "lz10"
        else:
            decoded = raw
            compression = "none"
        relative_path = Path(*relative.parts)
        _write_bytes(layout.original_raw_nitrofs / relative_path, raw)
        _write_bytes(layout.original_decoded_nitrofs / relative_path, decoded)
        _write_bytes(layout.modified_nitrofs / relative_path, decoded)
        extracted_files.append(
            ExtractedFile(
                file_id=file_id,
                path=relative.as_posix(),
                raw_size=len(raw),
                decoded_size=len(decoded),
                compression=compression,
                raw_sha256=sha256_bytes(raw),
                decoded_sha256=sha256_bytes(decoded),
            )
        )

    extracted_overlays: list[ExtractedOverlay] = []
    overlays = sorted(
        (*inspection.arm9_overlays, *inspection.arm7_overlays),
        key=lambda item: item.overlay_id,
    )
    for overlay in overlays:
        if overlay.file_id >= len(inspection.fat):
            raise WorkspaceError(
                f"overlay {overlay.overlay_id} file ID {overlay.file_id} is outside the FAT"
            )
        fat_entry = inspection.fat[overlay.file_id]
        raw = bytes(rom_data[fat_entry.start : fat_entry.end])
        if is_blz(raw):
            decoded = decompress_blz(raw)
            compression = "blz"
        elif len(raw) == overlay.ram_size:
            decoded = raw
            compression = "none"
        else:
            raise RomFormatError(
                f"overlay {overlay.overlay_id} is neither valid BLZ nor an uncompressed "
                f"payload of declared size {overlay.ram_size}"
            )
        if len(decoded) != overlay.ram_size:
            raise RomFormatError(
                f"overlay {overlay.overlay_id} decoded size mismatch: "
                f"expected {overlay.ram_size}, got {len(decoded)}"
            )
        filename = f"overlay_{overlay.overlay_id:03d}.bin"
        _write_bytes(layout.original_raw_overlays / filename, raw)
        _write_bytes(layout.original_decoded_overlays / filename, decoded)
        _write_bytes(layout.modified_overlays / filename, decoded)
        extracted_overlays.append(
            ExtractedOverlay(
                overlay_id=overlay.overlay_id,
                file_id=overlay.file_id,
                ram_address=overlay.ram_address,
                ram_size=overlay.ram_size,
                bss_size=overlay.bss_size,
                raw_size=len(raw),
                decoded_size=len(decoded),
                raw_sha256=sha256_bytes(raw),
                decoded_sha256=sha256_bytes(decoded),
                compression=compression,
            )
        )

    manifest = WorkspaceManifest(
        format_version=1,
        profile_id=inspection.profile_id,
        rom_sha256=inspection.identity.sha256,
        rom_size=inspection.identity.size,
        arm9_sha256=sha256_bytes(arm9),
        arm7_sha256=sha256_bytes(arm7),
        files=tuple(extracted_files),
        overlays=tuple(extracted_overlays),
    )
    payload = manifest.to_dict()
    write_json_atomic(layout.manifests / "workspace.json", payload)
    write_json_atomic(
        layout.manifests / "files.json",
        {"format_version": manifest.format_version, "files": payload["files"]},
    )
    write_json_atomic(
        layout.manifests / "overlays.json",
        {"format_version": manifest.format_version, "overlays": payload["overlays"]},
    )
    _make_tree_read_only(layout.original)
    return manifest


def extract_workspace(
    rom_path: Path,
    options: ExtractionOptions,
    *,
    profile: RomProfile | None = None,
    require_supported: bool = False,
) -> WorkspaceManifest:
    target = options.workspace.expanduser().resolve()
    if target.exists() and not options.force:
        raise WorkspaceError(f"workspace already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=target.parent))
    backup: Path | None = None
    try:
        manifest = _populate_workspace(
            rom_path,
            WorkspaceLayout.from_root(staging),
            profile=profile,
            require_supported=require_supported,
        )
        if target.exists():
            backup = Path(tempfile.mkdtemp(prefix=f".{target.name}.backup-", dir=target.parent))
            backup.rmdir()
            target.replace(backup)
        try:
            staging.replace(target)
        except Exception:
            if backup is not None and backup.exists() and not target.exists():
                backup.replace(target)
            raise
        if backup is not None:
            _remove_tree(backup)
        return manifest
    except Exception:
        if staging.exists():
            _remove_tree(staging)
        raise
