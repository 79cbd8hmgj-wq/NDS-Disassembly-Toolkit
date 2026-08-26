from __future__ import annotations

import json
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.patches.model import BinaryPatch, load_patch_set
from nds_disassembly_toolkit.workspace.manifest import (
    WorkspaceManifest,
    load_workspace_manifest,
    sha256_bytes,
)
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout
from nds_disassembly_toolkit.workspace.paths import safe_relative_path


@dataclass(frozen=True)
class AppliedPatch:
    patch_id: str
    target: str
    offset: int
    length: int
    before_sha256: str
    after_sha256: str


@dataclass(frozen=True)
class PatchApplicationReport:
    format_version: int
    profile_id: str | None
    patch_file: str
    applied: tuple[AppliedPatch, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "profile_id": self.profile_id,
            "patch_file": self.patch_file,
            "applied": [asdict(item) for item in self.applied],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _resolve_target(
    layout: WorkspaceLayout,
    manifest: WorkspaceManifest,
    patch: BinaryPatch,
) -> Path:
    if patch.target == "arm9":
        return layout.modified / "arm9.bin"
    if patch.target == "arm7":
        return layout.modified / "arm7.bin"
    if patch.target.startswith("overlay:"):
        suffix = patch.target.split(":", 1)[1]
        try:
            overlay_id = int(suffix)
        except ValueError as exc:
            raise WorkspaceError(f"invalid overlay target: {patch.target}") from exc
        if overlay_id < 0 or overlay_id not in {item.overlay_id for item in manifest.overlays}:
            raise WorkspaceError(f"unknown overlay target: {patch.target}")
        return layout.modified_overlays / f"overlay_{overlay_id:03d}.bin"
    if patch.target.startswith("nitrofs:"):
        raw_path = patch.target.split(":", 1)[1]
        try:
            relative = safe_relative_path(raw_path)
        except ValueError as exc:
            raise WorkspaceError(str(exc)) from exc
        if relative.as_posix() not in {item.path for item in manifest.files}:
            raise WorkspaceError(f"unknown NitroFS target: {patch.target}")
        return layout.modified_nitrofs / Path(*relative.parts)
    raise WorkspaceError(f"unknown patch target: {patch.target}")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        prefix=f".{path.name}.tmp-",
        dir=path.parent,
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(data)
            handle.flush()
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def apply_patch_set(workspace: Path, patch_path: Path) -> PatchApplicationReport:
    layout = WorkspaceLayout.from_root(workspace)
    manifest = load_workspace_manifest(layout.manifests / "workspace.json")
    patch_set = load_patch_set(patch_path)

    if patch_set.profile_id is not None and patch_set.profile_id != manifest.profile_id:
        raise WorkspaceError(
            f"patch profile mismatch: expected {manifest.profile_id}, got {patch_set.profile_id}"
        )

    buffers: dict[Path, bytearray] = {}
    applied: list[AppliedPatch] = []
    for patch in patch_set.patches:
        target = _resolve_target(layout, manifest, patch)
        if target not in buffers:
            try:
                original = target.read_bytes()
            except OSError as exc:
                raise WorkspaceError(f"cannot read patch target {target}: {exc}") from exc
            buffers[target] = bytearray(original)

        buffer = buffers[target]
        end = patch.offset + len(patch.expected)
        if end > len(buffer):
            raise WorkspaceError(
                f"patch {patch.patch_id} range {patch.offset}:{end} is outside target size "
                f"{len(buffer)}"
            )
        actual = bytes(buffer[patch.offset:end])
        if actual != patch.expected:
            raise WorkspaceError(
                f"patch {patch.patch_id} expected bytes {patch.expected.hex()} at offset "
                f"0x{patch.offset:X}, found {actual.hex()}"
            )

        before_hash = sha256_bytes(bytes(buffer))
        buffer[patch.offset:end] = patch.replacement
        after_hash = sha256_bytes(bytes(buffer))
        applied.append(
            AppliedPatch(
                patch_id=patch.patch_id,
                target=patch.target,
                offset=patch.offset,
                length=len(patch.expected),
                before_sha256=before_hash,
                after_sha256=after_hash,
            )
        )

    for target, buffer in buffers.items():
        _atomic_write(target, bytes(buffer))

    report = PatchApplicationReport(
        format_version=1,
        profile_id=manifest.profile_id,
        patch_file=patch_path.name,
        applied=tuple(applied),
    )
    report_path = layout.manifests / f"patch-{patch_path.stem}.json"
    _atomic_write(report_path, report.to_json().encode("utf-8"))
    return report
