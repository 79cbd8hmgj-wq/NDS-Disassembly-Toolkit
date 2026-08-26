from __future__ import annotations

import json
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from nds_disassembly_toolkit.compression.blz import compress_blz
from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.profile import RomProfile
from nds_disassembly_toolkit.source_compile import CompiledSource, SourceToolchain, compile_source_patch
from nds_disassembly_toolkit.source_patch import (
    SourceHook,
    SourcePatchManifest,
    SourceTarget,
    encode_hook,
    load_source_patch_manifest,
    resolve_source_target,
)
from nds_disassembly_toolkit.workspace.manifest import sha256_bytes
from nds_disassembly_toolkit.workspace.model import WorkspaceLayout


@dataclass(frozen=True)
class AppliedSourceHook:
    hook_id: str
    runtime_address: int
    symbol: str
    destination: int
    before: str
    after: str


@dataclass(frozen=True)
class SourcePatchReport:
    format_version: int
    profile_id: str | None
    target: str
    manifest_file: str
    runtime_address: int
    compiled_size: int
    compiled_sha256: str
    target_storage_encoding: str
    target_stored_size: int
    passthrough_length: int | None
    before_runtime_sha256: str
    after_runtime_sha256: str
    before_stored_sha256: str
    after_stored_sha256: str
    source_hashes: tuple[tuple[str, str], ...]
    commands: tuple[tuple[str, ...], ...]
    hooks: tuple[AppliedSourceHook, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "profile_id": self.profile_id,
            "target": self.target,
            "manifest_file": self.manifest_file,
            "runtime_address": self.runtime_address,
            "compiled_size": self.compiled_size,
            "compiled_sha256": self.compiled_sha256,
            "target_storage_encoding": self.target_storage_encoding,
            "target_stored_size": self.target_stored_size,
            "passthrough_length": self.passthrough_length,
            "before_runtime_sha256": self.before_runtime_sha256,
            "after_runtime_sha256": self.after_runtime_sha256,
            "before_stored_sha256": self.before_stored_sha256,
            "after_stored_sha256": self.after_stored_sha256,
            "source_hashes": [
                {"path": path, "sha256": digest} for path, digest in self.source_hashes
            ],
            "commands": [list(command) for command in self.commands],
            "hooks": [asdict(hook) for hook in self.hooks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _ranges_overlap(first_start: int, first_end: int, second_start: int, second_end: int) -> bool:
    return first_start < second_end and second_start < first_end


def _canonical_hook_destination(hook: SourceHook, symbol_address: int) -> int:
    if hook.mode == "thumb":
        return symbol_address & ~1
    if symbol_address & 1:
        raise WorkspaceError(
            f"hook {hook.hook_id!r} ARM destination symbol {hook.symbol!r} is a Thumb-state symbol"
        )
    return symbol_address


def build_patched_runtime(
    target: SourceTarget,
    manifest: SourcePatchManifest,
    compiled: CompiledSource,
) -> tuple[bytes, tuple[AppliedSourceHook, ...]]:
    if len(compiled.image) > manifest.max_size:
        raise WorkspaceError(
            f"compiled source patch size {len(compiled.image)} exceeds max_size {manifest.max_size}"
        )
    placement_start = target.placement_offset
    placement_end = placement_start + len(compiled.image)
    if placement_start < 0 or placement_end > target.runtime_size:
        raise WorkspaceError("compiled source patch placement exceeds runtime image")
    emitted_runtime_start = manifest.runtime_address
    emitted_runtime_end = emitted_runtime_start + len(compiled.image)

    hook_ranges: list[tuple[int, int, str]] = []
    prepared_hooks: list[tuple[int, bytes, AppliedSourceHook]] = []
    for hook in manifest.hooks:
        hook_start = hook.runtime_address - target.runtime_base
        hook_end = hook_start + len(hook.expected)
        if hook_start < 0 or hook_end > target.runtime_size:
            raise WorkspaceError(f"hook {hook.hook_id!r} is outside target runtime image")
        if _ranges_overlap(placement_start, placement_end, hook_start, hook_end):
            raise WorkspaceError(f"hook {hook.hook_id!r} overlaps injected code")
        for other_start, other_end, other_id in hook_ranges:
            if _ranges_overlap(hook_start, hook_end, other_start, other_end):
                raise WorkspaceError(f"hook ranges overlap: {other_id!r} and {hook.hook_id!r}")
        actual = target.runtime_image[hook_start:hook_end]
        if actual != hook.expected:
            raise WorkspaceError(
                f"hook {hook.hook_id!r} guard mismatch at 0x{hook.runtime_address:08X}: "
                f"expected {hook.expected.hex()}, found {actual.hex()}"
            )
        try:
            raw_destination = compiled.symbol_address(hook.symbol)
        except WorkspaceError as exc:
            raise WorkspaceError(
                f"hook {hook.hook_id!r} references missing symbol {hook.symbol!r}"
            ) from exc
        destination = _canonical_hook_destination(hook, raw_destination)
        if not emitted_runtime_start <= destination < emitted_runtime_end:
            raise WorkspaceError(
                f"hook {hook.hook_id!r} symbol {hook.symbol!r} resolves outside emitted image"
            )
        encoded = encode_hook(hook, destination)
        hook_ranges.append((hook_start, hook_end, hook.hook_id))
        prepared_hooks.append(
            (
                hook_start,
                encoded,
                AppliedSourceHook(
                    hook_id=hook.hook_id,
                    runtime_address=hook.runtime_address,
                    symbol=hook.symbol,
                    destination=destination,
                    before=hook.expected.hex(),
                    after=encoded.hex(),
                ),
            )
        )

    patched = bytearray(target.runtime_image)
    patched[placement_start:placement_end] = compiled.image
    for hook_start, encoded, _report in prepared_hooks:
        patched[hook_start : hook_start + len(encoded)] = encoded
    return bytes(patched), tuple(report for _offset, _encoded, report in prepared_hooks)


def encode_target_storage(target: SourceTarget, runtime_image: bytes) -> bytes:
    if len(runtime_image) != target.runtime_size:
        raise WorkspaceError(
            f"patched runtime size changed: expected {target.runtime_size}, got {len(runtime_image)}"
        )
    if target.storage_encoding in {"decoded-overlay", "raw-arm"}:
        if len(runtime_image) != target.stored_size:
            raise WorkspaceError(
                f"stored size mismatch for {target.storage_encoding}: "
                f"expected {target.stored_size}, got {len(runtime_image)}"
            )
        return runtime_image
    if target.storage_encoding == "blz":
        if target.passthrough_length is None:
            raise WorkspaceError("BLZ target is missing passthrough length")
        try:
            return compress_blz(
                runtime_image,
                passthrough_length=target.passthrough_length,
                target_size=target.stored_size,
            )
        except (ValueError, AssertionError) as exc:
            raise WorkspaceError(f"cannot re-encode BLZ target at exact stored size: {exc}") from exc
    raise WorkspaceError(f"unsupported source target storage encoding: {target.storage_encoding}")


def _write_temp(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{path.name}.tmp-", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    if temporary is None:
        raise WorkspaceError(f"failed to create temporary file for {path}")
    return temporary


def _commit_target_and_report(
    target_path: Path,
    stored_data: bytes,
    report_path: Path,
    report_data: bytes,
    original_stored: bytes,
) -> None:
    target_temp = _write_temp(target_path, stored_data)
    report_temp = _write_temp(report_path, report_data)
    try:
        try:
            current_stored = target_path.read_bytes()
        except OSError as exc:
            raise WorkspaceError(f"cannot revalidate source patch target {target_path}: {exc}") from exc
        if current_stored != original_stored:
            raise WorkspaceError("source patch target changed during build; refusing stale write")
        target_temp.replace(target_path)
        try:
            report_temp.replace(report_path)
        except Exception:
            rollback = _write_temp(target_path, original_stored)
            rollback.replace(target_path)
            raise
    finally:
        target_temp.unlink(missing_ok=True)
        report_temp.unlink(missing_ok=True)


def apply_source_patch(
    workspace: Path,
    manifest_path: Path,
    profile: RomProfile | None = None,
    *,
    toolchain: SourceToolchain | None = None,
) -> SourcePatchReport:
    manifest = load_source_patch_manifest(manifest_path)
    resolve_source_target(workspace, manifest, profile)
    compiled = compile_source_patch(
        manifest_path, manifest, toolchain or SourceToolchain()
    )
    target = resolve_source_target(workspace, manifest, profile)
    original_stored = target.path.read_bytes()
    patched_runtime, hooks = build_patched_runtime(target, manifest, compiled)
    stored_data = encode_target_storage(target, patched_runtime)
    report = SourcePatchReport(
        format_version=1,
        profile_id=manifest.profile_id,
        target=manifest.target,
        manifest_file=manifest_path.name,
        runtime_address=manifest.runtime_address,
        compiled_size=len(compiled.image),
        compiled_sha256=sha256_bytes(compiled.image),
        target_storage_encoding=target.storage_encoding,
        target_stored_size=target.stored_size,
        passthrough_length=target.passthrough_length,
        before_runtime_sha256=sha256_bytes(target.runtime_image),
        after_runtime_sha256=sha256_bytes(patched_runtime),
        before_stored_sha256=sha256_bytes(original_stored),
        after_stored_sha256=sha256_bytes(stored_data),
        source_hashes=compiled.source_hashes,
        commands=compiled.commands,
        hooks=hooks,
    )
    layout = WorkspaceLayout.from_root(workspace)
    report_path = layout.manifests / f"source-patch-{manifest_path.stem}.json"
    _commit_target_and_report(
        target.path,
        stored_data,
        report_path,
        report.to_json().encode("utf-8"),
        original_stored,
    )
    return report
