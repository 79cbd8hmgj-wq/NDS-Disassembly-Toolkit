from __future__ import annotations

from nds_disassembly_toolkit.workspace.manifest import WorkspaceManifest, load_workspace_manifest


def _manifest(**kwargs: object) -> WorkspaceManifest:
    return WorkspaceManifest(
        format_version=1,
        profile_id=None,
        rom_sha256="0" * 64,
        rom_size=0x1000,
        arm9_sha256="1" * 64,
        arm7_sha256="2" * 64,
        files=(),
        overlays=(),
        **kwargs,
    )


def test_workspace_manifest_round_trips_arm_runtime_addresses(tmp_path) -> None:
    manifest = _manifest(
        arm9_ram_address=0x02000000,
        arm7_ram_address=0x02380000,
    )
    path = tmp_path / "workspace.json"
    path.write_text(manifest.to_json(), encoding="utf-8")

    loaded = load_workspace_manifest(path)

    assert loaded.arm9_ram_address == 0x02000000
    assert loaded.arm7_ram_address == 0x02380000


def test_legacy_workspace_manifest_without_runtime_addresses_still_loads(tmp_path) -> None:
    payload = _manifest().to_dict()
    payload.pop("arm9_ram_address", None)
    payload.pop("arm7_ram_address", None)
    import json

    path = tmp_path / "workspace.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_workspace_manifest(path)

    assert loaded.arm9_ram_address is None
    assert loaded.arm7_ram_address is None
