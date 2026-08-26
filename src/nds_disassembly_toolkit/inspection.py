from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path

from nds_disassembly_toolkit.nds.fat import FatEntry, parse_fat
from nds_disassembly_toolkit.nds.fnt import FntTree, parse_fnt
from nds_disassembly_toolkit.nds.header import NdsHeader
from nds_disassembly_toolkit.nds.overlays import OverlayEntry, parse_arm7_overlays, parse_arm9_overlays
from nds_disassembly_toolkit.profile import RomIdentity, RomProfile, read_rom_identity, validate_rom
from nds_disassembly_toolkit.util import require_range


@dataclass(frozen=True)
class LayoutMismatch:
    field: str
    actual: int
    expected: int


@dataclass(frozen=True)
class RomInspection:
    source_path: Path
    identity: RomIdentity
    profile_id: str | None
    supported: bool | None
    header: NdsHeader
    fat: tuple[FatEntry, ...]
    fnt: FntTree
    arm9_overlays: tuple[OverlayEntry, ...]
    arm7_overlays: tuple[OverlayEntry, ...]
    layout_mismatches: tuple[LayoutMismatch, ...]

    def to_dict(self) -> dict[str, object]:
        path_by_id = self.fnt.file_by_id()
        overlay_ids_by_file_id: dict[int, list[int]] = {}
        for overlay in (*self.arm9_overlays, *self.arm7_overlays):
            overlay_ids_by_file_id.setdefault(overlay.file_id, []).append(overlay.overlay_id)
        missing = sorted(
            entry.file_id
            for entry in self.fat
            if entry.file_id not in path_by_id and entry.file_id not in overlay_ids_by_file_id
        )
        if missing:
            raise ValueError(f"FAT file IDs missing from FNT and overlay tables: {missing}")
        return {
            "source": str(self.source_path),
            "profile_id": self.profile_id,
            "supported": self.supported,
            "identity": asdict(self.identity),
            "header": asdict(self.header),
            "counts": {
                "files": len(self.fat),
                "directories": len(self.fnt.directories),
                "arm9_overlays": len(self.arm9_overlays),
                "arm7_overlays": len(self.arm7_overlays),
            },
            "layout_mismatches": [asdict(item) for item in self.layout_mismatches],
            "files": [
                {
                    "file_id": entry.file_id,
                    "path": path_by_id[entry.file_id].path if entry.file_id in path_by_id else None,
                    "overlay_ids": sorted(overlay_ids_by_file_id.get(entry.file_id, [])),
                    "start": entry.start,
                    "end": entry.end,
                    "size": entry.size,
                }
                for entry in self.fat
            ],
            "directories": [asdict(item) for item in self.fnt.directories],
            "arm9_overlays": [
                asdict(item)
                | {
                    "compressed_size": item.compressed_size,
                    "flags": item.flags,
                    "ram_end": item.ram_end,
                }
                for item in self.arm9_overlays
            ],
            "arm7_overlays": [
                asdict(item)
                | {
                    "compressed_size": item.compressed_size,
                    "flags": item.flags,
                    "ram_end": item.ram_end,
                }
                for item in self.arm7_overlays
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _identity_matches_profile(identity: RomIdentity, profile: RomProfile) -> bool:
    return (
        identity.title == profile.title
        and identity.game_code == profile.game_code
        and identity.maker_code == profile.maker_code
        and identity.revision == profile.revision
        and identity.size == profile.size
        and identity.sha256 == profile.sha256
    )


def _layout_mismatches(
    header: NdsHeader,
    profile: RomProfile,
    *,
    file_count: int,
    directory_count: int,
    arm9_overlay_count: int,
    arm7_overlay_count: int,
) -> tuple[LayoutMismatch, ...]:
    actual = {
        "arm9_offset": header.arm9_offset,
        "arm9_ram_address": header.arm9_ram_address,
        "arm9_size": header.arm9_size,
        "arm7_offset": header.arm7_offset,
        "arm7_ram_address": header.arm7_ram_address,
        "arm7_size": header.arm7_size,
        "fnt_offset": header.fnt_offset,
        "fnt_size": header.fnt_size,
        "fat_offset": header.fat_offset,
        "fat_size": header.fat_size,
        "arm9_overlay_offset": header.arm9_overlay_offset,
        "arm9_overlay_size": header.arm9_overlay_size,
        "arm7_overlay_offset": header.arm7_overlay_offset,
        "arm7_overlay_size": header.arm7_overlay_size,
        "nitrofs_file_count": file_count,
        "directory_count": directory_count,
        "arm9_overlay_count": arm9_overlay_count,
        "arm7_overlay_count": arm7_overlay_count,
    }
    expected = asdict(profile.expected)
    return tuple(
        LayoutMismatch(field=name, actual=value, expected=expected[name])
        for name, value in sorted(actual.items())
        if value != expected[name]
    )


def inspect_rom(
    path: Path,
    profile: RomProfile | None = None,
    require_supported: bool = False,
) -> RomInspection:
    if require_supported and profile is None:
        raise ValueError("require_supported=True requires a ROM profile")

    if profile is None:
        identity = read_rom_identity(path)
        supported: bool | None = None
        profile_id: str | None = None
    elif require_supported:
        identity = validate_rom(path, profile)
        supported = True
        profile_id = profile.id
    else:
        identity = read_rom_identity(path)
        supported = _identity_matches_profile(identity, profile)
        profile_id = profile.id

    data = path.read_bytes()
    header = NdsHeader.from_bytes(data)
    for section in header.section_ranges():
        if section.size:
            require_range(data, section.offset, section.size, section.name)
    fat = parse_fat(data, header)
    fnt = parse_fnt(data, header, fat_entry_count=len(fat))
    arm9_overlays = parse_arm9_overlays(data, header)
    arm7_overlays = parse_arm7_overlays(data, header)
    mismatches = (
        ()
        if profile is None
        else _layout_mismatches(
            header,
            profile,
            file_count=len(fat),
            directory_count=len(fnt.directories),
            arm9_overlay_count=len(arm9_overlays),
            arm7_overlay_count=len(arm7_overlays),
        )
    )
    return RomInspection(
        source_path=path,
        identity=identity,
        profile_id=profile_id,
        supported=supported,
        header=header,
        fat=fat,
        fnt=fnt,
        arm9_overlays=arm9_overlays,
        arm7_overlays=arm7_overlays,
        layout_mismatches=mismatches,
    )
