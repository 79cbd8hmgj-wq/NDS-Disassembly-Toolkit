from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from nds_disassembly_toolkit.compression.lz10 import decompress_lz10, is_lz10
from nds_disassembly_toolkit.inspection import RomInspection

_SIGNATURE_FORMATS: dict[bytes, str] = {
    b"BMD0": "NSBMD",
    b"BTX0": "NSBTX",
    b"SDAT": "SDAT",
    b"NARC": "NARC",
    b"RGCN": "NCGR",
    b"RLCN": "NCLR",
    b"RCSN": "NSCR",
    b"BCA0": "NSBCA",
    b"BMA0": "NSBMA",
    b"BTP0": "NSBTP",
    b"BTA0": "NSBTA",
    b"BVA0": "NSBVA",
}
_EXTENSION_FORMATS: tuple[tuple[str, str], ...] = (
    (".nsbmd", "NSBMD"),
    (".nsbtx", "NSBTX"),
    (".ntft", "NTFT"),
    (".ntfp", "NTFP"),
    (".sdat", "SDAT"),
    (".narc", "NARC"),
    (".ncgr", "NCGR"),
    (".nclr", "NCLR"),
    (".nscr", "NSCR"),
    (".nsbca", "NSBCA"),
    (".nsbma", "NSBMA"),
    (".nsbtp", "NSBTP"),
    (".nsbta", "NSBTA"),
    (".nsbva", "NSBVA"),
)
_RAW_EXTENSION_FORMATS = frozenset({"NTFT", "NTFP"})
_SIGNATURE_BACKED_FORMATS = frozenset(_SIGNATURE_FORMATS.values())


@dataclass(frozen=True)
class AssetRecord:
    file_id: int
    path: str
    raw_size: int
    decoded_size: int
    compression: str
    extension: str
    extension_format: str | None
    detected_format: str | None
    evidence: str
    decoded_magic: str
    extension_signature_match: bool | None

    @property
    def recognized(self) -> bool:
        return self.detected_format is not None

    @property
    def signed_mismatch(self) -> bool:
        return self.extension_signature_match is False


@dataclass(frozen=True)
class AssetInventory:
    profile_id: str | None
    supported: bool | None
    scanned_files: int
    recognized_assets: int
    unknown_files: int
    signed_mismatches: int
    formats: tuple[tuple[str, int], ...]
    compressions: tuple[tuple[str, int], ...]
    assets: tuple[AssetRecord, ...]

    @classmethod
    def from_records(
        cls,
        *,
        profile_id: str | None,
        supported: bool | None,
        scanned_files: int,
        records: tuple[AssetRecord, ...],
        include_unknown: bool,
    ) -> AssetInventory:
        ordered = tuple(sorted(records, key=lambda item: (item.file_id, item.path)))
        recognized = tuple(item for item in ordered if item.recognized)
        assets = ordered if include_unknown else recognized
        formats = Counter(
            item.detected_format for item in recognized if item.detected_format is not None
        )
        compressions = Counter(item.compression for item in recognized)
        return cls(
            profile_id=profile_id,
            supported=supported,
            scanned_files=scanned_files,
            recognized_assets=len(recognized),
            unknown_files=len(ordered) - len(recognized),
            signed_mismatches=sum(item.signed_mismatch for item in ordered),
            formats=tuple(sorted(formats.items())),
            compressions=tuple(sorted(compressions.items())),
            assets=assets,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "format_version": 1,
            "profile_id": self.profile_id,
            "supported": self.supported,
            "counts": {
                "scanned_files": self.scanned_files,
                "reported_files": len(self.assets),
                "recognized_assets": self.recognized_assets,
                "unknown_files": self.unknown_files,
                "signed_mismatches": self.signed_mismatches,
            },
            "formats": dict(self.formats),
            "compressions": dict(self.compressions),
            "assets": [asdict(item) for item in self.assets],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def _extension_format(extension: str) -> str | None:
    for base_extension, format_name in _EXTENSION_FORMATS:
        if extension == base_extension or extension.startswith(base_extension + "_"):
            return format_name
    return None


def _magic_text(data: bytes) -> str:
    magic = data[:4]
    if len(magic) == 4 and all(0x20 <= value <= 0x7E for value in magic):
        return magic.decode("ascii")
    return magic.hex().upper()


def detect_asset(file_id: int, path: str, raw_data: bytes) -> AssetRecord:
    compressed = is_lz10(raw_data)
    decoded = decompress_lz10(raw_data) if compressed else raw_data
    extension = Path(path).suffix.lower()
    expected_format = _extension_format(extension)
    signature_format = _SIGNATURE_FORMATS.get(decoded[:4])

    if signature_format is not None:
        detected_format = signature_format
        evidence = "signature"
    elif expected_format in _RAW_EXTENSION_FORMATS:
        detected_format = expected_format
        evidence = "extension"
    else:
        detected_format = None
        evidence = "unknown"

    extension_signature_match: bool | None = None
    if expected_format in _SIGNATURE_BACKED_FORMATS:
        extension_signature_match = signature_format == expected_format

    return AssetRecord(
        file_id=file_id,
        path=path,
        raw_size=len(raw_data),
        decoded_size=len(decoded),
        compression="lz10" if compressed else "raw",
        extension=extension,
        extension_format=expected_format,
        detected_format=detected_format,
        evidence=evidence,
        decoded_magic=_magic_text(decoded),
        extension_signature_match=extension_signature_match,
    )


def inventory_assets(
    rom_data: bytes,
    inspection: RomInspection,
    *,
    include_unknown: bool = False,
) -> AssetInventory:
    path_by_id = inspection.fnt.file_by_id()
    fat_by_id = {entry.file_id: entry for entry in inspection.fat}
    records = tuple(
        detect_asset(
            file_id,
            path_by_id[file_id].path,
            rom_data[fat_by_id[file_id].start : fat_by_id[file_id].end],
        )
        for file_id in sorted(path_by_id)
    )
    return AssetInventory.from_records(
        profile_id=inspection.profile_id,
        supported=inspection.supported,
        scanned_files=len(path_by_id),
        records=records,
        include_unknown=include_unknown,
    )
