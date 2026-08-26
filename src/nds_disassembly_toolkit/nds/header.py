from __future__ import annotations

from dataclasses import dataclass

from nds_disassembly_toolkit.errors import RomFormatError
from nds_disassembly_toolkit.util import Buffer, read_u32_le, require_range


def _decode_ascii(raw: memoryview) -> str:
    try:
        return raw.tobytes().split(b"\x00", 1)[0].decode("ascii", errors="strict").rstrip()
    except UnicodeDecodeError as exc:
        raise RomFormatError("NDS header text is not valid ASCII") from exc


@dataclass(frozen=True)
class SectionRange:
    name: str
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class NdsHeader:
    title: str
    game_code: str
    maker_code: str
    revision: int
    arm9_offset: int
    arm9_entry_address: int
    arm9_ram_address: int
    arm9_size: int
    arm7_offset: int
    arm7_entry_address: int
    arm7_ram_address: int
    arm7_size: int
    fnt_offset: int
    fnt_size: int
    fat_offset: int
    fat_size: int
    arm9_overlay_offset: int
    arm9_overlay_size: int
    arm7_overlay_offset: int
    arm7_overlay_size: int
    rom_size_field: int

    @classmethod
    def from_bytes(cls, data: Buffer) -> "NdsHeader":
        header = require_range(data, 0, 0x200, "NDS header")
        result = cls(
            title=_decode_ascii(header[0x00:0x0C]),
            game_code=_decode_ascii(header[0x0C:0x10]),
            maker_code=_decode_ascii(header[0x10:0x12]),
            revision=header[0x1E],
            arm9_offset=read_u32_le(header, 0x20, "ARM9 ROM offset"),
            arm9_entry_address=read_u32_le(header, 0x24, "ARM9 entry address"),
            arm9_ram_address=read_u32_le(header, 0x28, "ARM9 RAM address"),
            arm9_size=read_u32_le(header, 0x2C, "ARM9 size"),
            arm7_offset=read_u32_le(header, 0x30, "ARM7 ROM offset"),
            arm7_entry_address=read_u32_le(header, 0x34, "ARM7 entry address"),
            arm7_ram_address=read_u32_le(header, 0x38, "ARM7 RAM address"),
            arm7_size=read_u32_le(header, 0x3C, "ARM7 size"),
            fnt_offset=read_u32_le(header, 0x40, "FNT offset"),
            fnt_size=read_u32_le(header, 0x44, "FNT size"),
            fat_offset=read_u32_le(header, 0x48, "FAT offset"),
            fat_size=read_u32_le(header, 0x4C, "FAT size"),
            arm9_overlay_offset=read_u32_le(header, 0x50, "ARM9 overlay offset"),
            arm9_overlay_size=read_u32_le(header, 0x54, "ARM9 overlay size"),
            arm7_overlay_offset=read_u32_le(header, 0x58, "ARM7 overlay offset"),
            arm7_overlay_size=read_u32_le(header, 0x5C, "ARM7 overlay size"),
            rom_size_field=read_u32_le(header, 0x80, "ROM size field"),
        )
        for label, size in (
            ("ARM9 overlay table size", result.arm9_overlay_size),
            ("ARM7 overlay table size", result.arm7_overlay_size),
        ):
            if size % 32 != 0:
                raise RomFormatError(f"{label} must be a multiple of 32, got {size}")
        return result

    def section_ranges(self) -> tuple[SectionRange, ...]:
        return (
            SectionRange("arm9", self.arm9_offset, self.arm9_size),
            SectionRange("arm7", self.arm7_offset, self.arm7_size),
            SectionRange("fnt", self.fnt_offset, self.fnt_size),
            SectionRange("fat", self.fat_offset, self.fat_size),
            SectionRange("arm9_overlays", self.arm9_overlay_offset, self.arm9_overlay_size),
            SectionRange("arm7_overlays", self.arm7_overlay_offset, self.arm7_overlay_size),
        )
