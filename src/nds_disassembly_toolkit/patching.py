from __future__ import annotations

import struct

from nds_disassembly_toolkit.errors import WorkspaceError

_U32_MASK = 0xFFFFFFFF


def _u32(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkspaceError(f"{label} must be an integer")
    if not 0 <= value <= _U32_MASK:
        raise WorkspaceError(f"{label} must fit unsigned 32-bit")
    return value


def _arm_address(value: int, label: str) -> int:
    result = _u32(value, label)
    if result & 0x3:
        raise WorkspaceError(f"{label} must be ARM aligned")
    return result


def encode_arm_branch(
    source_address: int,
    target_address: int,
    *,
    link: bool = False,
) -> int:
    source = _arm_address(source_address, "branch source address")
    target = _arm_address(target_address, "branch target address")
    if type(link) is not bool:
        raise WorkspaceError("branch link must be boolean")
    displacement = target - (source + 8)
    word_displacement = displacement // 4
    if not -(1 << 23) <= word_displacement < (1 << 23):
        raise WorkspaceError("ARM branch target is out of range")
    return 0xEA000000 | (int(link) << 24) | (word_displacement & 0x00FFFFFF)


def decode_arm_branch_target(source_address: int, instruction: int) -> int:
    source = _arm_address(source_address, "branch source address")
    encoded = _u32(instruction, "branch instruction")
    if (encoded & 0x0E000000) != 0x0A000000:
        raise WorkspaceError("instruction is not an ARM branch")
    displacement = encoded & 0x00FFFFFF
    if displacement & 0x00800000:
        displacement -= 1 << 24
    return (source + 8 + displacement * 4) & _U32_MASK


def encode_thumb_branch(source_address: int, target_address: int, *, link: bool) -> bytes:
    source = _u32(source_address, "Thumb branch source address")
    target = _u32(target_address, "Thumb branch target address")
    if source % 2 or target % 2:
        raise WorkspaceError("Thumb branch source and target must be halfword aligned")
    if type(link) is not bool:
        raise WorkspaceError("Thumb branch link must be boolean")
    displacement = target - (source + 4)
    if displacement % 2:
        raise WorkspaceError("Thumb branch displacement must be halfword aligned")

    if link:
        if not -4_194_304 <= displacement <= 4_194_302:
            raise WorkspaceError("Thumb BL target is outside signed 23-bit branch range")
        high = 0xF000 | ((displacement >> 12) & 0x7FF)
        low = 0xF800 | ((displacement >> 1) & 0x7FF)
        return struct.pack("<HH", high, low)

    if not -2_048 <= displacement <= 2_046:
        raise WorkspaceError("Thumb B target is outside signed 12-bit branch range")
    instruction = 0xE000 | ((displacement >> 1) & 0x7FF)
    return struct.pack("<H", instruction)
