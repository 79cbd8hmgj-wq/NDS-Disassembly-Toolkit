from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import TypeAlias

from nds_disassembly_toolkit.errors import WorkspaceError

_U32_MASK = 0xFFFFFFFF


class Condition(IntEnum):
    EQ = 0x0
    NE = 0x1
    CS = 0x2
    HS = 0x2
    CC = 0x3
    LO = 0x3
    MI = 0x4
    PL = 0x5
    VS = 0x6
    VC = 0x7
    HI = 0x8
    LS = 0x9
    GE = 0xA
    LT = 0xB
    GT = 0xC
    LE = 0xD
    AL = 0xE


class Register(IntEnum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    R9 = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    SP = 13
    R14 = 14
    LR = 14
    R15 = 15
    PC = 15


class ShiftType(IntEnum):
    LSL = 0
    LSR = 1
    ASR = 2
    ROR = 3


class DataOpcode(IntEnum):
    AND = 0x0
    EOR = 0x1
    SUB = 0x2
    RSB = 0x3
    ADD = 0x4
    ADC = 0x5
    SBC = 0x6
    RSC = 0x7
    TST = 0x8
    TEQ = 0x9
    CMP = 0xA
    CMN = 0xB
    ORR = 0xC
    MOV = 0xD
    BIC = 0xE
    MVN = 0xF


def _condition_bits(condition: Condition) -> int:
    if not isinstance(condition, Condition):
        raise WorkspaceError("ARM condition is invalid")
    return int(condition) << 28


def _register(value: Register, label: str) -> int:
    if not isinstance(value, Register):
        raise WorkspaceError(f"{label} register is invalid")
    return int(value)


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


def encode_branch(
    source_address: int,
    target_address: int,
    *,
    link: bool = False,
    condition: Condition = Condition.AL,
) -> int:
    source = _arm_address(source_address, "branch source address")
    target = _arm_address(target_address, "branch target address")
    displacement = target - (source + 8)
    if displacement & 0x3:
        raise WorkspaceError("branch displacement must be word aligned")
    word_displacement = displacement // 4
    if not -(1 << 23) <= word_displacement < (1 << 23):
        raise WorkspaceError("ARM branch target is out of range")
    return (
        _condition_bits(condition)
        | 0x0A000000
        | (int(link) << 24)
        | (word_displacement & 0x00FFFFFF)
    )


def decode_branch_target(source_address: int, instruction: int) -> int:
    source = _arm_address(source_address, "branch source address")
    encoded = _u32(instruction, "branch instruction")
    if (encoded & 0x0E000000) != 0x0A000000:
        raise WorkspaceError("instruction is not an ARM branch")
    displacement = encoded & 0x00FFFFFF
    if displacement & 0x00800000:
        displacement -= 1 << 24
    return (source + 8 + displacement * 4) & _U32_MASK


def encode_bx(
    register: Register,
    *,
    condition: Condition = Condition.AL,
) -> int:
    return _condition_bits(condition) | 0x012FFF10 | _register(register, "BX")


def _rotate_right(value: int, amount: int) -> int:
    amount &= 31
    value &= _U32_MASK
    if amount == 0:
        return value
    return ((value >> amount) | (value << (32 - amount))) & _U32_MASK


def _rotate_left(value: int, amount: int) -> int:
    return _rotate_right(value, -amount)


def encode_rotated_immediate(value: int) -> int:
    immediate = _u32(value, "data-processing immediate")
    for rotation in range(16):
        amount = rotation * 2
        candidate = _rotate_left(immediate, amount)
        if candidate <= 0xFF and _rotate_right(candidate, amount) == immediate:
            return (rotation << 8) | candidate
    raise WorkspaceError(f"value 0x{immediate:08X} is not an ARM rotated immediate")


def encode_data_processing_immediate(
    opcode: DataOpcode,
    *,
    rd: Register = Register.R0,
    rn: Register = Register.R0,
    immediate: int,
    set_flags: bool = False,
    condition: Condition = Condition.AL,
) -> int:
    if not isinstance(opcode, DataOpcode):
        raise WorkspaceError("data-processing opcode is invalid")
    if type(set_flags) is not bool:
        raise WorkspaceError("data-processing set_flags must be boolean")
    if opcode in (DataOpcode.TST, DataOpcode.TEQ, DataOpcode.CMP, DataOpcode.CMN):
        if not set_flags:
            raise WorkspaceError("comparison data-processing instructions set flags")
        if rd is not Register.R0:
            raise WorkspaceError("comparison destination register must be r0 placeholder")
    return (
        _condition_bits(condition)
        | 0x02000000
        | (int(opcode) << 21)
        | (int(set_flags) << 20)
        | (_register(rn, "data-processing source") << 16)
        | (_register(rd, "data-processing destination") << 12)
        | encode_rotated_immediate(immediate)
    )


def encode_data_processing_register(
    opcode: DataOpcode,
    *,
    rd: Register = Register.R0,
    rn: Register = Register.R0,
    rm: Register,
    set_flags: bool = False,
    condition: Condition = Condition.AL,
) -> int:
    if not isinstance(opcode, DataOpcode):
        raise WorkspaceError("data-processing opcode is invalid")
    if type(set_flags) is not bool:
        raise WorkspaceError("data-processing set_flags must be boolean")
    if opcode in (DataOpcode.TST, DataOpcode.TEQ, DataOpcode.CMP, DataOpcode.CMN):
        if not set_flags:
            raise WorkspaceError("comparison data-processing instructions set flags")
        if rd is not Register.R0:
            raise WorkspaceError("comparison destination register must be r0 placeholder")
    return (
        _condition_bits(condition)
        | (int(opcode) << 21)
        | (int(set_flags) << 20)
        | (_register(rn, "data-processing source") << 16)
        | (_register(rd, "data-processing destination") << 12)
        | _register(rm, "data-processing operand")
    )


def encode_data_processing_shifted_register(
    opcode: DataOpcode,
    *,
    rd: Register = Register.R0,
    rn: Register = Register.R0,
    rm: Register,
    shift_type: ShiftType,
    shift_amount: int,
    set_flags: bool = False,
    condition: Condition = Condition.AL,
) -> int:
    if not isinstance(shift_type, ShiftType):
        raise WorkspaceError("shift type is invalid")
    if isinstance(shift_amount, bool) or not isinstance(shift_amount, int):
        raise WorkspaceError("shift amount must be an integer")
    if not 0 <= shift_amount <= 31:
        raise WorkspaceError("shift amount must be between 0 and 31")
    base = encode_data_processing_register(
        opcode,
        rd=rd,
        rn=rn,
        rm=rm,
        set_flags=set_flags,
        condition=condition,
    )
    return base | (shift_amount << 7) | (int(shift_type) << 5)


def encode_mul(
    rd: Register,
    rm: Register,
    rs: Register,
    *,
    set_flags: bool = False,
    condition: Condition = Condition.AL,
) -> int:
    if type(set_flags) is not bool:
        raise WorkspaceError("multiply set_flags must be boolean")
    destination = _register(rd, "multiply destination")
    first = _register(rm, "multiply first operand")
    second = _register(rs, "multiply second operand")
    if destination == Register.PC or first == Register.PC or second == Register.PC:
        raise WorkspaceError("multiply cannot use r15")
    return (
        _condition_bits(condition)
        | (int(set_flags) << 20)
        | (destination << 16)
        | (second << 8)
        | 0x90
        | first
    )


def encode_load_store(
    rd: Register,
    rn: Register,
    *,
    offset: int = 0,
    load: bool,
    byte: bool = False,
    pre_index: bool = True,
    writeback: bool = False,
    condition: Condition = Condition.AL,
) -> int:
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise WorkspaceError("load/store offset must be an integer")
    if not -0xFFF <= offset <= 0xFFF:
        raise WorkspaceError("load/store offset must fit 12 bits")
    for label, value in (
        ("load", load),
        ("byte", byte),
        ("pre_index", pre_index),
        ("writeback", writeback),
    ):
        if type(value) is not bool:
            raise WorkspaceError(f"load/store {label} must be boolean")
    return (
        _condition_bits(condition)
        | 0x04000000
        | (int(pre_index) << 24)
        | (int(offset >= 0) << 23)
        | (int(byte) << 22)
        | (int(writeback) << 21)
        | (int(load) << 20)
        | (_register(rn, "load/store base") << 16)
        | (_register(rd, "load/store data") << 12)
        | abs(offset)
    )


def encode_halfword_transfer(
    rd: Register,
    rn: Register,
    *,
    offset: int = 0,
    load: bool,
    pre_index: bool = True,
    writeback: bool = False,
    condition: Condition = Condition.AL,
) -> int:
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise WorkspaceError("halfword offset must be an integer")
    if not -0xFF <= offset <= 0xFF:
        raise WorkspaceError("halfword offset must fit 8 bits")
    for label, value in (
        ("load", load),
        ("pre_index", pre_index),
        ("writeback", writeback),
    ):
        if type(value) is not bool:
            raise WorkspaceError(f"halfword {label} must be boolean")
    magnitude = abs(offset)
    return (
        _condition_bits(condition)
        | (int(pre_index) << 24)
        | (int(offset >= 0) << 23)
        | (1 << 22)
        | (int(writeback) << 21)
        | (int(load) << 20)
        | (_register(rn, "halfword base") << 16)
        | (_register(rd, "halfword data") << 12)
        | ((magnitude & 0xF0) << 4)
        | 0xB0
        | (magnitude & 0x0F)
    )


def _register_mask(registers: tuple[Register, ...], label: str) -> int:
    if not registers:
        raise WorkspaceError(f"{label} register list must be nonempty")
    seen: set[int] = set()
    mask = 0
    for register in registers:
        index = _register(register, label)
        if index in seen:
            raise WorkspaceError(f"{label} register list contains a duplicate")
        seen.add(index)
        mask |= 1 << index
    return mask


def encode_push(
    registers: tuple[Register, ...],
    *,
    condition: Condition = Condition.AL,
) -> int:
    return _condition_bits(condition) | 0x092D0000 | _register_mask(registers, "push")


def encode_pop(
    registers: tuple[Register, ...],
    *,
    condition: Condition = Condition.AL,
) -> int:
    return _condition_bits(condition) | 0x08BD0000 | _register_mask(registers, "pop")


def encode_literal_load(
    source_address: int,
    target_address: int,
    rd: Register,
    *,
    condition: Condition = Condition.AL,
) -> int:
    source = _arm_address(source_address, "literal-load source address")
    target = _arm_address(target_address, "literal-load target address")
    offset = target - (source + 8)
    if not -0xFFF <= offset <= 0xFFF:
        raise WorkspaceError("literal range exceeds 12-bit PC-relative load")
    return encode_load_store(
        rd,
        Register.PC,
        offset=offset,
        load=True,
        condition=condition,
    )


@dataclass(frozen=True)
class _LabelItem:
    name: str


@dataclass(frozen=True)
class _WordItem:
    value: int


@dataclass(frozen=True)
class _AlignItem:
    alignment: int


@dataclass(frozen=True)
class _LiteralItem:
    name: str
    value: int


@dataclass(frozen=True)
class _BranchItem:
    symbol: str
    link: bool
    condition: Condition


@dataclass(frozen=True)
class _LiteralLoadItem:
    register: Register
    symbol: str
    condition: Condition


ArmItem: TypeAlias = (
    _LabelItem | _WordItem | _AlignItem | _LiteralItem | _BranchItem | _LiteralLoadItem
)


def _symbol_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise WorkspaceError("ARM symbol name must be nonempty")
    return name


def label(name: str) -> ArmItem:
    return _LabelItem(_symbol_name(name))


def word(value: int) -> ArmItem:
    return _WordItem(_u32(value, "ARM word"))


def align(alignment: int) -> ArmItem:
    if isinstance(alignment, bool) or not isinstance(alignment, int):
        raise WorkspaceError("alignment must be an integer")
    if alignment < 4 or alignment & (alignment - 1):
        raise WorkspaceError("alignment must be a power of two at least four")
    return _AlignItem(alignment)


def literal(name: str, value: int) -> ArmItem:
    return _LiteralItem(_symbol_name(name), _u32(value, "literal value"))


def branch_to(
    symbol: str,
    *,
    link: bool = False,
    condition: Condition = Condition.AL,
) -> ArmItem:
    if type(link) is not bool:
        raise WorkspaceError("branch link must be boolean")
    _condition_bits(condition)
    return _BranchItem(_symbol_name(symbol), link, condition)


def load_literal(
    register: Register,
    symbol: str,
    *,
    condition: Condition = Condition.AL,
) -> ArmItem:
    _register(register, "literal-load destination")
    _condition_bits(condition)
    return _LiteralLoadItem(register, _symbol_name(symbol), condition)


@dataclass(frozen=True)
class ArmRelocation:
    kind: str
    symbol: str
    source_address: int
    target_address: int
    instruction: int


@dataclass(frozen=True)
class BuiltArmProgram:
    image: bytes
    symbols: dict[str, int]
    relocations: tuple[ArmRelocation, ...]


@dataclass(frozen=True)
class ArmProgram:
    items: tuple[ArmItem, ...] = ()

    def build(self, base_address: int, final_size: int) -> BuiltArmProgram:
        base = _arm_address(base_address, "ARM program base address")
        if isinstance(final_size, bool) or not isinstance(final_size, int):
            raise WorkspaceError("ARM program final size must be an integer")
        if final_size < 0:
            raise WorkspaceError("ARM program final size must be nonnegative")
        if final_size & 0x3:
            raise WorkspaceError("ARM program final size must be word aligned")

        symbols: dict[str, int] = {}
        offsets: list[int] = []
        offset = 0
        for item in self.items:
            offsets.append(offset)
            if isinstance(item, (_LabelItem, _LiteralItem)):
                if item.name in symbols:
                    raise WorkspaceError(f"duplicate symbol: {item.name}")
                symbols[item.name] = base + offset
            if isinstance(item, _LabelItem):
                continue
            if isinstance(item, _AlignItem):
                offset = (offset + item.alignment - 1) & ~(item.alignment - 1)
                if offset > final_size:
                    raise WorkspaceError("ARM program image exceeds final size")
                continue
            offset += 4
            if offset > final_size:
                raise WorkspaceError("ARM program image exceeds final size")

        image = bytearray(final_size)
        relocations: list[ArmRelocation] = []
        for item, item_offset in zip(self.items, offsets, strict=True):
            source_address = base + item_offset
            if isinstance(item, (_LabelItem, _AlignItem)):
                continue
            if isinstance(item, (_WordItem, _LiteralItem)):
                encoded = item.value
            elif isinstance(item, _BranchItem):
                target = symbols.get(item.symbol)
                if target is None:
                    raise WorkspaceError(f"unresolved symbol: {item.symbol}")
                encoded = encode_branch(
                    source_address,
                    target,
                    link=item.link,
                    condition=item.condition,
                )
                relocations.append(
                    ArmRelocation(
                        kind="branch",
                        symbol=item.symbol,
                        source_address=source_address,
                        target_address=target,
                        instruction=encoded,
                    )
                )
            elif isinstance(item, _LiteralLoadItem):
                target = symbols.get(item.symbol)
                if target is None:
                    raise WorkspaceError(f"unresolved symbol: {item.symbol}")
                encoded = encode_literal_load(
                    source_address,
                    target,
                    item.register,
                    condition=item.condition,
                )
                relocations.append(
                    ArmRelocation(
                        kind="literal_load",
                        symbol=item.symbol,
                        source_address=source_address,
                        target_address=target,
                        instruction=encoded,
                    )
                )
            else:
                raise WorkspaceError("unknown ARM program item")
            struct.pack_into("<I", image, item_offset, encoded)

        ordered_symbols = dict(sorted(symbols.items(), key=lambda item: (item[1], item[0])))
        return BuiltArmProgram(
            image=bytes(image),
            symbols=ordered_symbols,
            relocations=tuple(relocations),
        )


__all__ = [
    "ArmItem",
    "ArmProgram",
    "ArmRelocation",
    "BuiltArmProgram",
    "Condition",
    "DataOpcode",
    "Register",
    "ShiftType",
    "align",
    "branch_to",
    "decode_branch_target",
    "encode_branch",
    "encode_bx",
    "encode_data_processing_immediate",
    "encode_data_processing_register",
    "encode_data_processing_shifted_register",
    "encode_halfword_transfer",
    "encode_literal_load",
    "encode_load_store",
    "encode_mul",
    "encode_pop",
    "encode_push",
    "encode_rotated_immediate",
    "label",
    "literal",
    "load_literal",
    "word",
]
