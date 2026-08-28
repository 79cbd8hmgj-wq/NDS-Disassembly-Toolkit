from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, cast

from capstone import (  # type: ignore[import-untyped]
    CS_AC_READ,
    CS_AC_WRITE,
    CS_ARCH_ARM,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
)
from capstone.arm import (  # type: ignore[import-untyped]
    ARM_CC_AL,
    ARM_CC_EQ,
    ARM_CC_GE,
    ARM_CC_GT,
    ARM_CC_HI,
    ARM_CC_HS,
    ARM_CC_INVALID,
    ARM_CC_LE,
    ARM_CC_LO,
    ARM_CC_LS,
    ARM_CC_LT,
    ARM_CC_MI,
    ARM_CC_NE,
    ARM_CC_PL,
    ARM_CC_VC,
    ARM_CC_VS,
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_OP_REG,
    ARM_SFT_ASR,
    ARM_SFT_INVALID,
    ARM_SFT_LSL,
    ARM_SFT_LSR,
    ARM_SFT_ROR,
    ARM_SFT_RRX,
)

from nds_disassembly_toolkit.analysis.model import (
    ConditionCode,
    ControlFlowKind,
    DecodedInstruction,
    InstructionOperand,
    InstructionSemantics,
    InstructionSet,
    MemoryOperand,
    OperandAccess,
    OperandKind,
    OperandShift,
    Register,
    ShiftKind,
)

_CONDITION_SUFFIXES = frozenset(
    {
        "eq",
        "ne",
        "hs",
        "cs",
        "lo",
        "cc",
        "mi",
        "pl",
        "vs",
        "vc",
        "hi",
        "ls",
        "ge",
        "lt",
        "gt",
        "le",
    }
)

_CONDITION_CODES = {
    ARM_CC_INVALID: ConditionCode.INVALID,
    ARM_CC_EQ: ConditionCode.EQ,
    ARM_CC_NE: ConditionCode.NE,
    ARM_CC_HS: ConditionCode.HS,
    ARM_CC_LO: ConditionCode.LO,
    ARM_CC_MI: ConditionCode.MI,
    ARM_CC_PL: ConditionCode.PL,
    ARM_CC_VS: ConditionCode.VS,
    ARM_CC_VC: ConditionCode.VC,
    ARM_CC_HI: ConditionCode.HI,
    ARM_CC_LS: ConditionCode.LS,
    ARM_CC_GE: ConditionCode.GE,
    ARM_CC_LT: ConditionCode.LT,
    ARM_CC_GT: ConditionCode.GT,
    ARM_CC_LE: ConditionCode.LE,
    ARM_CC_AL: ConditionCode.AL,
}

_SHIFT_KINDS = {
    ARM_SFT_INVALID: ShiftKind.NONE,
    ARM_SFT_LSL: ShiftKind.LSL,
    ARM_SFT_LSR: ShiftKind.LSR,
    ARM_SFT_ASR: ShiftKind.ASR,
    ARM_SFT_ROR: ShiftKind.ROR,
    ARM_SFT_RRX: ShiftKind.RRX,
}


class _CapstoneMemory(Protocol):
    base: int
    index: int
    scale: int
    disp: int


class _CapstoneShift(Protocol):
    type: int
    value: int


class _CapstoneOperand(Protocol):
    type: int
    reg: int
    imm: int
    mem: _CapstoneMemory
    access: int
    shift: _CapstoneShift
    subtracted: bool


class _CapstoneInstruction(Protocol):
    address: int
    size: int
    bytes: bytearray
    mnemonic: str
    op_str: str
    operands: Sequence[_CapstoneOperand]
    cc: int
    writeback: bool

    def group(self, group_id: int) -> bool: ...

    def reg_name(self, reg_id: int) -> str: ...

    def regs_access(self) -> tuple[Sequence[int], Sequence[int]]: ...


def _is_return_idiom(instruction: _CapstoneInstruction) -> bool:
    return instruction.mnemonic.lower() == "bx" and instruction.op_str.lower().strip() == "lr"


def _control_flow(instruction: _CapstoneInstruction) -> ControlFlowKind:
    if instruction.group(CS_GRP_RET) or _is_return_idiom(instruction):
        return ControlFlowKind.RETURN
    if instruction.group(CS_GRP_CALL):
        return ControlFlowKind.CALL
    if instruction.group(CS_GRP_JUMP):
        return ControlFlowKind.BRANCH
    return ControlFlowKind.ORDINARY


def _direct_target(
    instruction: _CapstoneInstruction,
    control_flow: ControlFlowKind,
) -> int | None:
    if control_flow not in (ControlFlowKind.CALL, ControlFlowKind.BRANCH):
        return None
    if not instruction.operands:
        return None
    first = instruction.operands[0]
    return int(first.imm) if first.type == ARM_OP_IMM else None


def _is_conditional(mnemonic: str, control_flow: ControlFlowKind) -> bool:
    if control_flow not in (ControlFlowKind.CALL, ControlFlowKind.BRANCH):
        return False
    normalized = mnemonic.lower().split(".", maxsplit=1)[0]
    for base in ("blx", "bl", "bx", "b"):
        if normalized.startswith(base):
            return normalized[len(base) :] in _CONDITION_SUFFIXES
    return False


def _target_instruction_set(
    mnemonic: str,
    instruction_set: InstructionSet,
    direct_target: int | None,
) -> InstructionSet | None:
    if direct_target is None:
        return None
    if mnemonic.lower().startswith("blx"):
        return (
            InstructionSet.THUMB
            if instruction_set is InstructionSet.ARM
            else InstructionSet.ARM
        )
    return instruction_set


def _register(instruction: _CapstoneInstruction, reg_id: int) -> Register | None:
    if reg_id == 0:
        return None
    return Register.from_name(str(instruction.reg_name(reg_id)))


def _register_number(register: Register) -> int:
    return int(register.value[1:])


def _stable_registers(
    instruction: _CapstoneInstruction,
    reg_ids: Sequence[int],
) -> tuple[Register, ...]:
    registers = {
        register
        for reg_id in reg_ids
        if (register := _register(instruction, reg_id)) is not None
    }
    return tuple(sorted(registers, key=_register_number))


def _operand_access(raw_access: int) -> OperandAccess:
    access = OperandAccess.NONE
    if raw_access & CS_AC_READ:
        access |= OperandAccess.READ
    if raw_access & CS_AC_WRITE:
        access |= OperandAccess.WRITE
    return access


def _condition_code(raw_condition: int) -> ConditionCode:
    return _CONDITION_CODES.get(raw_condition, ConditionCode.INVALID)


def _shift(operand: _CapstoneOperand) -> OperandShift:
    kind = _SHIFT_KINDS.get(int(operand.shift.type), ShiftKind.NONE)
    return OperandShift(kind=kind, value=int(operand.shift.value))


def _memory(
    instruction: _CapstoneInstruction,
    operand: _CapstoneOperand,
) -> MemoryOperand:
    return MemoryOperand(
        base=_register(instruction, int(operand.mem.base)),
        index=_register(instruction, int(operand.mem.index)),
        scale=int(operand.mem.scale),
        displacement=int(operand.mem.disp),
        subtract_index=bool(operand.subtracted),
    )


def _access_width(mnemonic: str) -> int | None:
    normalized = mnemonic.lower().split(".", maxsplit=1)[0]
    if normalized.startswith(("ldrsb", "strb", "ldrb")):
        return 1
    if normalized.startswith(("ldrsh", "strh", "ldrh")):
        return 2
    if normalized.startswith(("ldr", "str")):
        return 4
    return None


def _memory_access(mnemonic: str, raw_access: int) -> OperandAccess:
    normalized = mnemonic.lower().split(".", maxsplit=1)[0]
    if normalized.startswith("ldr"):
        return OperandAccess.READ
    if normalized.startswith("str"):
        return OperandAccess.WRITE
    return _operand_access(raw_access)


def _register_access(
    register: Register,
    *,
    registers_read: tuple[Register, ...],
    registers_written: tuple[Register, ...],
) -> OperandAccess:
    access = OperandAccess.NONE
    if register in registers_read:
        access |= OperandAccess.READ
    if register in registers_written:
        access |= OperandAccess.WRITE
    return access


def _convert_operand(
    instruction: _CapstoneInstruction,
    operand: _CapstoneOperand,
    *,
    registers_read: tuple[Register, ...],
    registers_written: tuple[Register, ...],
) -> InstructionOperand | None:
    if operand.type == ARM_OP_REG:
        register = _register(instruction, int(operand.reg))
        if register is None:
            return None
        access = _register_access(
            register,
            registers_read=registers_read,
            registers_written=registers_written,
        )
        if access is OperandAccess.NONE:
            access = _operand_access(int(operand.access))
        return InstructionOperand(
            kind=OperandKind.REGISTER,
            access=access,
            register=register,
            shift=_shift(operand),
        )
    if operand.type == ARM_OP_IMM:
        return InstructionOperand(
            kind=OperandKind.IMMEDIATE,
            access=_operand_access(int(operand.access)),
            immediate=int(operand.imm),
            shift=_shift(operand),
        )
    if operand.type == ARM_OP_MEM:
        return InstructionOperand(
            kind=OperandKind.MEMORY,
            access=_memory_access(instruction.mnemonic, int(operand.access)),
            memory=_memory(instruction, operand),
            shift=_shift(operand),
            access_width=_access_width(instruction.mnemonic),
        )
    return None


def _register_list(
    instruction: _CapstoneInstruction,
    converted: Sequence[InstructionOperand],
) -> InstructionOperand | None:
    registers = tuple(
        sorted(
            {
                register
                for operand in converted
                if operand.kind is OperandKind.REGISTER
                and (register := operand.register) is not None
            },
            key=_register_number,
        )
    )
    if not registers:
        return None
    mnemonic = instruction.mnemonic.lower()
    access = OperandAccess.READ if mnemonic == "push" else OperandAccess.WRITE
    return InstructionOperand(
        kind=OperandKind.REGISTER_LIST,
        access=access,
        registers=registers,
    )


def _semantics(instruction: _CapstoneInstruction) -> InstructionSemantics:
    raw_read, raw_written = instruction.regs_access()
    registers_read = _stable_registers(instruction, raw_read)
    registers_written = _stable_registers(instruction, raw_written)
    converted = tuple(
        operand
        for raw_operand in instruction.operands
        if (
            operand := _convert_operand(
                instruction,
                raw_operand,
                registers_read=registers_read,
                registers_written=registers_written,
            )
        )
        is not None
    )
    if instruction.mnemonic.lower() in {"push", "pop"}:
        register_list = _register_list(instruction, converted)
        operands = () if register_list is None else (register_list,)
    else:
        operands = converted
    return InstructionSemantics(
        operands=operands,
        registers_read=registers_read,
        registers_written=registers_written,
        condition=_condition_code(int(instruction.cc)),
        writeback=bool(instruction.writeback),
    )


def decode_instruction(
    data: bytes,
    *,
    address: int,
    instruction_set: InstructionSet,
) -> DecodedInstruction | None:
    if address < 0:
        raise ValueError("instruction address must be non-negative")
    if address % instruction_set.alignment:
        raise ValueError(
            f"{instruction_set.value} instruction address must be "
            f"{instruction_set.alignment}-byte aligned"
        )

    mode = CS_MODE_ARM if instruction_set is InstructionSet.ARM else CS_MODE_THUMB
    engine = Cs(CS_ARCH_ARM, mode | CS_MODE_LITTLE_ENDIAN)
    engine.detail = True
    decoded = cast(
        Iterable[_CapstoneInstruction],
        engine.disasm(data, address, count=1),
    )
    instruction = next(iter(decoded), None)
    if instruction is None:
        return None

    control_flow = _control_flow(instruction)
    direct_target = _direct_target(instruction, control_flow)
    return DecodedInstruction(
        address=int(instruction.address),
        size=int(instruction.size),
        data=bytes(instruction.bytes),
        mnemonic=str(instruction.mnemonic),
        operands=str(instruction.op_str),
        instruction_set=instruction_set,
        control_flow=control_flow,
        direct_target=direct_target,
        target_instruction_set=_target_instruction_set(
            str(instruction.mnemonic),
            instruction_set,
            direct_target,
        ),
        conditional=_is_conditional(str(instruction.mnemonic), control_flow),
        semantics=_semantics(instruction),
    )
