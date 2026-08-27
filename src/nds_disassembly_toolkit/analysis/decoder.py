from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, cast

from capstone import (  # type: ignore[import-untyped]
    CS_ARCH_ARM,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
)
from capstone.arm import ARM_OP_IMM  # type: ignore[import-untyped]

from nds_disassembly_toolkit.analysis.model import (
    ControlFlowKind,
    DecodedInstruction,
    InstructionSet,
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


class _CapstoneOperand(Protocol):
    type: int
    imm: int


class _CapstoneInstruction(Protocol):
    address: int
    size: int
    bytes: bytearray
    mnemonic: str
    op_str: str
    operands: Sequence[_CapstoneOperand]

    def group(self, group_id: int) -> bool: ...


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
    )
