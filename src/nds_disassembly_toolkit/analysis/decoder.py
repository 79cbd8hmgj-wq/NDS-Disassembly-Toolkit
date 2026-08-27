from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, cast

from capstone import (  # type: ignore[import-untyped]
    CS_ARCH_ARM,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    Cs,
)
from capstone.arm_const import (  # type: ignore[import-untyped]
    ARM_CC_AL,
    ARM_CC_INVALID,
    ARM_OP_IMM,
    ARM_OP_REG,
    ARM_REG_LR,
    ARM_REG_PC,
)

from nds_disassembly_toolkit.analysis.model import (
    Component,
    ControlFlowKind,
    DecodedInstruction,
    ExecutionMode,
)


class InstructionDecoder(Protocol):
    def decode_one(
        self,
        component: Component,
        address: int,
        mode: ExecutionMode,
    ) -> DecodedInstruction | None: ...


class _ArmOperand(Protocol):
    type: int
    imm: int
    reg: int


class _CapstoneInstruction(Protocol):
    address: int
    size: int
    mnemonic: str
    op_str: str
    groups: Sequence[int]
    cc: int
    operands: Sequence[_ArmOperand]


class _CapstoneEngine(Protocol):
    detail: bool

    def disasm(
        self,
        code: bytes,
        address: int,
        count: int = 0,
    ) -> Iterable[_CapstoneInstruction]: ...


class CapstoneArmDecoder:
    """Translate Capstone ARM/Thumb decoding into toolkit-owned analysis models."""

    def __init__(self) -> None:
        self._arm = cast(_CapstoneEngine, Cs(CS_ARCH_ARM, CS_MODE_ARM))
        self._thumb = cast(_CapstoneEngine, Cs(CS_ARCH_ARM, CS_MODE_THUMB))
        self._arm.detail = True
        self._thumb.detail = True

    def decode_one(
        self,
        component: Component,
        address: int,
        mode: ExecutionMode,
    ) -> DecodedInstruction | None:
        if not component.base_address <= address < component.end_address:
            return None

        offset = address - component.base_address
        minimum_size = 4 if mode is ExecutionMode.ARM else 2
        if len(component.data) - offset < minimum_size:
            return None

        engine = self._arm if mode is ExecutionMode.ARM else self._thumb
        window = component.data[offset : offset + 4]
        instruction = next(iter(engine.disasm(window, address, count=1)), None)
        if instruction is None or instruction.address != address:
            return None

        target = self._direct_target(instruction)
        flow = self._flow_kind(instruction, target)
        target_mode = self._target_mode(instruction, mode, target)
        conditional = instruction.cc not in (ARM_CC_AL, ARM_CC_INVALID)
        return DecodedInstruction(
            address=instruction.address,
            size=instruction.size,
            mode=mode,
            mnemonic=instruction.mnemonic,
            operands=instruction.op_str,
            flow=flow,
            target=target,
            target_mode=target_mode,
            conditional=conditional,
        )

    @staticmethod
    def _direct_target(instruction: _CapstoneInstruction) -> int | None:
        for operand in instruction.operands:
            if operand.type == ARM_OP_IMM:
                return int(operand.imm) & 0xFFFFFFFF
        return None

    @staticmethod
    def _flow_kind(
        instruction: _CapstoneInstruction,
        target: int | None,
    ) -> ControlFlowKind:
        if CapstoneArmDecoder._is_return(instruction):
            return ControlFlowKind.RETURN
        if CS_GRP_CALL in instruction.groups:
            return ControlFlowKind.CALL
        if CS_GRP_JUMP in instruction.groups:
            if target is None:
                return ControlFlowKind.INDIRECT_BRANCH
            return ControlFlowKind.BRANCH
        return ControlFlowKind.FALLTHROUGH

    @staticmethod
    def _is_return(instruction: _CapstoneInstruction) -> bool:
        if CS_GRP_RET in instruction.groups:
            return True
        if instruction.mnemonic == "bx" and len(instruction.operands) == 1:
            operand = instruction.operands[0]
            return operand.type == ARM_OP_REG and operand.reg == ARM_REG_LR
        if instruction.mnemonic == "pop":
            return any(
                operand.type == ARM_OP_REG and operand.reg == ARM_REG_PC
                for operand in instruction.operands
            )
        if instruction.mnemonic == "mov" and len(instruction.operands) >= 2:
            destination, source = instruction.operands[:2]
            return (
                destination.type == ARM_OP_REG
                and destination.reg == ARM_REG_PC
                and source.type == ARM_OP_REG
                and source.reg == ARM_REG_LR
            )
        return False

    @staticmethod
    def _target_mode(
        instruction: _CapstoneInstruction,
        mode: ExecutionMode,
        target: int | None,
    ) -> ExecutionMode | None:
        if target is None:
            return None
        if instruction.mnemonic == "blx":
            return ExecutionMode.THUMB if mode is ExecutionMode.ARM else ExecutionMode.ARM
        return mode
