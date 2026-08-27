from pathlib import Path

from nds_disassembly_toolkit.analysis.decoder import CapstoneArmDecoder
from nds_disassembly_toolkit.analysis.model import Component, ControlFlowKind, ExecutionMode


def test_decodes_arm_direct_call_target() -> None:
    component = Component(
        "arm9",
        Path("arm9.bin"),
        0x02000000,
        bytes.fromhex("000000EB"),
    )

    decoded = CapstoneArmDecoder().decode_one(component, 0x02000000, ExecutionMode.ARM)

    assert decoded is not None
    assert decoded.address == 0x02000000
    assert decoded.size == 4
    assert decoded.mode is ExecutionMode.ARM
    assert decoded.flow is ControlFlowKind.CALL
    assert decoded.target == 0x02000008
    assert decoded.target_mode is ExecutionMode.ARM
    assert decoded.conditional is False


def test_decodes_thumb_bx_lr_as_return() -> None:
    component = Component(
        "overlay",
        Path("overlay.bin"),
        0x02200000,
        bytes.fromhex("7047"),
    )

    decoded = CapstoneArmDecoder().decode_one(component, 0x02200000, ExecutionMode.THUMB)

    assert decoded is not None
    assert decoded.size == 2
    assert decoded.mode is ExecutionMode.THUMB
    assert decoded.flow is ControlFlowKind.RETURN
    assert decoded.target is None
    assert decoded.target_mode is None


def test_decodes_arm_blx_immediate_with_thumb_target_mode() -> None:
    component = Component(
        "arm9",
        Path("arm9.bin"),
        0x02000000,
        bytes.fromhex("000000FB"),
    )

    decoded = CapstoneArmDecoder().decode_one(component, 0x02000000, ExecutionMode.ARM)

    assert decoded is not None
    assert decoded.flow is ControlFlowKind.CALL
    assert decoded.target == 0x0200000A
    assert decoded.target_mode is ExecutionMode.THUMB


def test_decoder_returns_none_for_incomplete_instruction() -> None:
    component = Component("arm9", Path("arm9.bin"), 0x02000000, b"\x00\x00")

    assert CapstoneArmDecoder().decode_one(component, 0x02000000, ExecutionMode.ARM) is None
