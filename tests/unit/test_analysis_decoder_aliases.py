import struct

from nds_disassembly_toolkit.analysis.decoder import decode_instruction
from nds_disassembly_toolkit.analysis.model import InstructionSet, Register


def test_arm_frame_pointer_alias_normalizes_to_r11() -> None:
    decoded = decode_instruction(
        struct.pack("<I", 0xE1A0B00D),  # mov r11, sp
        address=0x02000000,
        instruction_set=InstructionSet.ARM,
    )

    assert decoded is not None
    assert decoded.semantics.operands[0].register is Register.R11
    assert Register.R11 in decoded.semantics.registers_written
