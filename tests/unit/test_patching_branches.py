from __future__ import annotations

import struct

import pytest

from nds_disassembly_toolkit.errors import WorkspaceError
from nds_disassembly_toolkit.patching import (
    decode_arm_branch_target,
    encode_arm_branch,
    encode_thumb_branch,
)


def test_arm_branch_round_trips_forward_and_link_bit() -> None:
    source = 0x02000000
    target = 0x02000100

    instruction = encode_arm_branch(source, target, link=True)

    assert instruction & 0x01000000
    assert decode_arm_branch_target(source, instruction) == target


def test_arm_branch_rejects_unaligned_or_out_of_range_target() -> None:
    with pytest.raises(WorkspaceError, match="ARM aligned"):
        encode_arm_branch(0x02000000, 0x02000002)
    with pytest.raises(WorkspaceError, match="out of range"):
        encode_arm_branch(0x02000000, 0x06000000)


def test_thumb_short_branch_encodes_expected_halfword() -> None:
    encoded = encode_thumb_branch(0x02210000, 0x02210010, link=False)

    assert len(encoded) == 2
    assert struct.unpack("<H", encoded)[0] & 0xF800 == 0xE000


def test_thumb_link_branch_encodes_two_halfwords() -> None:
    encoded = encode_thumb_branch(0x02210000, 0x02211000, link=True)

    high, low = struct.unpack("<HH", encoded)
    assert high & 0xF800 == 0xF000
    assert low & 0xF800 == 0xF800


def test_thumb_branch_rejects_unaligned_and_out_of_range_targets() -> None:
    with pytest.raises(WorkspaceError, match="halfword aligned"):
        encode_thumb_branch(0x02210001, 0x02210010, link=False)
    with pytest.raises(WorkspaceError, match="outside"):
        encode_thumb_branch(0x02210000, 0x02212000, link=False)
