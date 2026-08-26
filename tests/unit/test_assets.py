from __future__ import annotations

import json
from types import SimpleNamespace

from nds_disassembly_toolkit.assets import AssetInventory, detect_asset, inventory_assets
from nds_disassembly_toolkit.compression.lz10 import compress_lz10


def test_detects_signature_confirmed_nsbmd() -> None:
    record = detect_asset(7, "effect/example.nsbmd", b"BMD0" + b"\x00" * 12)

    assert record.detected_format == "NSBMD"
    assert record.extension_format == "NSBMD"
    assert record.evidence == "signature"
    assert record.compression == "raw"
    assert record.decoded_magic == "BMD0"
    assert record.extension_signature_match is True


def test_detects_lz10_wrapped_nsbtx() -> None:
    record = detect_asset(
        8,
        "effect/example.nsbtx",
        compress_lz10(b"BTX0" + b"\x00" * 20),
    )

    assert record.detected_format == "NSBTX"
    assert record.compression == "lz10"
    assert record.decoded_size == 24
    assert record.extension_signature_match is True


def test_localized_suffix_normalizes_to_base_format() -> None:
    record = detect_asset(9, "locale/model.nsbmd_d", b"BMD0" + b"\x00" * 4)

    assert record.extension == ".nsbmd_d"
    assert record.extension_format == "NSBMD"
    assert record.detected_format == "NSBMD"
    assert record.extension_signature_match is True


def test_ntft_and_ntfp_are_extension_evidence_only() -> None:
    tile = detect_asset(10, "tex/tile.ntft", b"\x01\x02\x03\x04")
    palette = detect_asset(11, "tex/palette.ntfp", b"\x05\x06\x07\x08")

    assert tile.detected_format == "NTFT"
    assert tile.evidence == "extension"
    assert tile.extension_signature_match is None
    assert palette.detected_format == "NTFP"
    assert palette.evidence == "extension"
    assert palette.extension_signature_match is None


def test_signed_extension_signature_mismatch_is_explicit() -> None:
    record = detect_asset(12, "bad/model.nsbmd", b"BTX0" + b"\x00" * 8)

    assert record.extension_format == "NSBMD"
    assert record.detected_format == "NSBTX"
    assert record.extension_signature_match is False


def test_unknown_payload_stays_unknown() -> None:
    record = detect_asset(13, "misc/file.bin", b"ABCD" + b"\x00" * 8)

    assert record.extension_format is None
    assert record.detected_format is None
    assert record.evidence == "unknown"
    assert record.extension_signature_match is None


def test_inventory_summary_supports_profile_free_inspection() -> None:
    records = (
        detect_asset(3, "b.ntfp", b"\x00" * 4),
        detect_asset(1, "a.nsbmd", b"BMD0" + b"\x00" * 4),
        detect_asset(2, "unknown.bin", b"ABCD"),
        detect_asset(4, "bad.nsbmd", b"BTX0" + b"\x00" * 4),
    )
    inventory = AssetInventory.from_records(
        profile_id=None,
        supported=None,
        scanned_files=4,
        records=records,
        include_unknown=False,
    )

    payload = inventory.to_dict()
    assert payload["profile_id"] is None
    assert payload["supported"] is None
    assert payload["counts"] == {
        "scanned_files": 4,
        "reported_files": 3,
        "recognized_assets": 3,
        "unknown_files": 1,
        "signed_mismatches": 1,
    }
    assert payload["formats"] == {"NSBMD": 1, "NSBTX": 1, "NTFP": 1}
    assert [item["file_id"] for item in payload["assets"]] == [1, 3, 4]
    assert json.loads(inventory.to_json()) == payload


def test_inventory_can_include_unknown_records() -> None:
    records = (
        detect_asset(1, "known.nsbmd", b"BMD0" + b"\x00" * 4),
        detect_asset(2, "unknown.bin", b"ABCD"),
    )
    inventory = AssetInventory.from_records(
        profile_id="sample_rev0",
        supported=True,
        scanned_files=2,
        records=records,
        include_unknown=True,
    )

    assert [item.file_id for item in inventory.assets] == [1, 2]


def test_inventory_assets_propagates_optional_inspection_metadata() -> None:
    class FakeFnt:
        def file_by_id(self) -> dict[int, object]:
            return {0: SimpleNamespace(path="model.nsbmd")}

    inspection = SimpleNamespace(
        fnt=FakeFnt(),
        fat=(SimpleNamespace(file_id=0, start=0, end=8),),
        profile_id=None,
        supported=None,
    )
    inventory = inventory_assets(b"BMD0" + b"\x00" * 4, inspection)

    assert inventory.profile_id is None
    assert inventory.supported is None
    assert inventory.recognized_assets == 1
