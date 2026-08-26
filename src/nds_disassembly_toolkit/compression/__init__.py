from nds_disassembly_toolkit.compression.blz import (
    BlzFooter,
    compress_blz,
    decompress_blz,
    decompress_blz_in_place,
    is_blz,
    parse_blz_footer,
)
from nds_disassembly_toolkit.compression.lz10 import (
    compress_lz10,
    decompress_lz10,
    is_lz10,
    lz10_declared_size,
)

__all__ = [
    "BlzFooter",
    "compress_blz",
    "compress_lz10",
    "decompress_blz",
    "decompress_blz_in_place",
    "decompress_lz10",
    "is_blz",
    "is_lz10",
    "lz10_declared_size",
    "parse_blz_footer",
]
