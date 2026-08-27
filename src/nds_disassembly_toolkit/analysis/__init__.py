"""Generic binary-analysis primitives for Nintendo DS executable components."""

from nds_disassembly_toolkit.analysis.arm import (
    arm_function_starts,
    function_address_for_reference,
    nearest_function_start,
)
from nds_disassembly_toolkit.analysis.decoder import decode_instruction
from nds_disassembly_toolkit.analysis.functions import discover_functions
from nds_disassembly_toolkit.analysis.model import (
    Component,
    ControlFlowKind,
    DecodedInstruction,
    FunctionCandidate,
    FunctionDiscoveryResult,
    FunctionSeed,
    InstructionSet,
    NumericMatch,
    PointerReference,
    StringRecord,
    SymbolCandidate,
)
from nds_disassembly_toolkit.analysis.numeric import (
    cluster_numeric_matches,
    scan_scaled_byte_rows,
)
from nds_disassembly_toolkit.analysis.report import analyze_components, write_report
from nds_disassembly_toolkit.analysis.strings import (
    extract_ascii_strings,
    filter_strings,
    find_pointer_references,
)

__all__ = [
    "Component",
    "ControlFlowKind",
    "DecodedInstruction",
    "FunctionCandidate",
    "FunctionDiscoveryResult",
    "FunctionSeed",
    "InstructionSet",
    "NumericMatch",
    "PointerReference",
    "StringRecord",
    "SymbolCandidate",
    "analyze_components",
    "arm_function_starts",
    "cluster_numeric_matches",
    "decode_instruction",
    "discover_functions",
    "extract_ascii_strings",
    "filter_strings",
    "find_pointer_references",
    "function_address_for_reference",
    "nearest_function_start",
    "scan_scaled_byte_rows",
    "write_report",
]
