from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from nds_disassembly_toolkit.analysis.model import FunctionCandidate, Symbol
from nds_disassembly_toolkit.analysis.project.model import LocationAnnotation
from nds_disassembly_toolkit.errors import InvestigationError

_U32_MAX = 0xFFFFFFFF


class InvestigationEvidenceKind(StrEnum):
    RUNTIME_DIFFERENTIAL = "runtime_differential"
    TEXT = "text"
    CONSTANT = "constant"
    ADDRESS_XREF = "address_xref"
    CALL_NEIGHBOR = "call_neighbor"


@dataclass(frozen=True)
class InvestigationRequest:
    text: str | None = None
    constants: tuple[int, ...] = ()
    addresses: tuple[int, ...] = ()
    component: str | None = None
    baseline_trace: Path | None = None
    target_trace: Path | None = None
    top: int = 25
    include_pseudo_c: bool = False

    def validate(self) -> None:
        if (self.baseline_trace is None) != (self.target_trace is None):
            raise InvestigationError(
                "baseline and target traces must be supplied together"
            )
        if not 1 <= self.top <= 250:
            raise InvestigationError("top must be between 1 and 250")
        if self.component == "":
            raise InvestigationError("component cannot be empty")
        if any(address < 0 or address > _U32_MAX for address in self.addresses):
            raise InvestigationError("investigation addresses must be unsigned 32-bit values")
        has_text = self.text is not None and bool(self.text.strip())
        has_runtime = self.baseline_trace is not None and self.target_trace is not None
        if not (has_text or self.constants or self.addresses or has_runtime):
            raise InvestigationError("at least one investigation selector is required")


@dataclass(frozen=True)
class InvestigationEvidence:
    kind: InvestigationEvidenceKind
    value: float
    weight: float
    contribution: float
    reasons: tuple[str, ...]
    addresses: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ValueError("investigation evidence value must be between 0 and 1")
        if self.weight < 0.0:
            raise ValueError("investigation evidence weight cannot be negative")


@dataclass(frozen=True)
class InvestigationCandidate:
    function: FunctionCandidate
    name: str
    score: float
    evidence: tuple[InvestigationEvidence, ...]
    symbols: tuple[Symbol, ...] = ()
    annotation: LocationAnnotation | None = None
    pseudo_c: str | None = None
    pseudo_c_error: str | None = None


@dataclass(frozen=True)
class InvestigationReport:
    request: InvestigationRequest
    candidates: tuple[InvestigationCandidate, ...]
