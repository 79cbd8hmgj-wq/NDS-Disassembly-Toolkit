from __future__ import annotations

from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.investigation import (
    InvestigationEvidence,
    InvestigationEvidenceKind,
    InvestigationRequest,
)
from nds_disassembly_toolkit.errors import InvestigationError


def test_investigation_request_accepts_static_and_runtime_selectors() -> None:
    request = InvestigationRequest(
        text="score",
        constants=(100, -1),
        addresses=(0x02001234,),
        component="arm9",
        baseline_trace=Path("idle.ndstrace"),
        target_trace=Path("attack.ndstrace"),
        top=10,
        include_pseudo_c=True,
    )

    request.validate()

    assert request.constants == (100, -1)
    assert request.addresses == (0x02001234,)
    assert request.top == 10


def test_investigation_request_requires_at_least_one_evidence_selector() -> None:
    with pytest.raises(InvestigationError, match="at least one investigation selector"):
        InvestigationRequest().validate()


@pytest.mark.parametrize(
    ("baseline", "target"),
    [
        (Path("baseline.ndstrace"), None),
        (None, Path("target.ndstrace")),
    ],
)
def test_investigation_request_requires_trace_pair(
    baseline: Path | None,
    target: Path | None,
) -> None:
    with pytest.raises(InvestigationError, match="baseline and target traces"):
        InvestigationRequest(
            baseline_trace=baseline,
            target_trace=target,
        ).validate()


@pytest.mark.parametrize("top", [0, -1, 251])
def test_investigation_request_bounds_top(top: int) -> None:
    with pytest.raises(InvestigationError, match="top must be between 1 and 250"):
        InvestigationRequest(text="x", top=top).validate()


def test_blank_text_does_not_count_as_selector() -> None:
    with pytest.raises(InvestigationError, match="at least one investigation selector"):
        InvestigationRequest(text="   ").validate()


def test_investigation_evidence_is_transparent_and_immutable() -> None:
    evidence = InvestigationEvidence(
        kind=InvestigationEvidenceKind.CONSTANT,
        value=1.0,
        weight=0.20,
        contribution=0.20,
        reasons=("constant 100 at 0x02000004",),
        addresses=(0x02000004,),
    )

    assert evidence.contribution == pytest.approx(0.20)
    assert evidence.addresses == (0x02000004,)
    with pytest.raises(AttributeError):
        evidence.value = 0.0  # type: ignore[misc]
