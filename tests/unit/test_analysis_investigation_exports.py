from nds_disassembly_toolkit import analysis


def test_investigation_api_is_exported_from_analysis_package() -> None:
    assert analysis.InvestigationRequest is not None
    assert analysis.InvestigationEvidence is not None
    assert analysis.InvestigationEvidenceKind is not None
    assert analysis.InvestigationCandidate is not None
    assert analysis.InvestigationReport is not None
    assert analysis.investigate_project is not None
