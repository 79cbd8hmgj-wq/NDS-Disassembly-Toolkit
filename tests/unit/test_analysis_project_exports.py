def test_analysis_project_api_is_exported() -> None:
    from nds_disassembly_toolkit.analysis import (
        AnalysisFreshness,
        AnalysisProject,
        AnalysisProjectMetadata,
        ComponentAnalysisBundle,
        ComponentAnalysisIdentity,
        LocationAnnotation,
    )

    assert AnalysisProject is not None
    assert AnalysisProjectMetadata is not None
    assert AnalysisFreshness.CURRENT.value == "current"
    assert ComponentAnalysisBundle is not None
    assert ComponentAnalysisIdentity is not None
    assert LocationAnnotation is not None
