from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration.evidence import collect_failure_bundle
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    JournalStepState,
    ScenarioJournal,
    ScenarioJournalStep,
)


@dataclass
class BrokenEvidenceContext:
    session_root: Path

    def snapshot(self) -> object:
        raise RuntimeError("secondary snapshot failure")


def test_failure_bundle_preserves_primary_error_when_snapshot_fails(
    tmp_path: Path,
) -> None:
    context = BrokenEvidenceContext(tmp_path)
    journal = ScenarioJournal(
        schema_version=1,
        scenario_name="failure",
        steps=(ScenarioJournalStep("step-0000", JournalStepState.FAILED),),
    )
    primary = RuntimeError("primary scenario failure")

    bundle = collect_failure_bundle(
        context,
        error=primary,
        step_id="step-0000",
        journal=journal,
    )

    payload = json.loads((bundle / "failure.json").read_text(encoding="utf-8"))
    assert payload["error"] == "primary scenario failure"
    assert payload["step_id"] == "step-0000"
    assert payload["secondary_errors"]
    assert (bundle / "journal.json").is_file()
