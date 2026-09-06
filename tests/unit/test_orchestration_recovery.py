from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration import EmulatorKind
from nds_disassembly_toolkit.analysis.orchestration.input import DSButton
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    ButtonStep,
    JournalStepState,
    ScenarioDefinition,
    ScenarioJournal,
    ScenarioJournalStep,
    resume_scenario,
    store_journal,
)
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeCheckpointError, RuntimeRecoveryError


@dataclass
class RecoveryContext:
    restores: list[str] = field(default_factory=list)
    buttons: list[DSButton] = field(default_factory=list)

    def restore_checkpoint(self, name: str) -> None:
        self.restores.append(name)

    def press_button(self, button: DSButton) -> None:
        self.buttons.append(button)


def test_started_step_restores_initial_checkpoint_and_replays(
    tmp_path: Path,
) -> None:
    definition = ScenarioDefinition(
        schema_version=1,
        name="resume",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint="baseline",
        steps=(
            ButtonStep("first", DSButton.A),
            ButtonStep("second", DSButton.B),
        ),
    )
    journal_path = tmp_path / "journal.json"
    store_journal(
        journal_path,
        ScenarioJournal(
            schema_version=1,
            scenario_name="resume",
            steps=(
                ScenarioJournalStep("first", JournalStepState.STARTED),
                ScenarioJournalStep("second", JournalStepState.PENDING),
            ),
        ),
    )
    context = RecoveryContext()

    result = resume_scenario(context, definition, journal_path=journal_path)

    assert result.status == "passed"
    assert context.restores == ["baseline"]
    assert context.buttons == [DSButton.A, DSButton.B]



def test_resume_wraps_checkpoint_restore_failure(tmp_path: Path) -> None:
    definition = ScenarioDefinition(
        schema_version=1,
        name="resume",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint="baseline",
        steps=(ButtonStep("first", DSButton.A),),
    )
    journal_path = tmp_path / "journal.json"
    store_journal(
        journal_path,
        ScenarioJournal(
            schema_version=1,
            scenario_name="resume",
            steps=(ScenarioJournalStep("first", JournalStepState.STARTED),),
        ),
    )

    class FailingRecoveryContext(RecoveryContext):
        def restore_checkpoint(self, name: str) -> None:
            raise RuntimeCheckpointError(f"cannot restore {name}")

    with pytest.raises(RuntimeRecoveryError, match="baseline"):
        resume_scenario(
            FailingRecoveryContext(),
            definition,
            journal_path=journal_path,
        )
