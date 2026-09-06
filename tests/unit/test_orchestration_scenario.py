from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration import EmulatorKind
from nds_disassembly_toolkit.analysis.orchestration.input import DSButton
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    ButtonStep,
    JournalStepState,
    PredicateDefinition,
    ScenarioDefinition,
    load_journal,
    run_scenario,
)
from nds_disassembly_toolkit.analysis.runtime import (
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.errors import RuntimeScenarioError


@dataclass
class FakeScenarioContext:
    pc: int = 0x02000100
    buttons: list[DSButton] = field(default_factory=list)

    def snapshot(self) -> RuntimeSnapshot:
        return RuntimeSnapshot(
            cpu=RuntimeCpu.ARM9,
            registers=RegisterSnapshot.from_mapping(
                {"pc": self.pc, "cpsr": 0x13}
            ),
            stop=RuntimeStop(StopReasonKind.UNKNOWN),
        )

    def press_button(self, button: DSButton) -> None:
        self.buttons.append(button)


def _definition(*steps: ButtonStep) -> ScenarioDefinition:
    return ScenarioDefinition(
        schema_version=1,
        name="state-aware-actions",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint=None,
        steps=steps,
    )


def test_false_precondition_prevents_button_action(tmp_path: Path) -> None:
    context = FakeScenarioContext()
    definition = _definition(
        ButtonStep(
            id="guarded",
            button=DSButton.A,
            precondition=PredicateDefinition("pc_equals", address=0xDEADBEEF),
            timeout=0.001,
        )
    )
    journal_path = tmp_path / "journal.json"

    with pytest.raises(RuntimeScenarioError):
        run_scenario(context, definition, journal_path=journal_path)

    assert context.buttons == []
    journal = load_journal(journal_path)
    assert journal.steps[0].state is JournalStepState.FAILED


def test_failed_postcondition_stops_later_steps(tmp_path: Path) -> None:
    context = FakeScenarioContext()
    definition = _definition(
        ButtonStep(
            id="first",
            button=DSButton.A,
            postcondition=PredicateDefinition("pc_equals", address=0xDEADBEEF),
            timeout=0.001,
        ),
        ButtonStep(id="second", button=DSButton.B),
    )
    journal_path = tmp_path / "journal.json"

    with pytest.raises(RuntimeScenarioError):
        run_scenario(context, definition, journal_path=journal_path)

    assert context.buttons == [DSButton.A]
    journal = load_journal(journal_path)
    assert journal.steps[0].state is JournalStepState.FAILED
    assert journal.steps[1].state is JournalStepState.PENDING



def test_failed_step_collects_managed_failure_bundle(tmp_path: Path) -> None:
    @dataclass
    class ManagedFailureContext(FakeScenarioContext):
        session_root: Path = tmp_path

    context = ManagedFailureContext()
    definition = _definition(
        ButtonStep(
            id="first",
            button=DSButton.A,
            postcondition=PredicateDefinition("pc_equals", address=0xDEADBEEF),
            timeout=0.001,
        )
    )

    with pytest.raises(RuntimeScenarioError):
        run_scenario(
            context,
            definition,
            journal_path=tmp_path / "journal.json",
        )

    failure = tmp_path / "failure" / "first" / "failure.json"
    assert failure.is_file()
    payload = __import__("json").loads(failure.read_text(encoding="utf-8"))
    assert payload["step_id"] == "first"
    assert payload["scenario_name"] == "state-aware-actions"
    assert payload["error_type"] == "RuntimeScenarioError"



def test_run_scenario_restores_initial_checkpoint_before_actions(
    tmp_path: Path,
) -> None:
    @dataclass
    class CheckpointContext(FakeScenarioContext):
        events: list[str] = field(default_factory=list)

        def restore_checkpoint(self, name: str) -> None:
            self.events.append(f"restore:{name}")

        def press_button(self, button: DSButton) -> None:
            self.events.append(f"button:{button.value}")

    context = CheckpointContext()
    definition = ScenarioDefinition(
        schema_version=1,
        name="initial-baseline",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint="baseline",
        steps=(ButtonStep(id="press", button=DSButton.A),),
    )

    result = run_scenario(
        context,
        definition,
        journal_path=tmp_path / "journal.json",
    )

    assert result.status == "passed"
    assert context.events == ["restore:baseline", "button:a"]


def test_run_scenario_checkpoint_restore_failure_prevents_first_step(
    tmp_path: Path,
) -> None:
    @dataclass
    class FailingCheckpointContext(FakeScenarioContext):
        actions: list[str] = field(default_factory=list)

        def restore_checkpoint(self, name: str) -> None:
            raise RuntimeCheckpointError(f"cannot restore {name}")

        def press_button(self, button: DSButton) -> None:
            self.actions.append(button.value)

    context = FailingCheckpointContext()
    definition = ScenarioDefinition(
        schema_version=1,
        name="initial-baseline",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint="baseline",
        steps=(ButtonStep(id="press", button=DSButton.A),),
    )

    with pytest.raises(RuntimeRecoveryError, match="baseline"):
        run_scenario(
            context,
            definition,
            journal_path=tmp_path / "journal.json",
        )

    assert context.actions == []
