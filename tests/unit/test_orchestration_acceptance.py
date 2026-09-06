from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration import EmulatorKind
from nds_disassembly_toolkit.analysis.orchestration.acceptance import (
    AcceptanceCase,
    AcceptanceMatrix,
    load_matrix,
    run_acceptance_matrix,
)
from nds_disassembly_toolkit.analysis.orchestration.input import DSButton
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    ButtonStep,
    ScenarioDefinition,
)
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeRecoveryError, RuntimeScenarioError


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_load_matrix_preserves_case_order_and_parameters(tmp_path: Path) -> None:
    matrix = load_matrix(
        _write(
            tmp_path / "matrix.json",
            {
                "schema_version": 1,
                "scenario": "scenario.json",
                "cases": [
                    {"id": "case-a", "parameters": {"test_value": "01"}},
                    {"id": "case-b", "parameters": {"test_value": "15"}},
                ],
            },
        )
    )

    assert matrix.scenario == Path("scenario.json")
    assert [case.id for case in matrix.cases] == ["case-a", "case-b"]
    assert matrix.cases[0].parameters == {"test_value": "01"}


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 2, "scenario": "scenario.json", "cases": []},
        {"schema_version": 1, "cases": []},
        {
            "schema_version": 1,
            "scenario": "scenario.json",
            "cases": [
                {"id": "same", "parameters": {}},
                {"id": "same", "parameters": {}},
            ],
        },
        {
            "schema_version": 1,
            "scenario": "scenario.json",
            "cases": [{"id": "bad", "parameters": ["not", "an", "object"]}],
        },
    ],
)
def test_load_matrix_rejects_invalid_shapes(
    tmp_path: Path,
    payload: object,
) -> None:
    with pytest.raises(RuntimeScenarioError):
        load_matrix(_write(tmp_path / "bad.json", payload))


@dataclass
class MatrixFactory:
    root: Path
    restore_calls: list[str] = field(default_factory=list)
    run_count: int = 0

    def __call__(self, case: AcceptanceCase) -> MatrixContext:
        self.run_count += 1
        return MatrixContext(
            factory=self,
            session_root=self.root / f"session-{self.run_count}",
            fail_action=self.run_count == 1,
        )


@dataclass
class MatrixContext:
    factory: MatrixFactory
    session_root: Path
    fail_action: bool
    buttons: list[DSButton] = field(default_factory=list)

    def restore_checkpoint(self, name: str) -> None:
        self.factory.restore_calls.append(name)

    def press_button(self, button: DSButton) -> None:
        self.buttons.append(button)
        if self.fail_action:
            raise RuntimeScenarioError("synthetic first-case failure")


def _scenario() -> ScenarioDefinition:
    return ScenarioDefinition(
        schema_version=1,
        name="matrix-scenario",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint="baseline",
        steps=(ButtonStep("action", DSButton.A),),
    )


def test_each_case_restores_verified_baseline_and_continues_after_case_failure(
    tmp_path: Path,
) -> None:
    matrix = AcceptanceMatrix(
        schema_version=1,
        scenario=Path("scenario.json"),
        cases=(
            AcceptanceCase("first", {}),
            AcceptanceCase("second", {}),
        ),
    )
    factory = MatrixFactory(tmp_path)

    result = run_acceptance_matrix(factory, matrix, _scenario())

    assert factory.restore_calls == ["baseline", "baseline"]
    assert [case.status for case in result.cases] == ["failed", "passed"]
    assert result.status == "failed"


@dataclass
class RestoreFailureFactory:
    root: Path
    calls: int = 0
    restore_calls: list[str] = field(default_factory=list)

    def __call__(self, case: AcceptanceCase) -> RestoreFailureContext:
        self.calls += 1
        return RestoreFailureContext(
            factory=self,
            session_root=self.root / f"session-{self.calls}",
            fail_restore=self.calls == 2,
        )


@dataclass
class RestoreFailureContext:
    factory: RestoreFailureFactory
    session_root: Path
    fail_restore: bool

    def restore_checkpoint(self, name: str) -> None:
        self.factory.restore_calls.append(name)
        if self.fail_restore:
            raise RuntimeRecoveryError("baseline restore failed")

    def press_button(self, button: DSButton) -> None:
        del button


def test_baseline_restore_failure_aborts_remaining_cases(tmp_path: Path) -> None:
    matrix = AcceptanceMatrix(
        schema_version=1,
        scenario=Path("scenario.json"),
        cases=(
            AcceptanceCase("first", {}),
            AcceptanceCase("second", {}),
            AcceptanceCase("third", {}),
        ),
    )
    factory = RestoreFailureFactory(tmp_path)

    result = run_acceptance_matrix(factory, matrix, _scenario())

    assert factory.restore_calls == ["baseline", "baseline"]
    assert [case.id for case in result.cases] == ["first", "second"]
    assert [case.status for case in result.cases] == ["passed", "failed"]
    assert result.status == "aborted"
