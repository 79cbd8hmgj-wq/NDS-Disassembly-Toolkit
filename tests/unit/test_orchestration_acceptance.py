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
    MemoryWriteStep,
    ParameterReference,
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



@dataclass
class ParameterFactory:
    root: Path
    contexts: list[ParameterContext] = field(default_factory=list)

    def __call__(self, case: AcceptanceCase) -> ParameterContext:
        context = ParameterContext(self.root / case.id)
        self.contexts.append(context)
        return context


@dataclass
class ParameterContext:
    session_root: Path
    memory: bytes = b"\x00"

    def restore_checkpoint(self, name: str) -> None:
        assert name == "baseline"
        self.memory = b"\x00"

    def read_memory(self, address: int, length: int) -> bytes:
        assert address == 0x02000020
        return self.memory[:length]

    def write_memory(self, address: int, data: bytes) -> None:
        assert address == 0x02000020
        self.memory = data


def test_case_parameters_resolve_typed_memory_bytes(tmp_path: Path) -> None:
    scenario = ScenarioDefinition(
        schema_version=1,
        name="parameterized",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint="baseline",
        steps=(
            MemoryWriteStep(
                id="write",
                address=0x02000020,
                replacement=ParameterReference("test_value"),
                expected_before=b"\x00",
            ),
        ),
    )
    matrix = AcceptanceMatrix(
        schema_version=1,
        scenario=Path("scenario.json"),
        cases=(
            AcceptanceCase("one", {"test_value": "01"}),
            AcceptanceCase("two", {"test_value": "15"}),
        ),
    )
    factory = ParameterFactory(tmp_path)

    result = run_acceptance_matrix(factory, matrix, scenario)

    assert result.status == "passed"
    assert [context.memory for context in factory.contexts] == [b"\x01", b"\x15"]


def test_unknown_parameter_reference_fails_before_case_execution(tmp_path: Path) -> None:
    scenario = ScenarioDefinition(
        schema_version=1,
        name="parameterized",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint="baseline",
        steps=(
            MemoryWriteStep(
                id="write",
                address=0x02000020,
                replacement=ParameterReference("missing"),
                expected_before=b"\x00",
            ),
        ),
    )
    matrix = AcceptanceMatrix(
        schema_version=1,
        scenario=Path("scenario.json"),
        cases=(AcceptanceCase("one", {"different": "01"}),),
    )
    factory = ParameterFactory(tmp_path)

    with pytest.raises(RuntimeScenarioError, match="missing"):
        run_acceptance_matrix(factory, matrix, scenario)

    assert factory.contexts == []



@dataclass
class ResumeFactory:
    root: Path
    fail_second: bool
    actions: list[str] = field(default_factory=list)
    restores: list[str] = field(default_factory=list)

    def __call__(self, case: AcceptanceCase) -> "ResumeContext":
        return ResumeContext(self, case.id, self.root)


@dataclass
class ResumeContext:
    factory: ResumeFactory
    case_id: str
    session_root: Path

    def restore_checkpoint(self, name: str) -> None:
        self.factory.restores.append(name)

    def press_button(self, button: DSButton) -> None:
        del button
        self.factory.actions.append(self.case_id)
        if self.factory.fail_second and self.case_id == "second":
            raise RuntimeScenarioError("synthetic interrupted case")


def _resume_matrix() -> AcceptanceMatrix:
    return AcceptanceMatrix(
        schema_version=1,
        scenario=Path("scenario.json"),
        cases=(
            AcceptanceCase("first", {}),
            AcceptanceCase("second", {}),
        ),
    )


def test_matrix_resume_reuses_passed_prefix_and_restarts_failed_case(
    tmp_path: Path,
) -> None:
    first = ResumeFactory(tmp_path, fail_second=True)
    initial = run_acceptance_matrix(first, _resume_matrix(), _scenario())
    assert initial.status == "failed"
    assert first.actions == ["first", "second"]

    resumed = ResumeFactory(tmp_path, fail_second=False)
    result = run_acceptance_matrix(resumed, _resume_matrix(), _scenario())

    assert result.status == "passed"
    assert resumed.actions == ["second"]
    assert resumed.restores == ["baseline"]
    assert [case.status for case in result.cases] == ["passed", "passed"]


def test_matrix_resume_rejects_identity_mismatch_before_action(
    tmp_path: Path,
) -> None:
    initial = ResumeFactory(tmp_path, fail_second=False)
    assert run_acceptance_matrix(initial, _resume_matrix(), _scenario()).status == "passed"

    changed = ScenarioDefinition(
        schema_version=1,
        name="changed-scenario",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint="baseline",
        steps=(ButtonStep("action", DSButton.A),),
    )
    resumed = ResumeFactory(tmp_path, fail_second=False)

    with pytest.raises(RuntimeRecoveryError, match="identity"):
        run_acceptance_matrix(resumed, _resume_matrix(), changed)

    assert resumed.actions == []
    assert resumed.restores == []
