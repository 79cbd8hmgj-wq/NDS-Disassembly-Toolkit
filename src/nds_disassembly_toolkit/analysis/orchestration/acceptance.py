from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.orchestration.model import MATRIX_SCHEMA_VERSION
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    ScenarioDefinition,
    run_scenario,
)
from nds_disassembly_toolkit.errors import RuntimeRecoveryError, RuntimeScenarioError


@dataclass(frozen=True, slots=True)
class AcceptanceCase:
    id: str
    parameters: Mapping[str, object]

    def __post_init__(self) -> None:
        if not self.id or Path(self.id).name != self.id or self.id in {".", ".."}:
            raise ValueError("acceptance case id must be one safe path component")


@dataclass(frozen=True, slots=True)
class AcceptanceMatrix:
    schema_version: int
    scenario: Path
    cases: tuple[AcceptanceCase, ...]

    def __post_init__(self) -> None:
        if self.schema_version != MATRIX_SCHEMA_VERSION:
            raise ValueError("unsupported acceptance matrix schema version")
        if self.scenario.is_absolute():
            raise ValueError("acceptance matrix scenario path must be relative")


@dataclass(frozen=True, slots=True)
class AcceptanceCaseResult:
    id: str
    status: str
    parameters: Mapping[str, object]
    completed_steps: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True)
class AcceptanceMatrixResult:
    status: str
    cases: tuple[AcceptanceCaseResult, ...]


class AcceptanceContext(Protocol):
    session_root: Path

    def restore_checkpoint(self, name: str) -> None: ...


AcceptanceContextFactory = Callable[[AcceptanceCase], AcceptanceContext]


def _require_object(value: object, *, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeScenarioError(f"{name} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise RuntimeScenarioError(f"{name} keys must be strings")
    return value


def _only_keys(
    payload: dict[str, object],
    allowed: set[str],
    *,
    name: str,
) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise RuntimeScenarioError(
            f"{name} contains unsupported keys: {', '.join(unknown)}"
        )


def load_matrix(path: Path) -> AcceptanceMatrix:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeScenarioError("acceptance matrix is missing or invalid JSON") from exc

    payload = _require_object(raw, name="matrix")
    _only_keys(payload, {"schema_version", "scenario", "cases"}, name="matrix")
    if payload.get("schema_version") != MATRIX_SCHEMA_VERSION:
        raise RuntimeScenarioError("unsupported acceptance matrix schema version")

    scenario_value = payload.get("scenario")
    if not isinstance(scenario_value, str) or not scenario_value:
        raise RuntimeScenarioError("matrix.scenario must be a non-empty string")
    scenario = Path(scenario_value)
    if scenario.is_absolute() or ".." in scenario.parts:
        raise RuntimeScenarioError("matrix.scenario must be a safe relative path")

    cases_value = payload.get("cases")
    if not isinstance(cases_value, list):
        raise RuntimeScenarioError("matrix.cases must be an array")

    cases: list[AcceptanceCase] = []
    ids: set[str] = set()
    for ordinal, raw_case in enumerate(cases_value):
        case_payload = _require_object(raw_case, name=f"cases[{ordinal}]")
        _only_keys(case_payload, {"id", "parameters"}, name=f"cases[{ordinal}]")
        case_id = case_payload.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise RuntimeScenarioError("acceptance case id must be a non-empty string")
        if Path(case_id).name != case_id or case_id in {".", ".."}:
            raise RuntimeScenarioError("acceptance case id must be one safe path component")
        if case_id in ids:
            raise RuntimeScenarioError("acceptance matrix contains duplicate case ids")
        ids.add(case_id)

        parameters_value = case_payload.get("parameters", {})
        if not isinstance(parameters_value, dict):
            raise RuntimeScenarioError("acceptance case parameters must be a JSON object")
        if any(not isinstance(key, str) for key in parameters_value):
            raise RuntimeScenarioError("acceptance case parameter names must be strings")
        cases.append(AcceptanceCase(case_id, dict(parameters_value)))

    return AcceptanceMatrix(
        schema_version=MATRIX_SCHEMA_VERSION,
        scenario=scenario,
        cases=tuple(cases),
    )


def run_acceptance_matrix(
    context_factory: AcceptanceContextFactory,
    matrix: AcceptanceMatrix,
    scenario: ScenarioDefinition,
) -> AcceptanceMatrixResult:
    if scenario.checkpoint is None:
        raise RuntimeRecoveryError(
            "acceptance matrix scenarios require a baseline checkpoint"
        )

    results: list[AcceptanceCaseResult] = []
    saw_case_failure = False

    for case in matrix.cases:
        context = context_factory(case)
        case_root = context.session_root / "cases" / case.id
        case_root.mkdir(parents=True, exist_ok=True)

        try:
            context.restore_checkpoint(scenario.checkpoint)
        except Exception as exc:
            results.append(
                AcceptanceCaseResult(
                    id=case.id,
                    status="failed",
                    parameters=dict(case.parameters),
                    error=str(exc),
                )
            )
            return AcceptanceMatrixResult(status="aborted", cases=tuple(results))

        try:
            scenario_result = run_scenario(
                context,
                scenario,
                journal_path=case_root / "journal.json",
            )
        except Exception as exc:
            saw_case_failure = True
            results.append(
                AcceptanceCaseResult(
                    id=case.id,
                    status="failed",
                    parameters=dict(case.parameters),
                    error=str(exc),
                )
            )
            continue

        results.append(
            AcceptanceCaseResult(
                id=case.id,
                status="passed",
                parameters=dict(case.parameters),
                completed_steps=scenario_result.completed_steps,
            )
        )

    return AcceptanceMatrixResult(
        status="failed" if saw_case_failure else "passed",
        cases=tuple(results),
    )
