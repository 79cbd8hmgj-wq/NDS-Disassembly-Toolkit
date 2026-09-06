from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.orchestration.model import MATRIX_SCHEMA_VERSION
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    AssertStep,
    ButtonSequenceStep,
    ButtonStep,
    CaptureSnapshotStep,
    CaptureTraceStep,
    MemoryWriteStep,
    ParameterReference,
    PredicateDefinition,
    ScenarioDefinition,
    TouchDragStep,
    TouchFlickStep,
    TouchTapStep,
    WaitStep,
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



def _parameter_bytes(
    value: bytes | ParameterReference,
    parameters: Mapping[str, object],
    *,
    field: str,
) -> bytes:
    if isinstance(value, bytes):
        return value
    if value.name not in parameters:
        raise RuntimeScenarioError(
            f"missing acceptance parameter: {value.name}"
        )
    raw = parameters[value.name]
    if isinstance(raw, bytes):
        if not raw:
            raise RuntimeScenarioError(
                f"acceptance parameter {value.name} for {field} must not be empty"
            )
        return raw
    if not isinstance(raw, str) or not raw or len(raw) % 2:
        raise RuntimeScenarioError(
            f"acceptance parameter {value.name} for {field} must be hexadecimal bytes"
        )
    try:
        resolved = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeScenarioError(
            f"acceptance parameter {value.name} for {field} must be hexadecimal bytes"
        ) from exc
    if not resolved:
        raise RuntimeScenarioError(
            f"acceptance parameter {value.name} for {field} must not be empty"
        )
    return resolved



def _parameter_string(
    value: str | ParameterReference,
    parameters: Mapping[str, object],
    *,
    field: str,
) -> str:
    if isinstance(value, str):
        return value
    if value.name not in parameters:
        raise RuntimeScenarioError(f"missing acceptance parameter: {value.name}")
    raw = parameters[value.name]
    if not isinstance(raw, str) or not raw:
        raise RuntimeScenarioError(
            f"acceptance parameter {value.name} for {field} must be a non-empty string"
        )
    return raw


def _parameter_int(
    value: int | ParameterReference,
    parameters: Mapping[str, object],
    *,
    field: str,
) -> int:
    if isinstance(value, int):
        return value
    if value.name not in parameters:
        raise RuntimeScenarioError(f"missing acceptance parameter: {value.name}")
    raw = parameters[value.name]
    if isinstance(raw, bool):
        raise RuntimeScenarioError(
            f"acceptance parameter {value.name} for {field} must be an integer"
        )
    if isinstance(raw, int):
        resolved = raw
    elif isinstance(raw, str):
        try:
            resolved = int(raw, 0)
        except ValueError as exc:
            raise RuntimeScenarioError(
                f"acceptance parameter {value.name} for {field} must be an integer"
            ) from exc
    else:
        raise RuntimeScenarioError(
            f"acceptance parameter {value.name} for {field} must be an integer"
        )
    if not 0 <= resolved <= 0xFFFFFFFF:
        raise RuntimeScenarioError(
            f"acceptance parameter {value.name} for {field} must fit 32 bits"
        )
    return resolved


def _resolve_predicate(
    predicate: PredicateDefinition | None,
    parameters: Mapping[str, object],
) -> PredicateDefinition | None:
    if predicate is None:
        return None
    expected = predicate.expected
    if isinstance(expected, ParameterReference):
        if predicate.type in {"memory_equals", "memory_masked_equals"}:
            expected = _parameter_bytes(expected, parameters, field="predicate expected")
        else:
            expected = _parameter_int(expected, parameters, field="predicate expected")
    children = tuple(
        resolved
        for child in predicate.children
        if (resolved := _resolve_predicate(child, parameters)) is not None
    )
    return replace(predicate, expected=expected, children=children)


def _resolve_case_scenario(
    scenario: ScenarioDefinition,
    parameters: Mapping[str, object],
) -> ScenarioDefinition:
    resolved_steps = []
    action_types = (
        ButtonStep,
        ButtonSequenceStep,
        TouchTapStep,
        TouchDragStep,
        TouchFlickStep,
    )
    for step in scenario.steps:
        if isinstance(step, MemoryWriteStep):
            replacement = _parameter_bytes(
                step.replacement,
                parameters,
                field="replacement",
            )
            expected_before = step.expected_before
            if isinstance(expected_before, ParameterReference):
                expected_before = _parameter_bytes(
                    expected_before,
                    parameters,
                    field="expected_before",
                )
            if expected_before is not None and len(expected_before) != len(replacement):
                raise RuntimeScenarioError(
                    "resolved expected_before length must match replacement length"
                )
            step = replace(
                step,
                replacement=replacement,
                expected_before=expected_before,
                precondition=_resolve_predicate(step.precondition, parameters),
                postcondition=_resolve_predicate(step.postcondition, parameters),
            )
        elif isinstance(step, action_types):
            step = replace(
                step,
                precondition=_resolve_predicate(step.precondition, parameters),
                postcondition=_resolve_predicate(step.postcondition, parameters),
            )
        elif isinstance(step, WaitStep):
            condition = _resolve_predicate(step.condition, parameters)
            if condition is None:
                raise RuntimeScenarioError("wait condition could not be resolved")
            step = replace(step, condition=condition)
        elif isinstance(step, AssertStep):
            condition = _resolve_predicate(step.condition, parameters)
            if condition is None:
                raise RuntimeScenarioError("assert condition could not be resolved")
            step = replace(step, condition=condition)
        elif isinstance(step, CaptureSnapshotStep):
            label = step.label
            if isinstance(label, ParameterReference):
                label = _parameter_string(label, parameters, field="snapshot label")
            step = replace(step, label=label)
        elif isinstance(step, CaptureTraceStep):
            output = _parameter_string(step.output, parameters, field="trace output")
            step = replace(step, output=output)
        resolved_steps.append(step)
    return replace(scenario, steps=tuple(resolved_steps))


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
        resolved_scenario = _resolve_case_scenario(scenario, case.parameters)
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
                resolved_scenario,
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
