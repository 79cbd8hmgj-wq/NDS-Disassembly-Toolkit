from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Protocol, cast

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
    schema_version: int = MATRIX_SCHEMA_VERSION
    matrix_identity: str | None = None
    scenario_identity: str | None = None
    checkpoint_identity: str | None = None


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


def _identity_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {
            str(key): _identity_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_identity_value(item) for item in value]
    return value


def _identity_payload(value: object) -> str:
    normalized = _identity_value(
        asdict(cast(Any, value))
        if hasattr(value, "__dataclass_fields__")
        else value
    )
    rendered = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _result_payload(result: AcceptanceMatrixResult) -> dict[str, object]:
    return {
        "schema_version": result.schema_version,
        "matrix_identity": result.matrix_identity,
        "scenario_identity": result.scenario_identity,
        "checkpoint_identity": result.checkpoint_identity,
        "status": result.status,
        "cases": [
            {
                "id": case.id,
                "status": case.status,
                "parameters": dict(case.parameters),
                "completed_steps": list(case.completed_steps),
                "error": case.error,
            }
            for case in result.cases
        ],
    }


def _store_result(path: Path, result: AcceptanceMatrixResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    rendered = json.dumps(_result_payload(result), indent=2, sort_keys=True) + "\n"
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(path)


def _load_result(path: Path) -> AcceptanceMatrixResult:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeRecoveryError("acceptance result is missing or invalid JSON") from exc
    payload = _require_object(raw, name="acceptance result")
    _only_keys(
        payload,
        {
            "schema_version",
            "matrix_identity",
            "scenario_identity",
            "checkpoint_identity",
            "status",
            "cases",
        },
        name="acceptance result",
    )
    if payload.get("schema_version") != MATRIX_SCHEMA_VERSION:
        raise RuntimeRecoveryError("unsupported acceptance result schema version")
    cases_value = payload.get("cases")
    if not isinstance(cases_value, list):
        raise RuntimeRecoveryError("acceptance result cases must be an array")
    cases: list[AcceptanceCaseResult] = []
    for ordinal, raw_case in enumerate(cases_value):
        case_payload = _require_object(raw_case, name=f"acceptance result cases[{ordinal}]")
        _only_keys(
            case_payload,
            {"id", "status", "parameters", "completed_steps", "error"},
            name=f"acceptance result cases[{ordinal}]",
        )
        case_id = case_payload.get("id")
        status = case_payload.get("status")
        parameters = case_payload.get("parameters")
        completed = case_payload.get("completed_steps")
        error = case_payload.get("error")
        if not isinstance(case_id, str) or not case_id:
            raise RuntimeRecoveryError("acceptance result case id is invalid")
        if status not in {"passed", "failed"}:
            raise RuntimeRecoveryError("acceptance result case status is invalid")
        if not isinstance(parameters, dict):
            raise RuntimeRecoveryError("acceptance result parameters must be an object")
        if not isinstance(completed, list) or any(
            not isinstance(item, str) for item in completed
        ):
            raise RuntimeRecoveryError("acceptance result completed_steps is invalid")
        if error is not None and not isinstance(error, str):
            raise RuntimeRecoveryError("acceptance result error must be a string or null")
        cases.append(
            AcceptanceCaseResult(
                id=case_id,
                status=status,
                parameters=dict(parameters),
                completed_steps=tuple(completed),
                error=error,
            )
        )
    status_value = payload.get("status")
    if status_value not in {"passed", "failed", "aborted"}:
        raise RuntimeRecoveryError("acceptance result status is invalid")
    def _optional_identity(name: str) -> str | None:
        value = payload.get(name)
        if value is None:
            return None
        if not isinstance(value, str) or len(value) != 64:
            raise RuntimeRecoveryError(f"acceptance result {name} is invalid")
        return value
    return AcceptanceMatrixResult(
        status=status_value,
        cases=tuple(cases),
        matrix_identity=_optional_identity("matrix_identity"),
        scenario_identity=_optional_identity("scenario_identity"),
        checkpoint_identity=_optional_identity("checkpoint_identity"),
    )


def _result_with_identities(
    *,
    status: str,
    cases: tuple[AcceptanceCaseResult, ...],
    matrix_identity: str,
    scenario_identity: str,
    checkpoint_identity: str,
) -> AcceptanceMatrixResult:
    return AcceptanceMatrixResult(
        status=status,
        cases=cases,
        matrix_identity=matrix_identity,
        scenario_identity=scenario_identity,
        checkpoint_identity=checkpoint_identity,
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

    matrix_identity = _identity_payload(matrix)
    scenario_identity = _identity_payload(scenario)
    checkpoint_identity = hashlib.sha256(
        scenario.checkpoint.encode("utf-8")
    ).hexdigest()

    resolved_cases = {
        case.id: _resolve_case_scenario(scenario, case.parameters)
        for case in matrix.cases
    }


    results: list[AcceptanceCaseResult] = []
    saw_case_failure = False
    result_path: Path | None = None
    reusable: dict[str, AcceptanceCaseResult] = {}
    reuse_open = True

    for case in matrix.cases:
        context = context_factory(case)
        if result_path is None:
            result_path = context.session_root / "matrix-result.json"
            if result_path.exists():
                prior = _load_result(result_path)
                if (
                    prior.matrix_identity != matrix_identity
                    or prior.scenario_identity != scenario_identity
                    or prior.checkpoint_identity != checkpoint_identity
                ):
                    raise RuntimeRecoveryError(
                        "acceptance result identity does not match matrix/scenario/checkpoint"
                    )
                for prior_case in prior.cases:
                    if not reuse_open or prior_case.status != "passed":
                        reuse_open = False
                        continue
                    reusable[prior_case.id] = prior_case

        reusable_case = reusable.get(case.id)
        if reusable_case is not None:
            results.append(reusable_case)
            continue

        resolved_scenario = resolved_cases[case.id]
        case_root = context.session_root / "cases" / case.id
        case_root.mkdir(parents=True, exist_ok=True)

        try:
            scenario_result = run_scenario(
                context,
                resolved_scenario,
                journal_path=case_root / "journal.json",
            )
        except RuntimeRecoveryError as exc:
            results.append(
                AcceptanceCaseResult(
                    id=case.id,
                    status="failed",
                    parameters=dict(case.parameters),
                    error=str(exc),
                )
            )
            result = _result_with_identities(
                status="aborted",
                cases=tuple(results),
                matrix_identity=matrix_identity,
                scenario_identity=scenario_identity,
                checkpoint_identity=checkpoint_identity,
            )
            if result_path is not None:
                _store_result(result_path, result)
            return result
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
        else:
            results.append(
                AcceptanceCaseResult(
                    id=case.id,
                    status="passed",
                    parameters=dict(case.parameters),
                    completed_steps=scenario_result.completed_steps,
                )
            )

        if result_path is not None:
            _store_result(
                result_path,
                _result_with_identities(
                    status="failed" if saw_case_failure else "passed",
                    cases=tuple(results),
                    matrix_identity=matrix_identity,
                    scenario_identity=scenario_identity,
                    checkpoint_identity=checkpoint_identity,
                ),
            )

    result = _result_with_identities(
        status="failed" if saw_case_failure else "passed",
        cases=tuple(results),
        matrix_identity=matrix_identity,
        scenario_identity=scenario_identity,
        checkpoint_identity=checkpoint_identity,
    )
    if result_path is not None:
        _store_result(result_path, result)
    return result
