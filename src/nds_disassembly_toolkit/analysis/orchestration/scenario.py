from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import TypeAlias

from nds_disassembly_toolkit.analysis.orchestration.input import DSButton, DSPoint
from nds_disassembly_toolkit.analysis.orchestration.model import (
    JOURNAL_SCHEMA_VERSION,
    SCENARIO_SCHEMA_VERSION,
    EmulatorKind,
)
from nds_disassembly_toolkit.analysis.orchestration.predicates import (
    AllOf,
    AnyOf,
    DebuggerReachable,
    MemoryEquals,
    MemoryMaskedEquals,
    PcEquals,
    PcInRange,
    ProcessAlive,
    RegisterEquals,
    RuntimeMemoryWrite,
    RuntimePredicate,
    WindowReady,
    apply_guarded_write,
    wait_for_predicate,
)
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeRecoveryError, RuntimeScenarioError


class JournalStepState(StrEnum):
    PENDING = "pending"
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ParameterReference:
    name: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("parameter reference name must not be empty")


@dataclass(frozen=True, slots=True)
class PredicateDefinition:
    type: str
    address: int | None = None
    expected: bytes | int | ParameterReference | None = None
    mask: bytes | None = None
    register: str | None = None
    start: int | None = None
    end: int | None = None
    children: tuple[PredicateDefinition, ...] = ()


@dataclass(frozen=True, slots=True)
class WaitStep:
    id: str
    condition: PredicateDefinition
    timeout: float
    poll_interval: float = 0.05
    type: str = "wait"


@dataclass(frozen=True, slots=True)
class ButtonStep:
    id: str
    button: DSButton
    precondition: PredicateDefinition | None = None
    postcondition: PredicateDefinition | None = None
    timeout: float = 5.0
    type: str = "button"


@dataclass(frozen=True, slots=True)
class ButtonSequenceStep:
    id: str
    buttons: tuple[DSButton, ...]
    precondition: PredicateDefinition | None = None
    postcondition: PredicateDefinition | None = None
    timeout: float = 5.0
    type: str = "button_sequence"


@dataclass(frozen=True, slots=True)
class TouchTapStep:
    id: str
    point: DSPoint
    precondition: PredicateDefinition | None = None
    postcondition: PredicateDefinition | None = None
    timeout: float = 5.0
    type: str = "touch_tap"


@dataclass(frozen=True, slots=True)
class TouchDragStep:
    id: str
    start: DSPoint
    end: DSPoint
    duration_ms: int
    precondition: PredicateDefinition | None = None
    postcondition: PredicateDefinition | None = None
    timeout: float = 5.0
    type: str = "touch_drag"


@dataclass(frozen=True, slots=True)
class TouchFlickStep:
    id: str
    start: DSPoint
    end: DSPoint
    duration_ms: int
    precondition: PredicateDefinition | None = None
    postcondition: PredicateDefinition | None = None
    timeout: float = 5.0
    type: str = "touch_flick"


@dataclass(frozen=True, slots=True)
class MemoryWriteStep:
    id: str
    address: int
    replacement: bytes | ParameterReference
    expected_before: bytes | ParameterReference | None = None
    verify_after: bool = True
    precondition: PredicateDefinition | None = None
    postcondition: PredicateDefinition | None = None
    timeout: float = 5.0
    type: str = "memory_write"


@dataclass(frozen=True, slots=True)
class CaptureSnapshotStep:
    id: str
    label: str | ParameterReference | None = None
    type: str = "capture_snapshot"


@dataclass(frozen=True, slots=True)
class CaptureTraceStep:
    id: str
    output: str | ParameterReference | ParameterReference
    steps: int | None = None
    events: int | None = None
    break_address: int | None = None
    memory: tuple[tuple[int, int], ...] = ()
    type: str = "capture_trace"


@dataclass(frozen=True, slots=True)
class AssertStep:
    id: str
    condition: PredicateDefinition
    timeout: float = 5.0
    type: str = "assert"


@dataclass(frozen=True, slots=True)
class CheckpointSaveStep:
    id: str
    name: str
    type: str = "checkpoint_save"


@dataclass(frozen=True, slots=True)
class CheckpointRestoreStep:
    id: str
    name: str
    type: str = "checkpoint_restore"


ScenarioStep: TypeAlias = (
    WaitStep
    | ButtonStep
    | ButtonSequenceStep
    | TouchTapStep
    | TouchDragStep
    | TouchFlickStep
    | MemoryWriteStep
    | CaptureSnapshotStep
    | CaptureTraceStep
    | AssertStep
    | CheckpointSaveStep
    | CheckpointRestoreStep
)


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    schema_version: int
    name: str
    backend: EmulatorKind
    cpu: RuntimeCpu
    required_capabilities: tuple[str, ...]
    checkpoint: str | None
    steps: tuple[ScenarioStep, ...]


@dataclass(frozen=True, slots=True)
class ScenarioJournalStep:
    id: str
    state: JournalStepState
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ScenarioJournal:
    schema_version: int
    scenario_name: str
    steps: tuple[ScenarioJournalStep, ...]


_SUPPORTED_STEP_TYPES = frozenset(
    {
        "wait",
        "button",
        "button_sequence",
        "touch_tap",
        "touch_drag",
        "touch_flick",
        "memory_write",
        "capture_snapshot",
        "capture_trace",
        "assert",
        "checkpoint_save",
        "checkpoint_restore",
    }
)


def _require_object(value: object, *, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeScenarioError(f"{name} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise RuntimeScenarioError(f"{name} keys must be strings")
    return value


def _only_keys(
    payload: dict[str, object],
    allowed: set[str] | frozenset[str],
    *,
    name: str,
) -> None:
    unknown = sorted(set(payload) - set(allowed))
    if unknown:
        raise RuntimeScenarioError(
            f"{name} contains unsupported keys: {', '.join(unknown)}"
        )


def _required_string(payload: dict[str, object], key: str, *, name: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise RuntimeScenarioError(f"{name}.{key} must be a non-empty string")
    return value


def _optional_string(payload: dict[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise RuntimeScenarioError(f"{key} must be a non-empty string")
    return value


def _positive_float(value: object, *, name: str, default: float | None = None) -> float:
    if value is None and default is not None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeScenarioError(f"{name} must be a positive number")
    result = float(value)
    if result <= 0:
        raise RuntimeScenarioError(f"{name} must be positive")
    return result


def _positive_int(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RuntimeScenarioError(f"{name} must be a positive integer")
    return value


def _address(value: object, *, name: str = "address") -> int:
    if isinstance(value, bool):
        raise RuntimeScenarioError(f"{name} must be an integer or hexadecimal string")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise RuntimeScenarioError(f"{name} is not a valid address") from exc
    else:
        raise RuntimeScenarioError(f"{name} must be an integer or hexadecimal string")
    if not 0 <= result <= 0xFFFFFFFF:
        raise RuntimeScenarioError(f"{name} must fit the 32-bit address space")
    return result


def _hex_bytes(value: object, *, name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise RuntimeScenarioError(f"{name} must be a non-empty hexadecimal string")
    if len(value) % 2:
        raise RuntimeScenarioError(f"{name} must contain whole bytes")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeScenarioError(f"{name} is not valid hexadecimal bytes") from exc
    if not result:
        raise RuntimeScenarioError(f"{name} must not be empty")
    return result



def _parameter_reference(value: object, *, name: str) -> ParameterReference:
    payload = _require_object(value, name=name)
    _only_keys(payload, {"parameter"}, name=name)
    parameter = payload.get("parameter")
    if not isinstance(parameter, str) or not parameter:
        raise RuntimeScenarioError(
            f"{name}.parameter must be a non-empty string"
        )
    return ParameterReference(parameter)


def _hex_bytes_or_parameter(
    value: object,
    *,
    name: str,
) -> bytes | ParameterReference:
    if isinstance(value, dict):
        return _parameter_reference(value, name=name)
    return _hex_bytes(value, name=name)


def _address_or_parameter(
    value: object,
    *,
    name: str,
) -> int | ParameterReference:
    if isinstance(value, dict):
        return _parameter_reference(value, name=name)
    return _address(value, name=name)


def _required_string_or_parameter(
    payload: dict[str, object],
    key: str,
    *,
    name: str,
) -> str | ParameterReference:
    value = payload.get(key)
    if isinstance(value, dict):
        return _parameter_reference(value, name=f"{name}.{key}")
    return _required_string(payload, key, name=name)


def _optional_string_or_parameter(
    payload: dict[str, object],
    key: str,
) -> str | ParameterReference | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, dict):
        return _parameter_reference(value, name=key)
    if not isinstance(value, str) or not value:
        raise RuntimeScenarioError(f"{key} must be a non-empty string")
    return value


def _point(value: object, *, name: str) -> DSPoint:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(isinstance(item, bool) or not isinstance(item, int) for item in value)
    ):
        raise RuntimeScenarioError(f"{name} must be [x, y] integer coordinates")
    try:
        return DSPoint(value[0], value[1])
    except ValueError as exc:
        raise RuntimeScenarioError(f"{name} contains invalid DS touch coordinates") from exc


def _button(value: object, *, name: str = "button") -> DSButton:
    if not isinstance(value, str):
        raise RuntimeScenarioError(f"{name} must be a Nintendo DS button name")
    try:
        return DSButton(value.lower())
    except ValueError as exc:
        raise RuntimeScenarioError(f"{name} is not a supported Nintendo DS button") from exc


def _predicate(value: object, *, name: str = "condition") -> PredicateDefinition:
    payload = _require_object(value, name=name)
    kind = _required_string(payload, "type", name=name)

    if kind in {"process_alive", "debugger_reachable", "window_ready"}:
        _only_keys(payload, {"type"}, name=name)
        return PredicateDefinition(kind)

    if kind == "pc_equals":
        _only_keys(payload, {"type", "address"}, name=name)
        return PredicateDefinition(kind, address=_address(payload.get("address"), name="address"))

    if kind == "pc_in_range":
        _only_keys(payload, {"type", "start", "end"}, name=name)
        start = _address(payload.get("start"), name="start")
        end = _address(payload.get("end"), name="end")
        if end < start:
            raise RuntimeScenarioError("pc_in_range end must not precede start")
        return PredicateDefinition(kind, start=start, end=end)

    if kind == "register_equals":
        _only_keys(payload, {"type", "register", "value"}, name=name)
        register = _required_string(payload, "register", name=name)
        expected = _address_or_parameter(payload.get("value"), name="value")
        return PredicateDefinition(kind, register=register, expected=expected)

    if kind == "memory_equals":
        _only_keys(payload, {"type", "address", "bytes"}, name=name)
        return PredicateDefinition(
            kind,
            address=_address(payload.get("address")),
            expected=_hex_bytes_or_parameter(payload.get("bytes"), name="bytes"),
        )

    if kind == "memory_masked_equals":
        _only_keys(payload, {"type", "address", "bytes", "mask"}, name=name)
        expected_bytes = _hex_bytes_or_parameter(payload.get("bytes"), name="bytes")
        mask_bytes = _hex_bytes(payload.get("mask"), name="mask")
        if (
            isinstance(expected_bytes, bytes)
            and len(expected_bytes) != len(mask_bytes)
        ):
            raise RuntimeScenarioError("memory mask length must match expected bytes")
        return PredicateDefinition(
            kind,
            address=_address(payload.get("address")),
            expected=expected_bytes,
            mask=mask_bytes,
        )

    if kind in {"all_of", "any_of"}:
        _only_keys(payload, {"type", "conditions"}, name=name)
        conditions = payload.get("conditions")
        if not isinstance(conditions, list) or not conditions:
            raise RuntimeScenarioError(f"{kind}.conditions must be a non-empty array")
        return PredicateDefinition(
            kind,
            children=tuple(
                _predicate(item, name=f"{name}.conditions") for item in conditions
            ),
        )

    raise RuntimeScenarioError(f"unsupported predicate type: {kind}")


def _action_conditions(
    payload: dict[str, object],
) -> tuple[PredicateDefinition | None, PredicateDefinition | None, float]:
    precondition = (
        None
        if payload.get("precondition") is None
        else _predicate(payload["precondition"], name="precondition")
    )
    postcondition = (
        None
        if payload.get("postcondition") is None
        else _predicate(payload["postcondition"], name="postcondition")
    )
    timeout = _positive_float(payload.get("timeout"), name="timeout", default=5.0)
    return precondition, postcondition, timeout


def _parse_step(raw: object, ordinal: int) -> ScenarioStep:
    payload = _require_object(raw, name=f"steps[{ordinal}]")
    kind = _required_string(payload, "type", name=f"steps[{ordinal}]")
    if kind not in _SUPPORTED_STEP_TYPES:
        raise RuntimeScenarioError(f"unsupported scenario step type: {kind}")
    step_id = payload.get("id", f"step-{ordinal:04d}")
    if not isinstance(step_id, str) or not step_id:
        raise RuntimeScenarioError("scenario step id must be a non-empty string")

    common_action = {"id", "type", "precondition", "postcondition", "timeout"}

    if kind == "wait":
        _only_keys(payload, {"id", "type", "condition", "timeout", "poll_interval"}, name=step_id)
        return WaitStep(
            step_id,
            _predicate(payload.get("condition")),
            _positive_float(payload.get("timeout"), name="timeout"),
            _positive_float(
                payload.get("poll_interval"),
                name="poll_interval",
                default=0.05,
            ),
        )

    if kind == "button":
        _only_keys(payload, common_action | {"button"}, name=step_id)
        pre, post, timeout = _action_conditions(payload)
        return ButtonStep(step_id, _button(payload.get("button")), pre, post, timeout)

    if kind == "button_sequence":
        _only_keys(payload, common_action | {"buttons"}, name=step_id)
        raw_buttons = payload.get("buttons")
        if not isinstance(raw_buttons, list) or not raw_buttons:
            raise RuntimeScenarioError("button_sequence.buttons must be a non-empty array")
        pre, post, timeout = _action_conditions(payload)
        return ButtonSequenceStep(
            step_id,
            tuple(_button(item, name="buttons") for item in raw_buttons),
            pre,
            post,
            timeout,
        )

    if kind == "touch_tap":
        _only_keys(payload, common_action | {"point"}, name=step_id)
        pre, post, timeout = _action_conditions(payload)
        return TouchTapStep(step_id, _point(payload.get("point"), name="point"), pre, post, timeout)

    if kind in {"touch_drag", "touch_flick"}:
        _only_keys(
            payload,
            common_action | {"start", "end", "duration_ms"},
            name=step_id,
        )
        start = _point(payload.get("start"), name="start")
        end = _point(payload.get("end"), name="end")
        duration = _positive_int(payload.get("duration_ms"), name="duration_ms")
        pre, post, timeout = _action_conditions(payload)
        if kind == "touch_drag":
            return TouchDragStep(step_id, start, end, duration, pre, post, timeout)
        return TouchFlickStep(step_id, start, end, duration, pre, post, timeout)

    if kind == "memory_write":
        _only_keys(
            payload,
            common_action
            | {"address", "replacement", "expected_before", "verify_after"},
            name=step_id,
        )
        verify_after = payload.get("verify_after", True)
        if not isinstance(verify_after, bool):
            raise RuntimeScenarioError("verify_after must be boolean")
        expected_value = payload.get("expected_before")
        expected_before = (
            None
            if expected_value is None
            else _hex_bytes_or_parameter(expected_value, name="expected_before")
        )
        replacement = _hex_bytes_or_parameter(
            payload.get("replacement"),
            name="replacement",
        )
        if (
            isinstance(expected_before, bytes)
            and isinstance(replacement, bytes)
            and len(expected_before) != len(replacement)
        ):
            raise RuntimeScenarioError("expected_before must match replacement length")
        pre, post, timeout = _action_conditions(payload)
        return MemoryWriteStep(
            step_id,
            _address(payload.get("address")),
            replacement,
            expected_before,
            verify_after,
            pre,
            post,
            timeout,
        )

    if kind == "capture_snapshot":
        _only_keys(payload, {"id", "type", "label"}, name=step_id)
        return CaptureSnapshotStep(
            step_id,
            _optional_string_or_parameter(payload, "label"),
        )

    if kind == "capture_trace":
        _only_keys(
            payload,
            {"id", "type", "output", "steps", "events", "break", "memory"},
            name=step_id,
        )
        output = _required_string_or_parameter(
            payload,
            "output",
            name=step_id,
        )
        steps_value = payload.get("steps")
        events_value = payload.get("events")
        steps = None if steps_value is None else _positive_int(steps_value, name="steps")
        events = None if events_value is None else _positive_int(events_value, name="events")
        break_value = payload.get("break")
        break_address = None if break_value is None else _address(break_value, name="break")
        if sum(item is not None for item in (steps, events, break_address)) != 1:
            raise RuntimeScenarioError(
                "capture_trace requires exactly one of steps, events, or break"
            )
        memory_value = payload.get("memory", [])
        if not isinstance(memory_value, list):
            raise RuntimeScenarioError("capture_trace.memory must be an array")
        regions: list[tuple[int, int]] = []
        for item in memory_value:
            region = _require_object(item, name="capture_trace.memory")
            _only_keys(region, {"address", "length"}, name="capture_trace.memory")
            regions.append(
                (
                    _address(region.get("address")),
                    _positive_int(region.get("length"), name="length"),
                )
            )
        return CaptureTraceStep(
            step_id,
            output,
            steps=steps,
            events=events,
            break_address=break_address,
            memory=tuple(regions),
        )

    if kind == "assert":
        _only_keys(payload, {"id", "type", "condition", "timeout"}, name=step_id)
        return AssertStep(
            step_id,
            _predicate(payload.get("condition")),
            _positive_float(payload.get("timeout"), name="timeout", default=5.0),
        )

    if kind in {"checkpoint_save", "checkpoint_restore"}:
        _only_keys(payload, {"id", "type", "name"}, name=step_id)
        checkpoint_name = _required_string(payload, "name", name=step_id)
        if Path(checkpoint_name).name != checkpoint_name:
            raise RuntimeScenarioError("checkpoint step name must be a simple name")
        if kind == "checkpoint_save":
            return CheckpointSaveStep(step_id, checkpoint_name)
        return CheckpointRestoreStep(step_id, checkpoint_name)

    raise RuntimeScenarioError(f"unsupported scenario step type: {kind}")


def load_scenario(path: Path) -> ScenarioDefinition:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeScenarioError("scenario file is missing or invalid JSON") from exc
    payload = _require_object(raw, name="scenario")
    _only_keys(
        payload,
        {
            "schema_version",
            "name",
            "backend",
            "cpu",
            "required_capabilities",
            "checkpoint",
            "steps",
        },
        name="scenario",
    )
    if payload.get("schema_version") != SCENARIO_SCHEMA_VERSION:
        raise RuntimeScenarioError("unsupported scenario schema version")
    name = _required_string(payload, "name", name="scenario")
    try:
        backend = EmulatorKind(_required_string(payload, "backend", name="scenario"))
    except ValueError as exc:
        raise RuntimeScenarioError("unsupported scenario emulator backend") from exc
    try:
        cpu = RuntimeCpu(_required_string(payload, "cpu", name="scenario").lower())
    except ValueError as exc:
        raise RuntimeScenarioError("scenario CPU must be arm9 or arm7") from exc

    required = payload.get("required_capabilities", [])
    if (
        not isinstance(required, list)
        or any(not isinstance(item, str) or not item for item in required)
    ):
        raise RuntimeScenarioError("required_capabilities must be an array of strings")

    checkpoint = _optional_string(payload, "checkpoint")
    steps_raw = payload.get("steps")
    if not isinstance(steps_raw, list):
        raise RuntimeScenarioError("scenario.steps must be an array")
    steps = tuple(_parse_step(item, ordinal) for ordinal, item in enumerate(steps_raw))
    ids = [step.id for step in steps]
    if len(ids) != len(set(ids)):
        raise RuntimeScenarioError("scenario contains duplicate step ids")

    return ScenarioDefinition(
        schema_version=SCENARIO_SCHEMA_VERSION,
        name=name,
        backend=backend,
        cpu=cpu,
        required_capabilities=tuple(required),
        checkpoint=checkpoint,
        steps=steps,
    )


def _journal_payload(journal: ScenarioJournal) -> dict[str, object]:
    return {
        "schema_version": journal.schema_version,
        "scenario_name": journal.scenario_name,
        "steps": [
            {
                "id": step.id,
                "state": step.state.value,
                "error": step.error,
            }
            for step in journal.steps
        ],
    }


def _replace_file(source: Path, destination: Path) -> None:
    source.replace(destination)


def store_journal(path: Path, journal: ScenarioJournal) -> None:
    if journal.schema_version != JOURNAL_SCHEMA_VERSION:
        raise RuntimeScenarioError("unsupported scenario journal schema version")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    rendered = json.dumps(_journal_payload(journal), indent=2, sort_keys=True) + "\n"
    temporary.write_text(rendered, encoding="utf-8")
    try:
        _replace_file(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_journal(path: Path) -> ScenarioJournal:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeScenarioError("scenario journal is missing or invalid JSON") from exc
    payload = _require_object(raw, name="journal")
    _only_keys(payload, {"schema_version", "scenario_name", "steps"}, name="journal")
    if payload.get("schema_version") != JOURNAL_SCHEMA_VERSION:
        raise RuntimeScenarioError("unsupported scenario journal schema version")
    scenario_name = _required_string(payload, "scenario_name", name="journal")
    steps_raw = payload.get("steps")
    if not isinstance(steps_raw, list):
        raise RuntimeScenarioError("journal.steps must be an array")
    steps: list[ScenarioJournalStep] = []
    ids: set[str] = set()
    for ordinal, item in enumerate(steps_raw):
        step = _require_object(item, name=f"journal.steps[{ordinal}]")
        _only_keys(step, {"id", "state", "error"}, name=f"journal.steps[{ordinal}]")
        step_id = _required_string(step, "id", name=f"journal.steps[{ordinal}]")
        if step_id in ids:
            raise RuntimeScenarioError("journal contains duplicate step ids")
        ids.add(step_id)
        try:
            state = JournalStepState(
                _required_string(step, "state", name=f"journal.steps[{ordinal}]")
            )
        except ValueError as exc:
            raise RuntimeScenarioError("journal contains invalid step state") from exc
        error_value = step.get("error")
        if error_value is not None and not isinstance(error_value, str):
            raise RuntimeScenarioError("journal step error must be a string or null")
        steps.append(ScenarioJournalStep(step_id, state, error_value))
    return ScenarioJournal(
        schema_version=JOURNAL_SCHEMA_VERSION,
        scenario_name=scenario_name,
        steps=tuple(steps),
    )



@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario_name: str
    completed_steps: tuple[str, ...]
    status: str


def _runtime_predicate(definition: PredicateDefinition) -> RuntimePredicate:
    kind = definition.type
    if kind == "process_alive":
        return ProcessAlive()
    if kind == "debugger_reachable":
        return DebuggerReachable()
    if kind == "window_ready":
        return WindowReady()
    if kind == "pc_equals" and definition.address is not None:
        return PcEquals(definition.address)
    if (
        kind == "pc_in_range"
        and definition.start is not None
        and definition.end is not None
    ):
        return PcInRange(definition.start, definition.end)
    if (
        kind == "register_equals"
        and definition.register is not None
        and isinstance(definition.expected, int)
    ):
        return RegisterEquals(definition.register, definition.expected)
    if (
        kind == "memory_equals"
        and definition.address is not None
        and isinstance(definition.expected, bytes)
    ):
        return MemoryEquals(definition.address, definition.expected)
    if (
        kind == "memory_masked_equals"
        and definition.address is not None
        and isinstance(definition.expected, bytes)
        and definition.mask is not None
    ):
        return MemoryMaskedEquals(
            definition.address,
            expected=definition.expected,
            mask=definition.mask,
        )
    if kind == "all_of":
        return AllOf(tuple(_runtime_predicate(child) for child in definition.children))
    if kind == "any_of":
        return AnyOf(tuple(_runtime_predicate(child) for child in definition.children))
    raise RuntimeScenarioError(f"invalid predicate definition for execution: {kind}")


def _initial_journal(definition: ScenarioDefinition) -> ScenarioJournal:
    return ScenarioJournal(
        schema_version=JOURNAL_SCHEMA_VERSION,
        scenario_name=definition.name,
        steps=tuple(
            ScenarioJournalStep(step.id, JournalStepState.PENDING)
            for step in definition.steps
        ),
    )


def _set_journal_step(
    journal: ScenarioJournal,
    step_id: str,
    state: JournalStepState,
    *,
    error: str | None = None,
) -> ScenarioJournal:
    updated: list[ScenarioJournalStep] = []
    found = False
    for entry in journal.steps:
        if entry.id == step_id:
            updated.append(replace(entry, state=state, error=error))
            found = True
        else:
            updated.append(entry)
    if not found:
        raise RuntimeScenarioError(f"scenario journal has no step {step_id}")
    return replace(journal, steps=tuple(updated))


def _invoke_context(context: object, name: str, *args: object) -> object:
    method = getattr(context, name, None)
    if not callable(method):
        raise RuntimeScenarioError(f"scenario context does not provide {name}()")
    return method(*args)


def _wait_definition(
    context: object,
    definition: PredicateDefinition,
    *,
    timeout: float,
    poll_interval: float = 0.05,
) -> None:
    wait_for_predicate(
        _runtime_predicate(definition),
        context,
        timeout=timeout,
        poll_interval=poll_interval,
    )


def _execute_step(context: object, step: ScenarioStep) -> None:
    if isinstance(step, WaitStep):
        _wait_definition(
            context,
            step.condition,
            timeout=step.timeout,
            poll_interval=step.poll_interval,
        )
        return
    if isinstance(step, ButtonStep):
        _invoke_context(context, "press_button", step.button)
        return
    if isinstance(step, ButtonSequenceStep):
        for button in step.buttons:
            _invoke_context(context, "press_button", button)
        return
    if isinstance(step, TouchTapStep):
        _invoke_context(context, "touch_tap", step.point)
        return
    if isinstance(step, TouchDragStep):
        _invoke_context(
            context,
            "touch_drag",
            step.start,
            step.end,
            step.duration_ms / 1000.0,
        )
        return
    if isinstance(step, TouchFlickStep):
        _invoke_context(
            context,
            "touch_flick",
            step.start,
            step.end,
            step.duration_ms / 1000.0,
        )
        return
    if isinstance(step, MemoryWriteStep):
        if isinstance(step.replacement, ParameterReference) or isinstance(
            step.expected_before,
            ParameterReference,
        ):
            raise RuntimeScenarioError(
                "scenario contains unresolved memory-write parameter reference"
            )
        apply_guarded_write(
            context,  # type: ignore[arg-type]
            RuntimeMemoryWrite(
                address=step.address,
                replacement=step.replacement,
                expected_before=step.expected_before,
                verify_after=step.verify_after,
            ),
        )
        return
    if isinstance(step, CaptureSnapshotStep):
        if isinstance(step.label, ParameterReference):
            raise RuntimeScenarioError(
                "scenario contains unresolved snapshot-label parameter reference"
            )
        _invoke_context(context, "capture_snapshot", step.label)
        return
    if isinstance(step, CaptureTraceStep):
        if isinstance(step.output, ParameterReference):
            raise RuntimeScenarioError(
                "scenario contains unresolved trace-output parameter reference"
            )
        _invoke_context(context, "capture_trace", step)
        return
    if isinstance(step, AssertStep):
        _wait_definition(context, step.condition, timeout=step.timeout)
        return
    if isinstance(step, CheckpointSaveStep):
        _invoke_context(context, "save_checkpoint", step.name)
        return
    if isinstance(step, CheckpointRestoreStep):
        _invoke_context(context, "restore_checkpoint", step.name)
        return
    raise RuntimeScenarioError(f"unsupported scenario step at execution: {step!r}")


def _conditions_for_step(
    step: ScenarioStep,
) -> tuple[PredicateDefinition | None, PredicateDefinition | None, float]:
    if isinstance(
        step,
        (
            ButtonStep,
            ButtonSequenceStep,
            TouchTapStep,
            TouchDragStep,
            TouchFlickStep,
            MemoryWriteStep,
        ),
    ):
        return step.precondition, step.postcondition, step.timeout
    return None, None, 5.0


def _collect_failure_if_managed(
    context: object,
    *,
    error: BaseException,
    step_id: str,
    journal: ScenarioJournal,
) -> None:
    session_root = getattr(context, "session_root", None)
    if not isinstance(session_root, Path):
        return
    with suppress(Exception):
        from nds_disassembly_toolkit.analysis.orchestration.evidence import (
            collect_failure_bundle,
        )

        collect_failure_bundle(
            context,  # type: ignore[arg-type]
            error=error,
            step_id=step_id,
            journal=journal,
        )


def _run_journaled_steps(
    context: object,
    definition: ScenarioDefinition,
    *,
    journal_path: Path,
    journal: ScenarioJournal,
    start_index: int,
) -> ScenarioResult:
    completed = [
        entry.id
        for entry in journal.steps[:start_index]
        if entry.state is JournalStepState.COMPLETED
    ]

    for step in definition.steps[start_index:]:
        precondition, postcondition, timeout = _conditions_for_step(step)
        try:
            if precondition is not None:
                _wait_definition(context, precondition, timeout=timeout)

            journal = _set_journal_step(
                journal,
                step.id,
                JournalStepState.STARTED,
            )
            store_journal(journal_path, journal)

            _execute_step(context, step)

            if postcondition is not None:
                _wait_definition(context, postcondition, timeout=timeout)

            journal = _set_journal_step(
                journal,
                step.id,
                JournalStepState.COMPLETED,
            )
            store_journal(journal_path, journal)
            completed.append(step.id)
        except BaseException as exc:
            journal = _set_journal_step(
                journal,
                step.id,
                JournalStepState.FAILED,
                error=str(exc),
            )
            store_journal(journal_path, journal)
            _collect_failure_if_managed(
                context,
                error=exc,
                step_id=step.id,
                journal=journal,
            )
            if isinstance(exc, RuntimeScenarioError):
                raise
            raise RuntimeScenarioError(
                f"scenario step {step.id} failed: {exc}"
            ) from exc

    return ScenarioResult(
        scenario_name=definition.name,
        completed_steps=tuple(completed),
        status="passed",
    )


def run_scenario(
    context: object,
    definition: ScenarioDefinition,
    *,
    journal_path: Path,
) -> ScenarioResult:
    journal = _initial_journal(definition)
    store_journal(journal_path, journal)
    return _run_journaled_steps(
        context,
        definition,
        journal_path=journal_path,
        journal=journal,
        start_index=0,
    )


def _validate_resume_journal(
    definition: ScenarioDefinition,
    journal: ScenarioJournal,
) -> None:
    if journal.scenario_name != definition.name:
        raise RuntimeRecoveryError("scenario journal identity does not match scenario")
    expected_ids = tuple(step.id for step in definition.steps)
    actual_ids = tuple(step.id for step in journal.steps)
    if actual_ids != expected_ids:
        raise RuntimeRecoveryError("scenario journal step identity does not match scenario")


def _resume_anchor(
    definition: ScenarioDefinition,
    journal: ScenarioJournal,
) -> tuple[int, str | None]:
    first_incomplete = next(
        (
            index
            for index, entry in enumerate(journal.steps)
            if entry.state is not JournalStepState.COMPLETED
        ),
        len(journal.steps),
    )
    if first_incomplete == len(journal.steps):
        return first_incomplete, None

    for index in range(first_incomplete - 1, -1, -1):
        step = definition.steps[index]
        entry = journal.steps[index]
        if (
            entry.state is JournalStepState.COMPLETED
            and isinstance(step, CheckpointSaveStep)
        ):
            return index + 1, step.name

    if definition.checkpoint is not None:
        return 0, definition.checkpoint
    raise RuntimeRecoveryError(
        "interrupted scenario has no safe checkpoint anchor for recovery"
    )


def resume_scenario(
    context: object,
    definition: ScenarioDefinition,
    *,
    journal_path: Path,
) -> ScenarioResult:
    journal = load_journal(journal_path)
    _validate_resume_journal(definition, journal)
    start_index, checkpoint = _resume_anchor(definition, journal)
    if start_index == len(definition.steps):
        return ScenarioResult(
            scenario_name=definition.name,
            completed_steps=tuple(step.id for step in definition.steps),
            status="passed",
        )

    if checkpoint is None:
        raise RuntimeRecoveryError("recovery requires a checkpoint anchor")
    try:
        _invoke_context(context, "restore_checkpoint", checkpoint)
    except Exception as exc:
        raise RuntimeRecoveryError(
            f"failed to restore safe recovery checkpoint {checkpoint}"
        ) from exc

    reset_steps = tuple(
        entry
        if index < start_index
        else ScenarioJournalStep(entry.id, JournalStepState.PENDING)
        for index, entry in enumerate(journal.steps)
    )
    journal = replace(journal, steps=reset_steps)
    store_journal(journal_path, journal)
    return _run_journaled_steps(
        context,
        definition,
        journal_path=journal_path,
        journal=journal,
        start_index=start_index,
    )
