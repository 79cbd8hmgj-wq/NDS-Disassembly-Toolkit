from __future__ import annotations

import json
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration import EmulatorKind
from nds_disassembly_toolkit.analysis.orchestration.input import DSButton, DSPoint
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    AssertStep,
    ButtonSequenceStep,
    ButtonStep,
    CaptureSnapshotStep,
    CaptureTraceStep,
    CheckpointRestoreStep,
    CheckpointSaveStep,
    JournalStepState,
    MemoryWriteStep,
    ParameterReference,
    PredicateDefinition,
    ScenarioDefinition,
    ScenarioJournal,
    ScenarioJournalStep,
    TouchDragStep,
    TouchFlickStep,
    TouchTapStep,
    WaitStep,
    load_journal,
    load_scenario,
    store_journal,
    store_scenario,
)
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeScenarioError


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _scenario() -> dict[str, object]:
    return {
        "schema_version": 1,
        "name": "representative-trigger",
        "backend": "desmume",
        "cpu": "arm9",
        "required_capabilities": ["save_state", "touchscreen_input"],
        "checkpoint": "battle-ready",
        "steps": [
            {
                "type": "wait",
                "condition": {
                    "type": "memory_equals",
                    "address": "0x02100000",
                    "bytes": "00",
                },
                "timeout": 5.0,
            },
            {
                "type": "memory_write",
                "address": "0x02100020",
                "expected_before": "48",
                "replacement": "01",
            },
            {"id": "press-a", "type": "button", "button": "A"},
            {
                "type": "touch_flick",
                "start": [128, 170],
                "end": [128, 40],
                "duration_ms": 180,
            },
        ],
    }


def test_load_scenario_normalizes_ids_and_typed_values(tmp_path: Path) -> None:
    scenario = load_scenario(_write(tmp_path / "scenario.json", _scenario()))

    assert scenario.name == "representative-trigger"
    assert scenario.backend is EmulatorKind.DESMUME
    assert scenario.cpu is RuntimeCpu.ARM9
    assert scenario.required_capabilities == ("save_state", "touchscreen_input")
    assert [step.id for step in scenario.steps] == [
        "step-0000",
        "step-0001",
        "press-a",
        "step-0003",
    ]
    assert scenario.steps[1].replacement == b"\x01"
    assert scenario.steps[2].button is DSButton.A
    assert scenario.steps[3].start == DSPoint(128, 170)
    assert scenario.steps[3].end == DSPoint(128, 40)


def test_store_scenario_round_trips_a_loaded_scenario(tmp_path: Path) -> None:
    original = load_scenario(_write(tmp_path / "scenario.json", _scenario()))

    roundtrip_path = tmp_path / "roundtrip.json"
    store_scenario(roundtrip_path, original)
    reloaded = load_scenario(roundtrip_path)

    assert reloaded == original
    assert not roundtrip_path.with_suffix(".json.tmp").exists()


def test_store_scenario_round_trips_every_step_and_predicate_kind(tmp_path: Path) -> None:
    original = ScenarioDefinition(
        schema_version=1,
        name="comprehensive",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=("save_state", "window_input"),
        checkpoint="baseline",
        steps=(
            WaitStep(
                id="wait-pc-range",
                condition=PredicateDefinition(
                    type="all_of",
                    children=(
                        PredicateDefinition(type="pc_in_range", start=0x02000000, end=0x02000100),
                        PredicateDefinition(type="process_alive"),
                    ),
                ),
                timeout=5.0,
                poll_interval=0.1,
            ),
            ButtonStep(
                id="press-a",
                button=DSButton.A,
                precondition=PredicateDefinition(type="window_ready"),
                postcondition=PredicateDefinition(type="debugger_reachable"),
                timeout=3.0,
            ),
            ButtonSequenceStep(
                id="combo",
                buttons=(DSButton.A, DSButton.B, DSButton.START),
                timeout=2.0,
            ),
            TouchTapStep(id="tap", point=DSPoint(10, 20), timeout=1.0),
            TouchDragStep(
                id="drag", start=DSPoint(0, 0), end=DSPoint(50, 60), duration_ms=200, timeout=1.0
            ),
            TouchFlickStep(
                id="flick", start=DSPoint(5, 5), end=DSPoint(1, 1), duration_ms=80, timeout=1.0
            ),
            MemoryWriteStep(
                id="write",
                address=0x02100020,
                replacement=ParameterReference("replacement"),
                expected_before=b"\x48",
                verify_after=False,
                precondition=PredicateDefinition(
                    type="memory_masked_equals",
                    address=0x02100020,
                    expected=b"\x48",
                    mask=b"\xff",
                ),
            ),
            CaptureSnapshotStep(id="snap", label=ParameterReference("snapshot_label")),
            CaptureTraceStep(
                id="trace",
                output="trace.ndstrace",
                break_address=0x02012340,
                memory=((0x02000000, 4), (0x02100000, 8)),
            ),
            AssertStep(
                id="assert-register",
                condition=PredicateDefinition(
                    type="register_equals",
                    register="r0",
                    expected=ParameterReference("expected_r0"),
                ),
                timeout=4.0,
            ),
            CheckpointSaveStep(id="save", name="post-battle"),
            CheckpointRestoreStep(id="restore", name="post-battle"),
        ),
    )

    path = tmp_path / "comprehensive.json"
    store_scenario(path, original)
    reloaded = load_scenario(path)

    assert reloaded == original


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.__setitem__("schema_version", 2),
        lambda value: value["steps"].append({"type": "shell", "command": "rm -rf /"}),
        lambda value: value["steps"].append({"type": "button", "button": "A", "script": "x"}),
        lambda value: value["steps"].append({"type": "touch_tap", "point": [256, 0]}),
        lambda value: value["steps"].append(
            {"type": "memory_write", "address": "0x20", "replacement": "0xz1"}
        ),
        lambda value: value["steps"].append(
            {
                "type": "wait",
                "condition": {"type": "pc_equals", "address": "0x20"},
                "timeout": 0,
            }
        ),
    ],
)
def test_load_scenario_rejects_unsafe_or_invalid_shapes(
    tmp_path: Path,
    mutator,
) -> None:
    payload = _scenario()
    mutator(payload)
    with pytest.raises(RuntimeScenarioError):
        load_scenario(_write(tmp_path / "bad.json", payload))


def test_load_scenario_rejects_duplicate_explicit_step_ids(tmp_path: Path) -> None:
    payload = _scenario()
    payload["steps"] = [
        {"id": "same", "type": "button", "button": "A"},
        {"id": "same", "type": "button", "button": "B"},
    ]
    with pytest.raises(RuntimeScenarioError, match="duplicate"):
        load_scenario(_write(tmp_path / "duplicate.json", payload))


def test_journal_round_trip_preserves_started_and_completed_states(tmp_path: Path) -> None:
    path = tmp_path / "journal.json"
    journal = ScenarioJournal(
        schema_version=1,
        scenario_name="representative-trigger",
        steps=(
            ScenarioJournalStep("step-0000", JournalStepState.COMPLETED),
            ScenarioJournalStep("step-0001", JournalStepState.STARTED),
            ScenarioJournalStep("step-0002", JournalStepState.PENDING),
        ),
    )

    store_journal(path, journal)
    loaded = load_journal(path)

    assert loaded == journal
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["steps"][0]["state"] == "completed"
    assert raw["steps"][1]["state"] == "started"


def test_atomic_journal_failure_preserves_previous_valid_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "journal.json"
    original = ScenarioJournal(
        schema_version=1,
        scenario_name="scenario",
        steps=(ScenarioJournalStep("step-0000", JournalStepState.PENDING),),
    )
    replacement = ScenarioJournal(
        schema_version=1,
        scenario_name="scenario",
        steps=(ScenarioJournalStep("step-0000", JournalStepState.STARTED),),
    )
    store_journal(path, original)

    def fail_replace(source: Path, destination: Path) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(
        "nds_disassembly_toolkit.analysis.orchestration.scenario._replace_file",
        fail_replace,
    )

    with pytest.raises(OSError, match="replace failed"):
        store_journal(path, replacement)

    assert load_journal(path) == original
    assert not path.with_suffix(path.suffix + ".tmp").exists()



def test_load_scenario_parses_explicit_parameter_references(tmp_path: Path) -> None:
    payload = _scenario()
    payload["steps"] = [
        {
            "type": "memory_write",
            "address": "0x02100020",
            "expected_before": {"parameter": "before"},
            "replacement": {"parameter": "replacement"},
        },
        {
            "type": "capture_snapshot",
            "label": {"parameter": "snapshot_label"},
        },
        {
            "type": "capture_trace",
            "output": {"parameter": "trace_name"},
            "steps": 1,
        },
        {
            "type": "wait",
            "condition": {
                "type": "memory_equals",
                "address": "0x02100000",
                "bytes": {"parameter": "expected_memory"},
            },
            "timeout": 1.0,
        },
        {
            "type": "assert",
            "condition": {
                "type": "register_equals",
                "register": "r0",
                "value": {"parameter": "expected_r0"},
            },
        },
    ]

    scenario = load_scenario(_write(tmp_path / "parameterized.json", payload))

    assert scenario.steps[0].replacement == ParameterReference("replacement")
    assert scenario.steps[0].expected_before == ParameterReference("before")
    assert scenario.steps[1].label == ParameterReference("snapshot_label")
    assert scenario.steps[2].output == ParameterReference("trace_name")
    assert scenario.steps[3].condition.expected == ParameterReference("expected_memory")
    assert scenario.steps[4].condition.expected == ParameterReference("expected_r0")


def test_parameter_reference_rejects_arbitrary_object_shape(tmp_path: Path) -> None:
    payload = _scenario()
    payload["steps"] = [
        {
            "type": "memory_write",
            "address": "0x02100020",
            "replacement": {"parameter": "value", "script": "bad"},
        }
    ]

    with pytest.raises(RuntimeScenarioError):
        load_scenario(_write(tmp_path / "bad-parameter.json", payload))



def test_load_scenario_parses_explicit_typed_parameter_references(
    tmp_path: Path,
) -> None:
    payload = {
        "schema_version": 1,
        "name": "parameterized",
        "backend": "desmume",
        "cpu": "arm9",
        "checkpoint": "baseline",
        "steps": [
            {
                "type": "memory_write",
                "address": "0x02000020",
                "replacement": {"parameter": "write_bytes"},
                "expected_before": "00",
            },
            {
                "type": "capture_snapshot",
                "label": {"parameter": "snapshot_label"},
            },
            {
                "type": "capture_trace",
                "output": {"parameter": "trace_name"},
                "steps": 1,
            },
            {
                "type": "assert",
                "condition": {
                    "type": "memory_equals",
                    "address": "0x02000020",
                    "bytes": {"parameter": "expected_bytes"},
                },
            },
        ],
    }

    scenario = load_scenario(_write(tmp_path / "parameterized.json", payload))

    assert isinstance(scenario.steps[0], MemoryWriteStep)
    assert scenario.steps[0].replacement == ParameterReference("write_bytes")
    assert isinstance(scenario.steps[1], CaptureSnapshotStep)
    assert scenario.steps[1].label == ParameterReference("snapshot_label")
    assert isinstance(scenario.steps[2], CaptureTraceStep)
    assert scenario.steps[2].output == ParameterReference("trace_name")
    assert scenario.steps[3].condition.expected == ParameterReference("expected_bytes")
