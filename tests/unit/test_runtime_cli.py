from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import nds_disassembly_toolkit.analysis.runtime_cli as runtime_cli
from nds_disassembly_toolkit.analysis.orchestration import (
    DSButton,
    DSPoint,
    RuntimeLifecycleState,
    RuntimeSessionRecord,
    ScreenLayoutProfile,
    ScreenViewport,
    WindowGeometry,
)
from nds_disassembly_toolkit.analysis.orchestration.x11 import X11DisplayLease
from nds_disassembly_toolkit.analysis.runtime import (
    BreakpointKind,
    RegisterSnapshot,
    RuntimeComponentLocation,
    RuntimeCpu,
    RuntimeLocation,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.rsp import RSPCapabilities
from nds_disassembly_toolkit.cli import build_parser, main
from nds_disassembly_toolkit.errors import (
    RuntimeConnectionError,
    RuntimeRecoveryError,
    RuntimeScenarioError,
)


def _snapshot(
    pc: int = 0x02000010,
    *,
    stop_kind: StopReasonKind = StopReasonKind.BREAKPOINT,
) -> RuntimeSnapshot:
    return RuntimeSnapshot(
        cpu=RuntimeCpu.ARM9,
        registers=RegisterSnapshot.from_mapping(
            {
                "r0": 1,
                "pc": pc,
                "cpsr": 0x13,
            }
        ),
        stop=RuntimeStop(stop_kind, signal=5, address=pc, raw="T05"),
    )


class _FakeSession:
    def __init__(self, snapshots: list[RuntimeSnapshot] | None = None) -> None:
        self.capabilities = RSPCapabilities(
            features=(("PacketSize", "400"), ("QStartNoAckMode", True)),
            packet_size=0x400,
        )
        self.events: list[object] = []
        self.connect_kwargs: dict[str, object] = {}
        self._snapshots = list(snapshots or [_snapshot()])

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.detach()

    def detach(self) -> None:
        self.events.append("detach")

    def snapshot(self) -> RuntimeSnapshot:
        self.events.append("snapshot")
        return self._snapshots[0]

    def read_memory(self, address: int, length: int) -> bytes:
        self.events.append(("read-memory", address, length))
        return b"\x00\xab\xff"[:length]

    def run_until_breakpoint(self, address: int, *, length: int = 4) -> RuntimeSnapshot:
        self.events.append(("break", address, length))
        return self._snapshots[0]

    def run_until_watchpoint(
        self,
        kind: BreakpointKind,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        self.events.append(("watch", kind, address, length))
        return self._snapshots[0]

    def step(self) -> RuntimeSnapshot:
        index = sum(event == "step" for event in self.events)
        self.events.append("step")
        return self._snapshots[index]


def _install_fake_session(monkeypatch: pytest.MonkeyPatch, session: _FakeSession) -> None:
    class _Factory:
        @classmethod
        def connect(cls, **kwargs: object) -> _FakeSession:
            session.connect_kwargs = dict(kwargs)
            return session

    monkeypatch.setattr(runtime_cli, "MelonDSSession", _Factory, raising=False)


def _json_text(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


@pytest.mark.parametrize(
    ("argv", "runtime_command"),
    [
        (["runtime", "probe", "--cpu", "arm9"], "probe"),
        (
            [
                "runtime",
                "snapshot",
                "--cpu",
                "arm7",
                "--host",
                "127.0.0.1",
                "--port",
                "3334",
                "--project",
                "game.ndsre",
            ],
            "snapshot",
        ),
        (
            [
                "runtime",
                "read-memory",
                "--cpu",
                "arm9",
                "0x02000000",
                "0x100",
            ],
            "read-memory",
        ),
        (
            [
                "runtime",
                "run-until",
                "--cpu",
                "arm9",
                "--break",
                "0x02012340",
            ],
            "run-until",
        ),
        (
            [
                "runtime",
                "run-until",
                "--cpu",
                "arm9",
                "--watch-write",
                "0x02100000",
                "--length",
                "4",
            ],
            "run-until",
        ),
        (["runtime", "step", "--cpu", "arm9", "--count", "4"], "step"),
    ],
)
def test_runtime_parser_accepts_phase_7h1_commands(
    argv: list[str],
    runtime_command: str,
) -> None:
    arguments = build_parser().parse_args(argv)
    assert arguments.command == "runtime"
    assert arguments.runtime_command == runtime_command


def test_runtime_parser_requires_cpu() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["runtime", "probe"])
    assert exc_info.value.code == 2


def test_runtime_run_until_rejects_conflicting_stop_conditions() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(
            [
                "runtime",
                "run-until",
                "--cpu",
                "arm9",
                "--break",
                "0x02000000",
                "--watch-write",
                "0x02100000",
            ]
        )
    assert exc_info.value.code == 2


@pytest.mark.parametrize(
    "argv",
    [
        ["runtime", "read-memory", "--cpu", "arm9", "0x02000000", "0"],
        ["runtime", "run-until", "--cpu", "arm9", "--break", "0x02000000", "--length", "0"],
        ["runtime", "step", "--cpu", "arm9", "--count", "0"],
        ["runtime", "step", "--cpu", "arm9", "--count", "257"],
    ],
)
def test_runtime_parser_rejects_unsafe_bounds(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(argv)
    assert exc_info.value.code == 2


def test_runtime_probe_reports_capabilities_without_target_execution(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = _FakeSession()
    _install_fake_session(monkeypatch, session)
    arguments = build_parser().parse_args(["runtime", "probe", "--cpu", "arm9"])

    assert runtime_cli.run_runtime_command(arguments) == 0

    assert session.connect_kwargs == {
        "cpu": RuntimeCpu.ARM9,
        "host": "127.0.0.1",
        "port": None,
        "timeout": 5.0,
    }
    assert session.events == ["detach"]
    assert capsys.readouterr().out == _json_text(
        {
            "capabilities": {
                "features": [
                    {"name": "PacketSize", "value": "400"},
                    {"name": "QStartNoAckMode", "value": True},
                ],
                "packet_size": "0x00000400",
            },
            "cpu": "arm9",
            "host": "127.0.0.1",
            "port": 3333,
        }
    )


def test_runtime_snapshot_json_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = _FakeSession()
    _install_fake_session(monkeypatch, session)
    arguments = build_parser().parse_args(["runtime", "snapshot", "--cpu", "arm9"])

    assert runtime_cli.run_runtime_command(arguments) == 0

    assert session.events == ["snapshot", "detach"]
    assert capsys.readouterr().out == _json_text(
        {
            "correlation": None,
            "cpu": "arm9",
            "cpsr": "0x00000013",
            "instruction_set": "arm",
            "pc": "0x02000010",
            "registers": [
                {"name": "r0", "value": "0x00000001"},
                {"name": "pc", "value": "0x02000010"},
                {"name": "cpsr", "value": "0x00000013"},
            ],
            "stop": {
                "address": "0x02000010",
                "kind": "breakpoint",
                "raw": "T05",
                "signal": 5,
            },
        }
    )


def test_runtime_read_memory_writes_atomic_deterministic_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = _FakeSession()
    _install_fake_session(monkeypatch, session)
    output = tmp_path / "memory.json"
    arguments = build_parser().parse_args(
        [
            "runtime",
            "read-memory",
            "--cpu",
            "arm9",
            "0x02000000",
            "3",
            "--output",
            str(output),
        ]
    )

    assert runtime_cli.run_runtime_command(arguments) == 0

    assert session.events == [("read-memory", 0x02000000, 3), "detach"]
    assert capsys.readouterr().out == ""
    assert output.read_text(encoding="utf-8") == _json_text(
        {
            "address": "0x02000000",
            "cpu": "arm9",
            "data": "00abff",
            "length": "0x00000003",
        }
    )
    assert not output.with_suffix(".json.tmp").exists()


def test_runtime_run_until_delegates_watchpoint_semantics(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = _FakeSession()
    _install_fake_session(monkeypatch, session)
    arguments = build_parser().parse_args(
        [
            "runtime",
            "run-until",
            "--cpu",
            "arm9",
            "--watch-write",
            "0x02100000",
            "--length",
            "4",
        ]
    )

    assert runtime_cli.run_runtime_command(arguments) == 0

    assert session.events == [
        ("watch", BreakpointKind.WRITE, 0x02100000, 4),
        "detach",
    ]
    payload = json.loads(capsys.readouterr().out)
    assert payload["condition"] == {
        "address": "0x02100000",
        "kind": "write",
        "length": "0x00000004",
    }
    assert payload["snapshot"]["pc"] == "0x02000010"


def test_runtime_step_returns_final_snapshot_and_ordered_stop_pcs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = _FakeSession(
        [
            _snapshot(0x02000012, stop_kind=StopReasonKind.STEP),
            _snapshot(0x02000014, stop_kind=StopReasonKind.STEP),
        ]
    )
    _install_fake_session(monkeypatch, session)
    arguments = build_parser().parse_args(
        ["runtime", "step", "--cpu", "arm9", "--count", "2"]
    )

    assert runtime_cli.run_runtime_command(arguments) == 0

    assert session.events == ["step", "step", "detach"]
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 2
    assert payload["stop_pcs"] == ["0x02000012", "0x02000014"]
    assert payload["final_snapshot"]["pc"] == "0x02000014"


def test_runtime_project_correlation_opens_project_read_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = _FakeSession()
    _install_fake_session(monkeypatch, session)
    project = object()
    open_calls: list[tuple[Path, bool]] = []

    class _ProjectContext:
        def __enter__(self) -> object:
            return project

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            return None

    class _AnalysisProject:
        @classmethod
        def open(cls, path: Path, *, read_only: bool = False) -> _ProjectContext:
            open_calls.append((path, read_only))
            return _ProjectContext()

    def _correlate(candidate_project: object, snapshot: RuntimeSnapshot) -> RuntimeLocation:
        assert candidate_project is project
        return RuntimeLocation(
            pc=snapshot.pc,
            instruction_set=snapshot.instruction_set,
            candidates=(RuntimeComponentLocation(component="arm9"),),
        )

    monkeypatch.setattr(runtime_cli, "AnalysisProject", _AnalysisProject, raising=False)
    monkeypatch.setattr(runtime_cli, "correlate_snapshot", _correlate, raising=False)
    arguments = build_parser().parse_args(
        [
            "runtime",
            "snapshot",
            "--cpu",
            "arm9",
            "--project",
            "game.ndsre",
        ]
    )

    assert runtime_cli.run_runtime_command(arguments) == 0

    assert open_calls == [(Path("game.ndsre"), True)]
    payload = json.loads(capsys.readouterr().out)
    assert payload["correlation"] == {
        "candidates": [
            {
                "annotation": None,
                "component": "arm9",
                "function": None,
                "symbols": [],
            }
        ],
        "instruction_set": "arm",
        "pc": "0x02000010",
    }


def test_runtime_errors_use_existing_top_level_toolkit_mapping(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _FailingFactory:
        @classmethod
        def connect(cls, **kwargs: Any) -> None:
            raise RuntimeConnectionError("runtime peer unavailable")

    monkeypatch.setattr(runtime_cli, "MelonDSSession", _FailingFactory, raising=False)

    assert main(["runtime", "probe", "--cpu", "arm9"]) == 4
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "runtime peer unavailable\n"


def test_runtime_orchestration_parsers_accept_managed_commands() -> None:
    parser = build_parser()

    doctor = parser.parse_args(["runtime", "doctor", "--emulator", "melonds"])
    assert doctor.runtime_command == "doctor"
    assert doctor.emulator == "melonds"

    launch = parser.parse_args(
        [
            "runtime",
            "launch",
            "game.nds",
            "--emulator",
            "desmume",
            "--cpu",
            "arm9",
            "--session-root",
            "runtime",
        ]
    )
    assert launch.runtime_command == "launch"
    assert launch.rom == Path("game.nds")
    assert launch.emulator == "desmume"

    info = parser.parse_args(["runtime", "session", "info", "runtime/session-a"])
    assert info.runtime_command == "session"
    assert info.runtime_session_command == "info"

    stop = parser.parse_args(["runtime", "session", "stop", "runtime/session-a"])
    assert stop.runtime_session_command == "stop"



def test_runtime_checkpoint_parser_accepts_save_and_restore() -> None:
    parser = build_parser()

    save = parser.parse_args(
        ["runtime", "checkpoint", "save", "runtime/session-a", "battle-ready"]
    )
    assert save.runtime_command == "checkpoint"
    assert save.runtime_checkpoint_command == "save"
    assert save.session == Path("runtime/session-a")
    assert save.name == "battle-ready"

    restore = parser.parse_args(
        ["runtime", "checkpoint", "restore", "runtime/session-a", "battle-ready"]
    )
    assert restore.runtime_command == "checkpoint"
    assert restore.runtime_checkpoint_command == "restore"
    assert restore.session == Path("runtime/session-a")
    assert restore.name == "battle-ready"



def test_runtime_scenario_and_resume_parsers_accept_paths() -> None:
    parser = build_parser()

    scenario = parser.parse_args(
        [
            "runtime",
            "scenario",
            "run",
            "runtime/session-a",
            "scenario.json",
        ]
    )
    assert scenario.runtime_command == "scenario"
    assert scenario.runtime_scenario_command == "run"
    assert scenario.session == Path("runtime/session-a")
    assert scenario.scenario == Path("scenario.json")

    resume = parser.parse_args(
        [
            "runtime",
            "session",
            "resume",
            "runtime/session-a",
            "scenario.json",
        ]
    )
    assert resume.runtime_command == "session"
    assert resume.runtime_session_command == "resume"
    assert resume.session == Path("runtime/session-a")
    assert resume.scenario == Path("scenario.json")



def test_runtime_scenario_dispatch_uses_managed_session_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session_root = tmp_path / "session"
    session_root.mkdir()
    record = type("Record", (), {"session_root": session_root})()
    definition = object()
    context = object()
    calls: list[tuple[object, ...]] = []

    class ManagedContext:
        def __enter__(self) -> object:
            return context

        def __exit__(
            self,
            exc_type: object,
            exc: object,
            traceback: object,
        ) -> None:
            return None

    monkeypatch.setattr(runtime_cli, "load_session", lambda path: record)
    monkeypatch.setattr(runtime_cli, "load_scenario", lambda path: definition, raising=False)
    monkeypatch.setattr(
        runtime_cli,
        "_scenario_context",
        lambda loaded_record, loaded_definition: ManagedContext(),
        raising=False,
    )

    def fake_run(
        loaded_context: object,
        loaded_definition: object,
        *,
        journal_path: Path,
    ) -> object:
        calls.append((loaded_context, loaded_definition, journal_path))
        return type(
            "Result",
            (),
            {
                "scenario_name": "fixture",
                "completed_steps": ("step-0000",),
                "status": "passed",
            },
        )()

    monkeypatch.setattr(runtime_cli, "run_scenario", fake_run, raising=False)

    assert (
        main(
            [
                "runtime",
                "scenario",
                "run",
                str(session_root),
                "scenario.json",
            ]
        )
        == 0
    )
    assert calls == [(context, definition, session_root / "journal.json")]
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "completed_steps": ["step-0000"],
        "scenario_name": "fixture",
        "status": "passed",
    }


def test_runtime_resume_dispatch_reuses_session_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    session_root = tmp_path / "session"
    session_root.mkdir()
    record = type("Record", (), {"session_root": session_root})()
    definition = object()
    context = object()
    calls: list[tuple[object, ...]] = []

    class ManagedContext:
        def __enter__(self) -> object:
            return context

        def __exit__(
            self,
            exc_type: object,
            exc: object,
            traceback: object,
        ) -> None:
            return None

    monkeypatch.setattr(runtime_cli, "load_session", lambda path: record)
    monkeypatch.setattr(runtime_cli, "load_scenario", lambda path: definition, raising=False)
    monkeypatch.setattr(
        runtime_cli,
        "_scenario_context",
        lambda loaded_record, loaded_definition: ManagedContext(),
        raising=False,
    )

    def fake_resume(
        loaded_context: object,
        loaded_definition: object,
        *,
        journal_path: Path,
    ) -> object:
        calls.append((loaded_context, loaded_definition, journal_path))
        return type(
            "Result",
            (),
            {
                "scenario_name": "fixture",
                "completed_steps": ("step-0000", "step-0001"),
                "status": "passed",
            },
        )()

    monkeypatch.setattr(runtime_cli, "resume_scenario", fake_resume, raising=False)

    assert (
        main(
            [
                "runtime",
                "session",
                "resume",
                str(session_root),
                "scenario.json",
            ]
        )
        == 0
    )
    assert calls == [(context, definition, session_root / "journal.json")]
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "passed"
    assert payload["completed_steps"] == ["step-0000", "step-0001"]



def test_managed_scenario_trace_uses_existing_capture_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = type(
        "Record",
        (),
        {
            "session_root": tmp_path,
            "cpu": RuntimeCpu.ARM9,
            "emulator": runtime_cli.EmulatorKind.DESMUME,
            "rom_sha256": "1" * 64,
            "window_id": None,
            "display": None,
        },
    )()
    debugger = object()
    backend = object()
    context = runtime_cli._ManagedScenarioContext(record, backend, debugger)
    calls: list[tuple[object, object, Path]] = []

    def fake_capture(session: object, config: object, destination: Path) -> None:
        calls.append((session, config, destination))

    monkeypatch.setattr(runtime_cli, "capture_trace", fake_capture)
    step = runtime_cli.CaptureTraceStep(
        id="trace-step",
        output="case.ndstrace",
        steps=4,
    )

    context.capture_trace(step)

    assert len(calls) == 1
    session, config, destination = calls[0]
    assert session is debugger
    assert config.mode is runtime_cli.TraceCaptureMode.STEP
    assert config.limit == 4
    assert destination == tmp_path / "traces" / "case.ndstrace"


def test_managed_scenario_snapshot_writes_canonical_runtime_json(
    tmp_path: Path,
) -> None:
    class Debugger:
        def snapshot(self) -> RuntimeSnapshot:
            return _snapshot(0x02000044)

    record = type(
        "Record",
        (),
        {
            "session_root": tmp_path,
            "cpu": RuntimeCpu.ARM9,
            "emulator": runtime_cli.EmulatorKind.DESMUME,
            "rom_sha256": "1" * 64,
            "window_id": None,
            "display": None,
        },
    )()
    context = runtime_cli._ManagedScenarioContext(record, object(), Debugger())

    context.capture_snapshot("before-action")

    payload = json.loads(
        (tmp_path / "traces" / "before-action.json").read_text(encoding="utf-8")
    )
    assert payload["pc"] == "0x02000044"
    registers = {item["name"]: item["value"] for item in payload["registers"]}
    assert registers["pc"] == "0x02000044"



def test_runtime_resume_rejects_unowned_process_as_recovery_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = SimpleNamespace(
        session_root=tmp_path,
        emulator=runtime_cli.EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
    )
    definition = SimpleNamespace(
        backend=runtime_cli.EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint=None,
        steps=(),
    )
    monkeypatch.setattr(runtime_cli, "load_session", lambda path: record)
    monkeypatch.setattr(runtime_cli, "load_scenario", lambda path: definition)
    monkeypatch.setattr(runtime_cli, "process_is_owned", lambda loaded: False)

    arguments = build_parser().parse_args(
        ["runtime", "session", "resume", str(tmp_path), "scenario.json"]
    )
    with pytest.raises(RuntimeRecoveryError, match="adopt"):
        runtime_cli.run_runtime_command(arguments)


def test_managed_ui_scenario_requires_owned_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = SimpleNamespace(
        session_root=tmp_path,
        emulator=runtime_cli.EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        pid=1234,
        window_id=None,
        display=":104",
        debugger_host="127.0.0.1",
        debugger_port=39001,
    )
    definition = SimpleNamespace(
        backend=runtime_cli.EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint=None,
        steps=(SimpleNamespace(type="button"),),
    )

    class Backend:
        capabilities = SimpleNamespace(window_input=True)

        def connect_debugger(self, **kwargs: object) -> object:
            return SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(runtime_cli, "process_is_owned", lambda loaded: True)
    monkeypatch.setattr(runtime_cli, "_managed_backend", lambda kind: Backend())

    with (
        pytest.raises(RuntimeScenarioError, match="window"),
        runtime_cli._scenario_context(record, definition),
    ):
        pass



def test_runtime_matrix_parser_accepts_matrix_path() -> None:
    arguments = build_parser().parse_args(
        ["runtime", "matrix", "run", "matrix.json"]
    )
    assert arguments.runtime_command == "matrix"
    assert arguments.runtime_matrix_command == "run"
    assert arguments.matrix == Path("matrix.json")



def test_runtime_matrix_dispatch_uses_relative_scenario_and_managed_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    matrix_path = tmp_path / "matrix.json"
    session_root = tmp_path / "session"
    record = SimpleNamespace(session_root=session_root)
    matrix = SimpleNamespace(scenario=Path("scenario.json"))
    scenario = object()
    context = object()
    calls: list[tuple[object, ...]] = []

    class ManagedContext:
        def __enter__(self) -> object:
            return context

        def __exit__(
            self,
            exc_type: object,
            exc: object,
            traceback: object,
        ) -> None:
            return None

    monkeypatch.setattr(runtime_cli, "load_matrix", lambda path: matrix, raising=False)
    monkeypatch.setattr(runtime_cli, "load_session", lambda path: record)
    monkeypatch.setattr(
        runtime_cli,
        "load_scenario",
        lambda path: scenario if path == tmp_path / "scenario.json" else None,
    )
    monkeypatch.setattr(
        runtime_cli,
        "_scenario_context",
        lambda loaded_record, loaded_scenario: ManagedContext(),
    )

    def fake_run(
        context_factory: object,
        loaded_matrix: object,
        loaded_scenario: object,
    ) -> object:
        case_context = context_factory(SimpleNamespace(id="case-a"))
        calls.append((case_context, loaded_matrix, loaded_scenario))
        return SimpleNamespace(
            status="passed",
            cases=(
                SimpleNamespace(
                    id="case-a",
                    status="passed",
                    parameters={"value": "01"},
                    completed_steps=("step-0000",),
                    error=None,
                ),
            ),
        )

    monkeypatch.setattr(
        runtime_cli,
        "run_acceptance_matrix",
        fake_run,
        raising=False,
    )

    assert (
        main(
            [
                "runtime",
                "matrix",
                "run",
                str(matrix_path),
                "--session-root",
                str(session_root),
            ]
        )
        == 0
    )
    assert calls == [(context, matrix, scenario)]
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "passed"
    assert [case["id"] for case in payload["cases"]] == ["case-a"]



def test_managed_scenario_context_routes_ds_input_through_owned_host(
    tmp_path: Path,
) -> None:
    class Backend:
        def host_key_for(self, button: object) -> str:
            assert button is DSButton.A
            return "x"

        def layout_profile(self, geometry: object) -> object:
            assert geometry.width == 256
            assert geometry.height == 384
            return ScreenLayoutProfile(
                window=geometry,
                lower_screen=ScreenViewport(0, 192, 256, 192),
            )

    class Host:
        def __init__(self) -> None:
            self.events: list[object] = []

        def send_key(self, record: object, host_key: str) -> None:
            self.events.append(("key", host_key))

        def window_geometry(self, record: object) -> object:
            return WindowGeometry(0, 0, 256, 384)

        def move_pointer(self, record: object, x: int, y: int) -> None:
            self.events.append(("move", x, y))

        def pointer_down(self, record: object, *, button: int = 1) -> None:
            self.events.append(("down", button))

        def pointer_up(self, record: object, *, button: int = 1) -> None:
            self.events.append(("up", button))

    record = SimpleNamespace(
        session_root=tmp_path,
        emulator=runtime_cli.EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        rom_sha256="1" * 64,
        window_id="0xabc",
        display=":104",
    )
    host = Host()
    context = runtime_cli._ManagedScenarioContext(
        record,
        Backend(),
        object(),
        host_driver=host,
    )

    context.press_button(DSButton.A)
    context.touch_tap(DSPoint(255, 191))

    assert host.events == [
        ("key", "x"),
        ("move", 255, 383),
        ("down", 1),
        ("up", 1),
    ]



def _managed_record(tmp_path: Path) -> object:
    return RuntimeSessionRecord(
        schema_version=1,
        session_id="session-a",
        lifecycle=RuntimeLifecycleState.CREATED,
        emulator=runtime_cli.EmulatorKind.DESMUME,
        emulator_executable=tmp_path / "desmume-cli",
        emulator_sha256=None,
        emulator_version=None,
        rom_path=tmp_path / "game.nds",
        rom_sha256="0" * 64,
        cpu=RuntimeCpu.ARM9,
        pid=None,
        process_group=None,
        process_start_identity=None,
        debugger_host="127.0.0.1",
        debugger_port=39001,
        display=None,
        window_id=None,
        session_root=tmp_path / "session-a",
        last_completed_step=None,
        last_completed_case=None,
    )


def test_runtime_launch_desmume_owns_display_and_binds_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _managed_record(tmp_path)
    record.session_root.mkdir()
    calls: list[object] = []

    class Backend:
        capabilities = SimpleNamespace(window_input=True)

        def build_launch_spec(self, **kwargs: object) -> object:
            calls.append(("launch-spec-display", kwargs["display"]))
            return SimpleNamespace(argv=("desmume-cli",), environment=(), cwd=None)

    lease = X11DisplayLease(
        display_number=104,
        pid=9001,
        process_group=9001,
        start_identity="xvfb-start",
        executable=Path("/usr/bin/Xvfb"),
    )

    class Driver:
        def __init__(self, **kwargs: object) -> None:
            calls.append(("driver-display", kwargs.get("display")))

        def wait_for_window(self, running: object, *, timeout: float) -> str:
            calls.append(("wait-window", running.display, timeout))
            return "0xabc"

    def fake_spawn(launch_record: object, spec: object) -> object:
        del spec
        calls.append(("spawn-display", launch_record.display))
        return replace(
            launch_record,
            lifecycle=RuntimeLifecycleState.LAUNCHING,
            pid=1234,
            process_group=1234,
            process_start_identity="emu-start",
        )

    monkeypatch.setattr(runtime_cli, "_managed_backend", lambda kind: Backend())
    monkeypatch.setattr(runtime_cli, "create_session", lambda *args, **kwargs: record)
    monkeypatch.setattr(runtime_cli, "start_x11_display", lambda: lease, raising=False)
    monkeypatch.setattr(runtime_cli, "X11HostDriver", Driver)
    monkeypatch.setattr(runtime_cli, "spawn_owned_process", fake_spawn)
    monkeypatch.setattr(
        runtime_cli,
        "store_x11_display_lease",
        lambda root, value: calls.append(("store-lease", root, value.display)),
        raising=False,
    )
    monkeypatch.setattr(
        runtime_cli,
        "store_session",
        lambda value: calls.append(("store-session", value.display, value.window_id)),
        raising=False,
    )

    assert main(
        [
            "runtime",
            "launch",
            str(tmp_path / "game.nds"),
            "--emulator",
            "desmume",
            "--cpu",
            "arm9",
            "--session-root",
            str(tmp_path),
            "--executable",
            str(tmp_path / "desmume-cli"),
        ]
    ) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["display"] == ":104"
    assert payload["window_id"] == "0xabc"
    assert ("launch-spec-display", ":104") in calls
    assert ("spawn-display", ":104") in calls
    assert ("store-lease", record.session_root, ":104") in calls


def test_runtime_session_stop_releases_owned_display_after_emulator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = replace(
        _managed_record(tmp_path),
        lifecycle=RuntimeLifecycleState.LAUNCHING,
        pid=1234,
        process_group=1234,
        process_start_identity="emu-start",
        display=":104",
        window_id="0xabc",
    )
    record.session_root.mkdir()
    closed = replace(
        record,
        lifecycle=RuntimeLifecycleState.CLOSED,
    )
    lease = X11DisplayLease(
        display_number=104,
        pid=9001,
        process_group=9001,
        start_identity="xvfb-start",
        executable=Path("/usr/bin/Xvfb"),
    )
    order: list[str] = []

    monkeypatch.setattr(runtime_cli, "load_session", lambda path: record)
    monkeypatch.setattr(
        runtime_cli,
        "stop_owned_process",
        lambda value: order.append("emulator") or closed,
    )
    monkeypatch.setattr(
        runtime_cli,
        "load_x11_display_lease",
        lambda root: lease,
        raising=False,
    )
    monkeypatch.setattr(
        runtime_cli,
        "stop_x11_display",
        lambda value: order.append("display"),
        raising=False,
    )

    assert main(["runtime", "session", "stop", str(record.session_root)]) == 0

    assert order == ["emulator", "display"]
    assert json.loads(capsys.readouterr().out)["lifecycle"] == "closed"
