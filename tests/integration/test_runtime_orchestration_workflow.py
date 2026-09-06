from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration import (
    CheckpointContext,
    DSButton,
    EmulatorKind,
    create_checkpoint,
    restore_checkpoint,
)
from nds_disassembly_toolkit.analysis.orchestration.acceptance import (
    AcceptanceCase,
    AcceptanceMatrix,
    run_acceptance_matrix,
)
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    AssertStep,
    ButtonStep,
    CaptureSnapshotStep,
    CaptureTraceStep,
    MemoryWriteStep,
    ParameterReference,
    PredicateDefinition,
    ScenarioDefinition,
)
from nds_disassembly_toolkit.analysis.runtime import (
    BreakpointKind,
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceMemoryRegion,
)
from nds_disassembly_toolkit.analysis.runtime.capture import capture_trace
from nds_disassembly_toolkit.analysis.runtime.trace_store import TraceStore


@dataclass
class WorkflowContext:
    session_root: Path
    memory: bytes = b"\x7f"
    restores: list[str] = field(default_factory=list)

    def restore_checkpoint(self, name: str) -> None:
        self.restores.append(name)
        self.memory = b"\x00"

    def read_memory(self, address: int, length: int) -> bytes:
        assert address == 0x02000020
        return self.memory[:length]

    def write_memory(self, address: int, data: bytes) -> None:
        assert address == 0x02000020
        self.memory = data

    def capture_snapshot(self, label: str | None) -> None:
        path = self.session_root / "evidence.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "label": label,
                    "memory": self.memory.hex(),
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


@dataclass
class WorkflowFactory:
    root: Path
    contexts: dict[str, WorkflowContext] = field(default_factory=dict)

    def __call__(self, case: AcceptanceCase) -> WorkflowContext:
        context = WorkflowContext(self.root / case.id)
        self.contexts[case.id] = context
        return context


def test_two_parameterized_cases_restore_baseline_and_keep_independent_evidence(
    tmp_path: Path,
) -> None:
    scenario = ScenarioDefinition(
        schema_version=1,
        name="two-case-workflow",
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
            CaptureSnapshotStep(id="evidence", label="after-write"),
        ),
    )
    matrix = AcceptanceMatrix(
        schema_version=1,
        scenario=Path("scenario.json"),
        cases=(
            AcceptanceCase("case-one", {"test_value": "01"}),
            AcceptanceCase("case-two", {"test_value": "15"}),
        ),
    )
    factory = WorkflowFactory(tmp_path)

    result = run_acceptance_matrix(factory, matrix, scenario)

    assert result.status == "passed"
    assert [case.id for case in result.cases] == ["case-one", "case-two"]
    assert [factory.contexts[case].restores for case in ("case-one", "case-two")] == [
        ["baseline"],
        ["baseline"],
    ]
    assert [
        json.loads((factory.contexts[case].session_root / "evidence.json").read_text())
        ["memory"]
        for case in ("case-one", "case-two")
    ] == ["01", "15"]
    for case in ("case-one", "case-two"):
        assert (
            factory.contexts[case].session_root
            / "cases"
            / case
            / "journal.json"
        ).is_file()



_SUBPROCESS_TARGET = r"""
import json
import sys

BASE = 0x02000020
memory = bytearray([0x7F, 0x7F])
pc = 0x02000000

for line in sys.stdin:
    request = json.loads(line)
    command = request["command"]
    if command == "read":
        offset = request["address"] - BASE
        length = request["length"]
        response = {"data": bytes(memory[offset:offset + length]).hex()}
    elif command == "write":
        offset = request["address"] - BASE
        data = bytes.fromhex(request["data"])
        memory[offset:offset + len(data)] = data
        response = {}
    elif command == "snapshot":
        response = {"pc": pc}
    elif command == "step":
        pc = (pc + 4) & 0xFFFFFFFF
        response = {"pc": pc}
    elif command == "press":
        if request["button"] == "a" and memory[0] != 0:
            memory[1] = 0xAA
        response = {}
    elif command == "save":
        with open(request["path"], "w", encoding="utf-8") as handle:
            json.dump({"memory": memory.hex(), "pc": pc}, handle, sort_keys=True)
        response = {}
    elif command == "load":
        with open(request["path"], encoding="utf-8") as handle:
            state = json.load(handle)
        memory[:] = bytes.fromhex(state["memory"])
        pc = int(state["pc"])
        response = {}
    elif command == "exit":
        print(json.dumps({"ok": True}), flush=True)
        break
    else:
        response = {"error": command}
    response["ok"] = "error" not in response
    print(json.dumps(response, sort_keys=True), flush=True)
"""


class SubprocessRuntimeTarget:
    cpu = RuntimeCpu.ARM9

    def __init__(self) -> None:
        import subprocess
        import sys

        self._process = subprocess.Popen(
            [sys.executable, "-u", "-c", _SUBPROCESS_TARGET],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

    def _request(self, payload: dict[str, object]) -> dict[str, object]:
        assert self._process.stdin is not None
        assert self._process.stdout is not None
        self._process.stdin.write(json.dumps(payload, sort_keys=True) + "\n")
        self._process.stdin.flush()
        line = self._process.stdout.readline()
        assert line
        response = json.loads(line)
        assert response["ok"] is True, response
        return response

    def read_memory(self, address: int, length: int) -> bytes:
        response = self._request(
            {"command": "read", "address": address, "length": length}
        )
        return bytes.fromhex(str(response["data"]))

    def write_memory(self, address: int, data: bytes) -> None:
        self._request(
            {"command": "write", "address": address, "data": data.hex()}
        )

    def _snapshot(self, *, stepped: bool) -> RuntimeSnapshot:
        response = self._request(
            {"command": "step" if stepped else "snapshot"}
        )
        return RuntimeSnapshot(
            cpu=RuntimeCpu.ARM9,
            registers=RegisterSnapshot.from_mapping(
                {"pc": int(response["pc"]), "cpsr": 0}
            ),
            stop=RuntimeStop(
                StopReasonKind.STEP if stepped else StopReasonKind.UNKNOWN
            ),
        )

    def snapshot(self) -> RuntimeSnapshot:
        return self._snapshot(stepped=False)

    def step(self) -> RuntimeSnapshot:
        return self._snapshot(stepped=True)

    def run_until_breakpoint(
        self,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        del address, length
        raise AssertionError("breakpoint capture is not used by this fixture")

    def run_until_watchpoint(
        self,
        kind: BreakpointKind,
        address: int,
        *,
        length: int = 4,
    ) -> RuntimeSnapshot:
        del kind, address, length
        raise AssertionError("watchpoint capture is not used by this fixture")

    def press_button(self, button: DSButton) -> None:
        self._request({"command": "press", "button": button.value})

    def save_state(self, destination: Path) -> None:
        self._request({"command": "save", "path": str(destination)})

    def load_state(self, source: Path) -> None:
        self._request({"command": "load", "path": str(source)})

    def close(self) -> None:
        if self._process.poll() is not None:
            return
        self._request({"command": "exit"})
        self._process.wait(timeout=5)


@dataclass
class SubprocessWorkflowContext:
    root: Path
    case_id: str
    target: SubprocessRuntimeTarget
    restores: list[str] = field(default_factory=list)
    buttons: list[DSButton] = field(default_factory=list)

    @property
    def session_root(self) -> Path:
        return self.root

    def _checkpoint_context(self) -> CheckpointContext:
        return CheckpointContext(
            checkpoint_root=self.root / "checkpoints",
            emulator=EmulatorKind.DESMUME,
            rom_sha256="0" * 64,
            backend=self.target,
        )

    def restore_checkpoint(self, name: str) -> None:
        self.restores.append(name)
        restore_checkpoint(
            self._checkpoint_context(),
            self.root / "checkpoints" / name,
        )

    def read_memory(self, address: int, length: int) -> bytes:
        return self.target.read_memory(address, length)

    def write_memory(self, address: int, data: bytes) -> None:
        self.target.write_memory(address, data)

    def press_button(self, button: DSButton) -> None:
        self.buttons.append(button)
        self.target.press_button(button)

    def capture_trace(self, step: CaptureTraceStep) -> None:
        assert isinstance(step.output, str)
        assert step.steps is not None
        regions = tuple(
            TraceMemoryRegion(index, address, length)
            for index, (address, length) in enumerate(step.memory)
        )
        destination = (
            self.root / "cases" / self.case_id / "traces" / step.output
        )
        capture_trace(
            self.target,
            TraceCaptureConfig(
                cpu=RuntimeCpu.ARM9,
                mode=TraceCaptureMode.STEP,
                limit=step.steps,
                timeout=1.0,
                memory_regions=regions,
                label=step.id,
            ),
            destination,
        )


@dataclass
class SubprocessWorkflowFactory:
    root: Path
    contexts: dict[str, SubprocessWorkflowContext] = field(default_factory=dict)

    def __call__(self, case: AcceptanceCase) -> SubprocessWorkflowContext:
        context = SubprocessWorkflowContext(
            root=self.root,
            case_id=case.id,
            target=SubprocessRuntimeTarget(),
        )
        self.contexts[case.id] = context
        return context

    def close(self) -> None:
        for context in self.contexts.values():
            context.target.close()


def test_subprocess_backed_acceptance_workflow_uses_real_checkpoint_and_trace(
    tmp_path: Path,
) -> None:
    base = 0x02000020
    output = base + 1
    baseline = SubprocessRuntimeTarget()
    try:
        baseline.write_memory(base, b"\x00\x00")
        create_checkpoint(
            CheckpointContext(
                checkpoint_root=tmp_path / "checkpoints",
                emulator=EmulatorKind.DESMUME,
                rom_sha256="0" * 64,
                backend=baseline,
            ),
            "baseline",
        )
    finally:
        baseline.close()

    scenario = ScenarioDefinition(
        schema_version=1,
        name="subprocess-acceptance",
        backend=EmulatorKind.DESMUME,
        cpu=RuntimeCpu.ARM9,
        required_capabilities=(),
        checkpoint="baseline",
        steps=(
            MemoryWriteStep(
                id="guarded-write",
                address=base,
                replacement=ParameterReference("test_value"),
                expected_before=b"\x00",
                precondition=PredicateDefinition(
                    type="memory_equals",
                    address=base,
                    expected=b"\x00",
                ),
            ),
            ButtonStep(
                id="controlled-input",
                button=DSButton.A,
                postcondition=PredicateDefinition(
                    type="memory_equals",
                    address=output,
                    expected=b"\xaa",
                ),
            ),
            CaptureTraceStep(
                id="runtime-trace",
                output="result.ndstrace",
                steps=1,
                memory=((output, 1),),
            ),
            AssertStep(
                id="postcondition",
                condition=PredicateDefinition(
                    type="memory_equals",
                    address=output,
                    expected=b"\xaa",
                ),
            ),
        ),
    )
    matrix = AcceptanceMatrix(
        schema_version=1,
        scenario=Path("scenario.json"),
        cases=(
            AcceptanceCase("case-one", {"test_value": "01"}),
            AcceptanceCase("case-two", {"test_value": "15"}),
        ),
    )
    factory = SubprocessWorkflowFactory(tmp_path)
    try:
        result = run_acceptance_matrix(factory, matrix, scenario)
    finally:
        factory.close()

    assert result.status == "passed"
    assert [case.status for case in result.cases] == ["passed", "passed"]
    for case_id in ("case-one", "case-two"):
        context = factory.contexts[case_id]
        assert context.restores == ["baseline"]
        assert context.buttons == [DSButton.A]
        case_root = tmp_path / "cases" / case_id
        assert (case_root / "journal.json").is_file()
        trace_path = case_root / "traces" / "result.ndstrace"
        assert trace_path.is_file()
        store = TraceStore.open(trace_path)
        try:
            events = store.events()
        finally:
            store.close()
        assert len(events) == 1

    assert (tmp_path / "matrix-result.json").is_file()
