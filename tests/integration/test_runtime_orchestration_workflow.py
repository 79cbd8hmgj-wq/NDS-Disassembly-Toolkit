from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration import EmulatorKind
from nds_disassembly_toolkit.analysis.orchestration.acceptance import (
    AcceptanceCase,
    AcceptanceMatrix,
    run_acceptance_matrix,
)
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    CaptureSnapshotStep,
    MemoryWriteStep,
    ParameterReference,
    ScenarioDefinition,
)
from nds_disassembly_toolkit.analysis.runtime import RuntimeCpu


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
