from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.analysis.orchestration.evidence import collect_failure_bundle
from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    JournalStepState,
    ScenarioJournal,
    ScenarioJournalStep,
)


@dataclass
class BrokenEvidenceContext:
    session_root: Path

    def snapshot(self) -> object:
        raise RuntimeError("secondary snapshot failure")


def test_failure_bundle_preserves_primary_error_when_snapshot_fails(
    tmp_path: Path,
) -> None:
    context = BrokenEvidenceContext(tmp_path)
    journal = ScenarioJournal(
        schema_version=1,
        scenario_name="failure",
        steps=(ScenarioJournalStep("step-0000", JournalStepState.FAILED),),
    )
    primary = RuntimeError("primary scenario failure")

    bundle = collect_failure_bundle(
        context,
        error=primary,
        step_id="step-0000",
        journal=journal,
    )

    payload = json.loads((bundle / "failure.json").read_text(encoding="utf-8"))
    assert payload["error"] == "primary scenario failure"
    assert payload["step_id"] == "step-0000"
    assert payload["secondary_errors"]
    assert (bundle / "journal.json").is_file()


@dataclass
class RichEvidenceContext:
    session_root: Path
    record: object
    _snapshot: object

    def snapshot(self) -> object:
        return self._snapshot

    def process_alive(self) -> bool:
        return True

    def capture_screenshot(self, destination: Path) -> bool:
        destination.write_bytes(b"fake-png-bytes")
        return True


def _journal() -> ScenarioJournal:
    return ScenarioJournal(
        schema_version=1,
        scenario_name="failure",
        steps=(ScenarioJournalStep("step-0000", JournalStepState.FAILED),),
    )


def test_failure_bundle_includes_screenshot_and_process_info(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from nds_disassembly_toolkit.analysis.orchestration.model import RuntimeLifecycleState
    from nds_disassembly_toolkit.analysis.runtime import (
        RegisterSnapshot,
        RuntimeCpu,
        RuntimeSnapshot,
        RuntimeStop,
        StopReasonKind,
    )

    record = SimpleNamespace(
        pid=4242,
        window_id="0xabc",
        display=":99",
        lifecycle=RuntimeLifecycleState.RUNNING,
    )
    snapshot = RuntimeSnapshot(
        cpu=RuntimeCpu.ARM9,
        registers=RegisterSnapshot.from_mapping({"pc": 0x02000000, "cpsr": 0x13}),
        stop=RuntimeStop(StopReasonKind.BREAKPOINT, signal=5, address=0x02000000, raw="T05"),
    )
    context = RichEvidenceContext(session_root=tmp_path, record=record, _snapshot=snapshot)
    (tmp_path / "emulator.stdout.log").write_bytes(b"boot ok\n")
    (tmp_path / "emulator.stderr.log").write_bytes(b"warn: gpu\n")

    bundle = collect_failure_bundle(
        context,
        error=RuntimeError("boom"),
        step_id="step-0000",
        journal=_journal(),
    )

    assert (bundle / "screenshot.png").read_bytes() == b"fake-png-bytes"
    assert (bundle / "emulator.stdout.tail.log").read_bytes() == b"boot ok\n"
    assert (bundle / "emulator.stderr.tail.log").read_bytes() == b"warn: gpu\n"
    process_info = json.loads((bundle / "process.json").read_text(encoding="utf-8"))
    assert process_info["pid"] == 4242
    assert process_info["window_id"] == "0xabc"
    assert process_info["display"] == ":99"
    assert process_info["lifecycle"] == "running"
    assert process_info["process_alive"] is True
    payload = json.loads((bundle / "failure.json").read_text(encoding="utf-8"))
    assert payload["secondary_errors"] == []


def test_failure_bundle_tolerates_missing_screenshot_capability(tmp_path: Path) -> None:
    context = BrokenEvidenceContext(tmp_path)

    bundle = collect_failure_bundle(
        context,
        error=RuntimeError("boom"),
        step_id="step-0000",
        journal=_journal(),
    )

    assert not (bundle / "screenshot.png").exists()
    assert not (bundle / "process.json").exists()
    assert (bundle / "failure.json").is_file()


def test_failure_bundle_records_screenshot_failure_without_masking_primary_error(
    tmp_path: Path,
) -> None:
    @dataclass
    class FailingScreenshotContext:
        session_root: Path

        def snapshot(self) -> object:
            raise RuntimeError("no snapshot")

        def capture_screenshot(self, destination: Path) -> bool:
            raise RuntimeError("capture tool crashed")

    context = FailingScreenshotContext(tmp_path)
    primary = RuntimeError("primary scenario failure")

    bundle = collect_failure_bundle(
        context,
        error=primary,
        step_id="step-0000",
        journal=_journal(),
    )

    payload = json.loads((bundle / "failure.json").read_text(encoding="utf-8"))
    assert payload["error"] == "primary scenario failure"
    assert any("capture tool crashed" in entry for entry in payload["secondary_errors"])
