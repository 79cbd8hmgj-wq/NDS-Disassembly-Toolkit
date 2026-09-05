from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    ScenarioJournal,
    store_journal,
)
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeSnapshot


class FailureEvidenceContext(Protocol):
    session_root: Path

    def snapshot(self) -> object: ...


def _safe_step_id(step_id: str) -> str:
    candidate = Path(step_id)
    if (
        not step_id
        or candidate.is_absolute()
        or candidate.name != step_id
        or "/" in step_id
        or "\\" in step_id
        or step_id in {".", ".."}
    ):
        return "unknown-step"
    return step_id


def _snapshot_payload(snapshot: RuntimeSnapshot) -> dict[str, object]:
    return {
        "cpu": snapshot.cpu.value,
        "pc": f"0x{snapshot.pc:08x}",
        "cpsr": f"0x{snapshot.cpsr:08x}",
        "instruction_set": snapshot.instruction_set.value,
        "registers": [
            {"name": name, "value": f"0x{value:08x}"}
            for name, value in snapshot.registers.values
        ],
        "stop": {
            "kind": snapshot.stop.kind.value,
            "signal": snapshot.stop.signal,
            "address": (
                None
                if snapshot.stop.address is None
                else f"0x{snapshot.stop.address:08x}"
            ),
            "raw": snapshot.stop.raw,
        },
    }


def _write_json(path: Path, payload: object) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(path)


def collect_failure_bundle(
    context: FailureEvidenceContext,
    *,
    error: BaseException,
    step_id: str,
    journal: ScenarioJournal,
) -> Path:
    bundle = context.session_root / "failure" / _safe_step_id(step_id)
    bundle.mkdir(parents=True, exist_ok=True)
    secondary_errors: list[str] = []

    try:
        store_journal(bundle / "journal.json", journal)
    except Exception as exc:
        secondary_errors.append(f"journal: {exc}")

    try:
        snapshot = context.snapshot()
        if not isinstance(snapshot, RuntimeSnapshot):
            raise TypeError("snapshot evidence was not a RuntimeSnapshot")
        _write_json(bundle / "registers.json", _snapshot_payload(snapshot))
    except Exception as exc:
        secondary_errors.append(f"snapshot: {exc}")

    _write_json(
        bundle / "failure.json",
        {
            "error": str(error),
            "error_type": type(error).__name__,
            "scenario_name": journal.scenario_name,
            "secondary_errors": secondary_errors,
            "step_id": step_id,
        },
    )
    return bundle
