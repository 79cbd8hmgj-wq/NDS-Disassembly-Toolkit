from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.orchestration.scenario import (
    ScenarioJournal,
    store_journal,
)
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeSnapshot

_LOG_TAIL_BYTES = 64 * 1024


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


def _copy_log_tail(source: Path, destination: Path) -> bool:
    if not source.is_file():
        return False
    size = source.stat().st_size
    with source.open("rb") as handle:
        if size > _LOG_TAIL_BYTES:
            handle.seek(size - _LOG_TAIL_BYTES)
        data = handle.read()
    destination.write_bytes(data)
    return True


def _process_info(context: FailureEvidenceContext) -> dict[str, object] | None:
    record = getattr(context, "record", None)
    if record is None:
        return None
    alive_method = getattr(context, "process_alive", None)
    info: dict[str, object] = {
        "pid": getattr(record, "pid", None),
        "window_id": getattr(record, "window_id", None),
        "display": getattr(record, "display", None),
    }
    lifecycle = getattr(record, "lifecycle", None)
    info["lifecycle"] = None if lifecycle is None else str(getattr(lifecycle, "value", lifecycle))
    if callable(alive_method):
        try:
            info["process_alive"] = bool(alive_method())
        except Exception:
            info["process_alive"] = None
    return info


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

    # Best-effort forensic extras: a window screenshot, tails of the
    # emulator's own stdout/stderr, and whatever process/window metadata the
    # context exposes. None of these are required for the bundle to be
    # useful, so a missing capability or transient failure here must never
    # mask the primary scenario error.
    capture = getattr(context, "capture_screenshot", None)
    if callable(capture):
        try:
            captured = capture(bundle / "screenshot.png")
            if captured is False:
                secondary_errors.append("screenshot: capability unavailable")
        except Exception as exc:
            secondary_errors.append(f"screenshot: {exc}")

    try:
        for name in ("emulator.stdout.log", "emulator.stderr.log"):
            source = context.session_root / name
            tail_destination = bundle / f"{Path(name).stem}.tail.log"
            _copy_log_tail(source, tail_destination)
    except Exception as exc:
        secondary_errors.append(f"emulator-log: {exc}")

    try:
        process_info = _process_info(context)
        if process_info is not None:
            _write_json(bundle / "process.json", process_info)
    except Exception as exc:
        secondary_errors.append(f"process-info: {exc}")

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
