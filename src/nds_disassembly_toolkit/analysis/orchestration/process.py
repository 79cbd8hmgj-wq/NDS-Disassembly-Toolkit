from __future__ import annotations

import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from nds_disassembly_toolkit.analysis.orchestration.model import (
    SESSION_SCHEMA_VERSION,
    EmulatorKind,
    LaunchSpec,
    RuntimeLifecycleState,
    RuntimeSessionRecord,
)
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeLaunchError, RuntimeOwnershipError


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _sha256_required(path: Path, *, name: str) -> str:
    digest = _sha256_file(path)
    if digest is None:
        raise RuntimeLaunchError(f"cannot fingerprint {name}: {path}")
    return digest


def allocate_loopback_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
        peer.bind((host, 0))
        port = peer.getsockname()[1]
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise RuntimeLaunchError("failed to allocate a loopback debugger port")
    return port


def _session_json(record: RuntimeSessionRecord) -> dict[str, object]:
    payload = asdict(record)
    payload["lifecycle"] = record.lifecycle.value
    payload["emulator"] = record.emulator.value
    payload["cpu"] = record.cpu.value
    for name in ("emulator_executable", "rom_path", "session_root"):
        payload[name] = str(getattr(record, name))
    return payload


def store_session(record: RuntimeSessionRecord) -> None:
    path = record.session_root / "session.json"
    temporary = record.session_root / "session.json.tmp"
    rendered = json.dumps(_session_json(record), indent=2, sort_keys=True) + "\n"
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(path)


def load_session(path: Path) -> RuntimeSessionRecord:
    root = path.expanduser().resolve()
    payload = json.loads((root / "session.json").read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeOwnershipError("runtime session manifest must be a JSON object")
    return RuntimeSessionRecord(
        schema_version=int(payload["schema_version"]),
        session_id=str(payload["session_id"]),
        lifecycle=RuntimeLifecycleState(str(payload["lifecycle"])),
        emulator=EmulatorKind(str(payload["emulator"])),
        emulator_executable=Path(str(payload["emulator_executable"])),
        emulator_sha256=(
            None if payload["emulator_sha256"] is None else str(payload["emulator_sha256"])
        ),
        emulator_version=(
            None if payload["emulator_version"] is None else str(payload["emulator_version"])
        ),
        rom_path=Path(str(payload["rom_path"])),
        rom_sha256=str(payload["rom_sha256"]),
        cpu=RuntimeCpu(str(payload["cpu"])),
        pid=None if payload["pid"] is None else int(payload["pid"]),
        process_group=(
            None if payload["process_group"] is None else int(payload["process_group"])
        ),
        process_start_identity=(
            None
            if payload["process_start_identity"] is None
            else str(payload["process_start_identity"])
        ),
        debugger_host=str(payload["debugger_host"]),
        debugger_port=int(payload["debugger_port"]),
        display=None if payload["display"] is None else str(payload["display"]),
        window_id=None if payload["window_id"] is None else str(payload["window_id"]),
        session_root=Path(str(payload["session_root"])),
        last_completed_step=(
            None
            if payload["last_completed_step"] is None
            else str(payload["last_completed_step"])
        ),
        last_completed_case=(
            None
            if payload["last_completed_case"] is None
            else str(payload["last_completed_case"])
        ),
    )


def create_session(
    root: Path,
    *,
    emulator: EmulatorKind,
    executable: Path,
    rom: Path,
    cpu: RuntimeCpu,
    debugger_host: str = "127.0.0.1",
) -> RuntimeSessionRecord:
    root = root.expanduser().resolve()
    executable = executable.expanduser().resolve()
    rom = rom.expanduser().resolve()
    session_id = secrets.token_hex(16)
    session_root = root / session_id
    session_root.mkdir(parents=True, exist_ok=False)
    for name in ("saves", "checkpoints", "traces", "cases", "failure"):
        (session_root / name).mkdir()
    record = RuntimeSessionRecord(
        schema_version=SESSION_SCHEMA_VERSION,
        session_id=session_id,
        lifecycle=RuntimeLifecycleState.CREATED,
        emulator=emulator,
        emulator_executable=executable,
        emulator_sha256=_sha256_required(executable, name="emulator executable"),
        emulator_version=None,
        rom_path=rom,
        rom_sha256=_sha256_required(rom, name="ROM"),
        cpu=cpu,
        pid=None,
        process_group=None,
        process_start_identity=None,
        debugger_host=debugger_host,
        debugger_port=allocate_loopback_port(debugger_host),
        display=None,
        window_id=None,
        session_root=session_root,
        last_completed_step=None,
        last_completed_case=None,
    )
    store_session(record)
    return record


def _linux_process_start_identity(pid: int) -> str | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    close = text.rfind(")")
    if close < 0:
        return None
    fields = text[close + 2 :].split()
    if len(fields) <= 19:
        return None
    return fields[19]


def _linux_process_executable(pid: int) -> Path | None:
    try:
        return Path(os.readlink(f"/proc/{pid}/exe")).resolve()
    except OSError:
        return None


def process_is_owned(record: RuntimeSessionRecord) -> bool:
    if (
        record.pid is None
        or record.process_group is None
        or record.process_start_identity is None
    ):
        return False
    pid = record.pid
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    if _linux_process_start_identity(pid) != record.process_start_identity:
        return False
    executable = _linux_process_executable(pid)
    if executable is None:
        return False
    try:
        expected = record.emulator_executable.resolve()
    except OSError:
        expected = record.emulator_executable
    if executable != expected:
        return False
    actual_sha = _sha256_file(executable)
    if record.emulator_sha256 is not None and actual_sha != record.emulator_sha256:
        return False
    try:
        return os.getpgid(pid) == record.process_group
    except OSError:
        return False


def spawn_owned_process(
    record: RuntimeSessionRecord,
    launch: LaunchSpec,
) -> RuntimeSessionRecord:
    if record.pid is not None:
        raise RuntimeLaunchError("runtime session already has a process identity")
    environment = os.environ.copy()
    environment.update(dict(launch.environment))
    stdout_path = record.session_root / "emulator.stdout.log"
    stderr_path = record.session_root / "emulator.stderr.log"
    try:
        with stdout_path.open("ab") as stdout, stderr_path.open("ab") as stderr:
            process = subprocess.Popen(
                list(launch.argv),
                cwd=None if launch.cwd is None else str(launch.cwd),
                env=environment,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
    except OSError as exc:
        raise RuntimeLaunchError(f"failed to launch managed emulator: {exc}") from exc

    start_identity: str | None = None
    process_group: int | None = None
    for _ in range(100):
        start_identity = _linux_process_start_identity(process.pid)
        try:
            process_group = os.getpgid(process.pid)
        except OSError:
            process_group = None
        if start_identity is not None and process_group is not None:
            break
        if process.poll() is not None:
            break
        time.sleep(0.001)

    if start_identity is None or process_group is None:
        try:
            process.terminate()
        except OSError:
            pass
        raise RuntimeLaunchError("managed emulator exited before process identity was established")

    running = replace(
        record,
        lifecycle=RuntimeLifecycleState.LAUNCHING,
        pid=process.pid,
        process_group=process_group,
        process_start_identity=start_identity,
    )
    if not process_is_owned(running):
        try:
            os.killpg(process_group, signal.SIGTERM)
        except OSError:
            pass
        raise RuntimeOwnershipError("managed emulator ownership could not be proven after launch")
    store_session(running)
    return running


def _group_alive(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except OSError:
        return False


def stop_owned_process(
    record: RuntimeSessionRecord,
    *,
    grace_seconds: float = 3.0,
) -> RuntimeSessionRecord:
    if grace_seconds < 0:
        raise ValueError("grace_seconds must be non-negative")
    if not process_is_owned(record):
        raise RuntimeOwnershipError("runtime process ownership could not be proven")
    assert record.process_group is not None

    stopping = replace(record, lifecycle=RuntimeLifecycleState.STOPPING)
    store_session(stopping)
    try:
        os.killpg(record.process_group, signal.SIGTERM)
    except OSError as exc:
        raise RuntimeOwnershipError("failed to signal owned runtime process") from exc

    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if not _group_alive(record.process_group):
            break
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))

    if _group_alive(record.process_group):
        # Re-prove ownership before escalation. If the original process has already
        # disappeared, never risk signalling a reused group id.
        if process_is_owned(record):
            os.killpg(record.process_group, signal.SIGKILL)
            kill_deadline = time.monotonic() + 1.0
            while time.monotonic() < kill_deadline and _group_alive(record.process_group):
                time.sleep(0.01)

    closed = replace(stopping, lifecycle=RuntimeLifecycleState.CLOSED)
    store_session(closed)
    return closed
