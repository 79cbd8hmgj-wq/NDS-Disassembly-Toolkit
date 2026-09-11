from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeLifecycleError

SESSION_SCHEMA_VERSION = 1
CHECKPOINT_SCHEMA_VERSION = 1
SCENARIO_SCHEMA_VERSION = 1
JOURNAL_SCHEMA_VERSION = 1
MATRIX_SCHEMA_VERSION = 1
_HEX_DIGITS = frozenset("0123456789abcdef")


def _validate_sha256(value: str | None, *, name: str) -> None:
    if value is None:
        return
    if len(value) != 64 or any(character not in _HEX_DIGITS for character in value):
        raise ValueError(f"{name} must be 64 lowercase hexadecimal characters")


class EmulatorKind(StrEnum):
    MELONDS = "melonds"
    DESMUME = "desmume"


class DebuggerHandshakeMode(StrEnum):
    INITIAL_ACK = "initial_ack"
    DIRECT = "direct"


class RuntimeLifecycleState(StrEnum):
    CREATED = "created"
    PREPARING = "preparing"
    LAUNCHING = "launching"
    WAITING_FOR_RUNTIME = "waiting_for_runtime"
    READY = "ready"
    RUNNING = "running"
    STOPPING = "stopping"
    CLOSED = "closed"
    FAILED = "failed"


# Legal successor states for each lifecycle state. STOPPING and FAILED are
# reachable from every non-terminal state so a session can always be torn
# down or flagged broken, even mid-launch; every other edge models a real
# forward step in bringing a managed emulator session up.
_LIFECYCLE_TRANSITIONS: dict[RuntimeLifecycleState, frozenset[RuntimeLifecycleState]] = {
    RuntimeLifecycleState.CREATED: frozenset(
        {
            RuntimeLifecycleState.PREPARING,
            RuntimeLifecycleState.LAUNCHING,
            RuntimeLifecycleState.FAILED,
            RuntimeLifecycleState.STOPPING,
        }
    ),
    RuntimeLifecycleState.PREPARING: frozenset(
        {
            RuntimeLifecycleState.LAUNCHING,
            RuntimeLifecycleState.FAILED,
            RuntimeLifecycleState.STOPPING,
        }
    ),
    RuntimeLifecycleState.LAUNCHING: frozenset(
        {
            RuntimeLifecycleState.WAITING_FOR_RUNTIME,
            RuntimeLifecycleState.READY,
            RuntimeLifecycleState.FAILED,
            RuntimeLifecycleState.STOPPING,
        }
    ),
    RuntimeLifecycleState.WAITING_FOR_RUNTIME: frozenset(
        {
            RuntimeLifecycleState.READY,
            RuntimeLifecycleState.FAILED,
            RuntimeLifecycleState.STOPPING,
        }
    ),
    RuntimeLifecycleState.READY: frozenset(
        {
            RuntimeLifecycleState.RUNNING,
            RuntimeLifecycleState.FAILED,
            RuntimeLifecycleState.STOPPING,
        }
    ),
    RuntimeLifecycleState.RUNNING: frozenset(
        {
            RuntimeLifecycleState.READY,
            RuntimeLifecycleState.FAILED,
            RuntimeLifecycleState.STOPPING,
        }
    ),
    RuntimeLifecycleState.STOPPING: frozenset(
        {RuntimeLifecycleState.CLOSED, RuntimeLifecycleState.FAILED}
    ),
    RuntimeLifecycleState.CLOSED: frozenset(),
    # A FAILED session can still own a live process (e.g. launch failed after
    # the emulator forked); STOPPING must stay reachable so it can be reaped.
    # LAUNCHING is also reachable so a session whose process died can be
    # relaunched from its last valid checkpoint instead of being permanently
    # stuck (see orchestration.recovery).
    RuntimeLifecycleState.FAILED: frozenset(
        {RuntimeLifecycleState.STOPPING, RuntimeLifecycleState.LAUNCHING}
    ),
}


def validate_lifecycle_transition(
    current: RuntimeLifecycleState,
    new: RuntimeLifecycleState,
) -> None:
    """Raise ``RuntimeLifecycleError`` if ``current -> new`` is not a legal step.

    Re-affirming the current state (``new is current``) is always a no-op.
    """
    if new is current:
        return
    allowed = _LIFECYCLE_TRANSITIONS.get(current, frozenset())
    if new not in allowed:
        raise RuntimeLifecycleError(
            f"illegal runtime lifecycle transition: {current.value} -> {new.value}"
        )


@dataclass(frozen=True, slots=True)
class EmulatorCapabilities:
    debugger_arm9: bool
    debugger_arm7: bool
    managed_launch: bool
    save_state: bool
    battery_save_isolation: bool
    window_input: bool
    touchscreen_input: bool
    screenshot: bool
    debugger_handshake_mode: DebuggerHandshakeMode


@dataclass(frozen=True, slots=True)
class LaunchSpec:
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...] = ()
    cwd: Path | None = None

    def __post_init__(self) -> None:
        if not self.argv:
            raise ValueError("launch argv must not be empty")
        if any(not argument for argument in self.argv):
            raise ValueError("launch argv entries must not be empty")
        names: set[str] = set()
        for name, _ in self.environment:
            if not name:
                raise ValueError("environment variable names must not be empty")
            if name in names:
                raise ValueError(f"duplicate environment variable: {name}")
            names.add(name)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    process_group: int
    start_identity: str
    executable: Path
    executable_sha256: str | None

    def __post_init__(self) -> None:
        if self.pid <= 0:
            raise ValueError("process pid must be positive")
        if self.process_group <= 0:
            raise ValueError("process group must be positive")
        if not self.start_identity:
            raise ValueError("process start identity must not be empty")
        _validate_sha256(self.executable_sha256, name="executable SHA-256")


@dataclass(frozen=True, slots=True)
class RuntimeSessionRecord:
    schema_version: int
    session_id: str
    lifecycle: RuntimeLifecycleState
    emulator: EmulatorKind
    emulator_executable: Path
    emulator_sha256: str | None
    emulator_version: str | None
    rom_path: Path
    rom_sha256: str
    cpu: RuntimeCpu
    pid: int | None
    process_group: int | None
    process_start_identity: str | None
    debugger_host: str
    debugger_port: int
    display: str | None
    window_id: str | None
    session_root: Path
    last_completed_step: str | None
    last_completed_case: str | None

    def __post_init__(self) -> None:
        if self.schema_version != SESSION_SCHEMA_VERSION:
            raise ValueError("unsupported runtime session schema version")
        if not self.session_id:
            raise ValueError("session id must not be empty")
        if not self.debugger_host:
            raise ValueError("debugger host must not be empty")
        if not 1 <= self.debugger_port <= 65535:
            raise ValueError("debugger port must be between 1 and 65535")
        if self.pid is not None and self.pid <= 0:
            raise ValueError("process pid must be positive")
        if self.process_group is not None and self.process_group <= 0:
            raise ValueError("process group must be positive")
        _validate_sha256(self.emulator_sha256, name="emulator SHA-256")
        _validate_sha256(self.rom_sha256, name="ROM SHA-256")


@dataclass(frozen=True, slots=True)
class DoctorCheckResult:
    name: str
    passed: bool
    detail: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("doctor check name must not be empty")


@dataclass(frozen=True, slots=True)
class DoctorReport:
    emulator: EmulatorKind
    checks: tuple[DoctorCheckResult, ...]

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)
