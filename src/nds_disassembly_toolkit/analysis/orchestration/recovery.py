from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Protocol

from nds_disassembly_toolkit.analysis.orchestration.checkpoint import (
    CheckpointContext,
    restore_checkpoint,
)
from nds_disassembly_toolkit.analysis.orchestration.model import (
    EmulatorCapabilities,
    LaunchSpec,
    RuntimeLifecycleState,
    RuntimeSessionRecord,
)
from nds_disassembly_toolkit.analysis.orchestration.process import (
    process_is_owned,
    spawn_owned_process,
    transition_session,
)
from nds_disassembly_toolkit.analysis.runtime.model import RuntimeCpu
from nds_disassembly_toolkit.errors import RuntimeRecoveryError


class RecoveryBackend(Protocol):
    @property
    def capabilities(self) -> EmulatorCapabilities: ...

    def build_launch_spec(
        self,
        *,
        executable: Path,
        rom: Path,
        cpu: RuntimeCpu,
        debugger_host: str,
        debugger_port: int,
        session_root: Path,
        display: str | None,
    ) -> LaunchSpec: ...


def relaunch_dead_session(
    record: RuntimeSessionRecord,
    backend: RecoveryBackend,
    *,
    display: str | None = None,
) -> RuntimeSessionRecord:
    """Spawn a fresh emulator process for a session whose owned process has
    died, reusing the session's identity (session_root, session_id, and
    debugger port) so existing checkpoints and callers keep addressing the
    same session.

    Raises ``RuntimeRecoveryError`` if the process can still be proven
    alive (relaunching a live session would orphan it) or if the session
    was deliberately CLOSED rather than having crashed - a closed session
    must not be silently resurrected.

    The session is driven through FAILED before relaunching regardless of
    its prior persisted state, so callers (the watchdog included) do not
    need to have already marked it FAILED themselves.
    """
    if process_is_owned(record):
        raise RuntimeRecoveryError(
            "runtime session process is still alive; relaunch is unnecessary"
        )
    if record.lifecycle is RuntimeLifecycleState.CLOSED:
        raise RuntimeRecoveryError(
            "runtime session was deliberately closed; refusing to relaunch it"
        )
    reset = replace(
        record,
        pid=None,
        process_group=None,
        process_start_identity=None,
        window_id=None,
    )
    if reset.lifecycle is not RuntimeLifecycleState.FAILED:
        reset = transition_session(reset, RuntimeLifecycleState.FAILED)
    launch = backend.build_launch_spec(
        executable=reset.emulator_executable,
        rom=reset.rom_path,
        cpu=reset.cpu,
        debugger_host=reset.debugger_host,
        debugger_port=reset.debugger_port,
        session_root=reset.session_root,
        display=display,
    )
    return spawn_owned_process(reset, launch)


def recover_session_from_checkpoint(
    record: RuntimeSessionRecord,
    backend: RecoveryBackend,
    *,
    checkpoint_context: CheckpointContext,
    checkpoint_path: Path,
    display: str | None = None,
    read_memory: Callable[[int, int], bytes] | None = None,
) -> RuntimeSessionRecord:
    """Relaunch a dead session's process and restore it from a known-good
    checkpoint in one bounded step.

    ``checkpoint_path`` must already have been validated as trustworthy by
    the caller (e.g. the newest checkpoint that passed
    ``validate_checkpoint``) - this function does not choose a checkpoint on
    its own, it only performs the relaunch-then-restore mechanics.
    """
    running = relaunch_dead_session(record, backend, display=display)
    restore_checkpoint(checkpoint_context, checkpoint_path, read_memory=read_memory)
    return running
