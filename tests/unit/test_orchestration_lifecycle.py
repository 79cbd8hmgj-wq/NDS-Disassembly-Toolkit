from __future__ import annotations

from itertools import pairwise

import pytest

from nds_disassembly_toolkit.analysis.orchestration.model import (
    RuntimeLifecycleState,
    validate_lifecycle_transition,
)
from nds_disassembly_toolkit.errors import RuntimeLifecycleError


def test_forward_launch_sequence_is_legal() -> None:
    sequence = [
        RuntimeLifecycleState.CREATED,
        RuntimeLifecycleState.LAUNCHING,
        RuntimeLifecycleState.WAITING_FOR_RUNTIME,
        RuntimeLifecycleState.READY,
        RuntimeLifecycleState.RUNNING,
        RuntimeLifecycleState.READY,
        RuntimeLifecycleState.STOPPING,
        RuntimeLifecycleState.CLOSED,
    ]
    for current, new in pairwise(sequence):
        validate_lifecycle_transition(current, new)


def test_reaffirming_the_current_state_is_a_no_op() -> None:
    for state in RuntimeLifecycleState:
        validate_lifecycle_transition(state, state)


@pytest.mark.parametrize(
    ("current", "new"),
    [
        (RuntimeLifecycleState.CREATED, RuntimeLifecycleState.RUNNING),
        (RuntimeLifecycleState.CREATED, RuntimeLifecycleState.READY),
        (RuntimeLifecycleState.READY, RuntimeLifecycleState.LAUNCHING),
        (RuntimeLifecycleState.RUNNING, RuntimeLifecycleState.LAUNCHING),
        (RuntimeLifecycleState.CLOSED, RuntimeLifecycleState.RUNNING),
        (RuntimeLifecycleState.CLOSED, RuntimeLifecycleState.STOPPING),
        (RuntimeLifecycleState.STOPPING, RuntimeLifecycleState.RUNNING),
    ],
)
def test_illegal_transitions_are_rejected(
    current: RuntimeLifecycleState,
    new: RuntimeLifecycleState,
) -> None:
    with pytest.raises(RuntimeLifecycleError, match="illegal runtime lifecycle transition"):
        validate_lifecycle_transition(current, new)


def test_stopping_and_failed_are_reachable_from_every_non_terminal_state() -> None:
    for state in RuntimeLifecycleState:
        if state in {RuntimeLifecycleState.CLOSED}:
            continue
        validate_lifecycle_transition(state, RuntimeLifecycleState.FAILED)
    for state in RuntimeLifecycleState:
        if state in {RuntimeLifecycleState.CLOSED, RuntimeLifecycleState.FAILED}:
            continue
        validate_lifecycle_transition(state, RuntimeLifecycleState.STOPPING)


def test_failed_session_can_still_be_stopped_for_cleanup() -> None:
    # A launch failure after the emulator forked leaves an orphaned process;
    # the watchdog/recovery path must still be able to reap it.
    validate_lifecycle_transition(RuntimeLifecycleState.FAILED, RuntimeLifecycleState.STOPPING)


def test_failed_session_can_be_relaunched_for_recovery() -> None:
    # A dead-process session marked FAILED by the watchdog must be able to
    # relaunch from a checkpoint rather than being permanently stuck.
    validate_lifecycle_transition(RuntimeLifecycleState.FAILED, RuntimeLifecycleState.LAUNCHING)


def test_closed_is_terminal() -> None:
    for state in RuntimeLifecycleState:
        if state is RuntimeLifecycleState.CLOSED:
            continue
        with pytest.raises(RuntimeLifecycleError):
            validate_lifecycle_transition(RuntimeLifecycleState.CLOSED, state)
