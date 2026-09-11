from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.orchestration.background import (
    detached_process_is_owned,
    spawn_detached_process,
    stop_detached_process,
)
from nds_disassembly_toolkit.errors import RuntimeLaunchError


def test_spawn_detached_process_proves_ownership_and_redirects_output(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "job.log"
    lease = spawn_detached_process(
        [sys.executable, "-c", "print('hello-from-child', flush=True)"],
        log_path=log_path,
    )
    try:
        assert lease.pid > 0
        assert lease.process_group > 0
        assert lease.start_identity
        for _ in range(200):
            if log_path.exists() and "hello-from-child" in log_path.read_text():
                break
            time.sleep(0.01)
        assert "hello-from-child" in log_path.read_text(encoding="utf-8")
    finally:
        stop_detached_process(lease, grace_seconds=1.0)


def test_spawn_detached_process_long_running_is_owned(tmp_path: Path) -> None:
    lease = spawn_detached_process(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        log_path=tmp_path / "job.log",
    )
    try:
        assert detached_process_is_owned(lease) is True
    finally:
        stop_detached_process(lease, grace_seconds=1.0)


def test_spawn_detached_process_raises_for_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(RuntimeLaunchError):
        spawn_detached_process(
            ["/definitely/not/a/real/executable-xyz"],
            log_path=tmp_path / "job.log",
        )


def test_spawn_detached_process_rejects_non_positive_timeout(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="establish_timeout"):
        spawn_detached_process(
            [sys.executable, "-c", "pass"],
            log_path=tmp_path / "job.log",
            establish_timeout=0,
        )


def test_stop_detached_process_terminates_owned_process(tmp_path: Path) -> None:
    lease = spawn_detached_process(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        log_path=tmp_path / "job.log",
    )
    assert stop_detached_process(lease, grace_seconds=1.0) is True
    assert detached_process_is_owned(lease) is False


def test_stop_detached_process_is_a_no_op_for_unowned_lease(tmp_path: Path) -> None:
    from nds_disassembly_toolkit.analysis.orchestration.background import (
        DetachedProcessLease,
    )

    fake_lease = DetachedProcessLease(
        pid=1,
        process_group=1,
        start_identity="not-the-real-identity",
        executable=Path("/usr/bin/nonexistent"),
    )
    assert stop_detached_process(fake_lease) is False


def test_stop_detached_process_rejects_negative_grace_seconds(tmp_path: Path) -> None:
    lease = spawn_detached_process(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        log_path=tmp_path / "job.log",
    )
    try:
        with pytest.raises(ValueError, match="grace_seconds"):
            stop_detached_process(lease, grace_seconds=-1.0)
    finally:
        stop_detached_process(lease, grace_seconds=1.0)
