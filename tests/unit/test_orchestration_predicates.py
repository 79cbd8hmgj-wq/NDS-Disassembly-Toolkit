from __future__ import annotations

from dataclasses import dataclass

import pytest

from nds_disassembly_toolkit.analysis.orchestration.predicates import (
    AllOf,
    AnyOf,
    MemoryEquals,
    MemoryMaskedEquals,
    PcEquals,
    PcInRange,
    PredicateObservation,
    RegisterEquals,
    RuntimeMemoryWrite,
    apply_guarded_write,
    wait_for_predicate,
)
from nds_disassembly_toolkit.analysis.runtime import (
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.errors import RuntimeScenarioError


@dataclass
class FakeContext:
    pc: int = 0x02000100
    registers: dict[str, int] | None = None
    memory: bytes = b"\x10\x20\x30\x40"

    def snapshot(self) -> RuntimeSnapshot:
        values = {"pc": self.pc, "cpsr": 0x13}
        values.update(self.registers or {})
        return RuntimeSnapshot(
            cpu=RuntimeCpu.ARM9,
            registers=RegisterSnapshot.from_mapping(values),
            stop=RuntimeStop(StopReasonKind.UNKNOWN),
        )

    def read_memory(self, address: int, length: int) -> bytes:
        return self.memory[:length]


def test_pc_and_register_predicates_report_observations() -> None:
    context = FakeContext(registers={"r0": 7})

    assert PcEquals(0x02000100).evaluate(context).satisfied
    assert PcInRange(0x02000100, 0x02000110).evaluate(context).satisfied
    assert RegisterEquals("r0", 7).evaluate(context).satisfied

    missing = RegisterEquals("r1", 7).evaluate(context)
    assert missing.satisfied is False
    assert missing.observed is None


def test_memory_exact_and_masked_predicates() -> None:
    context = FakeContext()

    assert MemoryEquals(0x02001000, b"\x10\x20").evaluate(context).satisfied
    assert MemoryEquals(0x02001000, b"\x10\x21").evaluate(context).satisfied is False
    assert MemoryMaskedEquals(
        0x02001000,
        expected=b"\x10\x00",
        mask=b"\xff\x00",
    ).evaluate(context).satisfied


def test_allof_and_anyof_preserve_child_observations() -> None:
    context = FakeContext(registers={"r0": 7})
    yes = PcEquals(0x02000100)
    no = RegisterEquals("r0", 8)

    all_observation = AllOf((yes, no)).evaluate(context)
    any_observation = AnyOf((yes, no)).evaluate(context)

    assert all_observation.satisfied is False
    assert any_observation.satisfied is True
    assert isinstance(all_observation.observed, tuple)
    assert len(all_observation.observed) == 2


def test_wait_for_predicate_is_bounded_and_returns_final_observation() -> None:
    times = iter([0.0, 0.0, 0.1, 0.2])
    sleeps: list[float] = []
    context = FakeContext()
    predicate = PcEquals(0x02000100)

    result = wait_for_predicate(
        predicate,
        context,
        timeout=1.0,
        poll_interval=0.1,
        monotonic=lambda: next(times),
        sleep=sleeps.append,
    )

    assert result.satisfied
    assert sleeps == []


def test_wait_for_predicate_timeout_reports_last_observation() -> None:
    current = [0.0]

    def monotonic() -> float:
        return current[0]

    def sleep(value: float) -> None:
        current[0] += value

    with pytest.raises(RuntimeScenarioError, match="last observed"):
        wait_for_predicate(
            PcEquals(0xDEADBEEF),
            FakeContext(),
            timeout=0.2,
            poll_interval=0.1,
            monotonic=monotonic,
            sleep=sleep,
        )


@dataclass
class FakeWriteSession:
    memory: bytes
    calls: list[tuple[object, ...]]

    def read_memory(self, address: int, length: int) -> bytes:
        self.calls.append(("read", address, length))
        return self.memory

    def write_memory(self, address: int, data: bytes) -> None:
        self.calls.append(("write", address, data))
        self.memory = data


def test_guarded_write_expected_before_mismatch_issues_no_write() -> None:
    session = FakeWriteSession(b"\x01\x02", [])

    with pytest.raises(RuntimeScenarioError, match="expected-before"):
        apply_guarded_write(
            session,
            RuntimeMemoryWrite(
                0x02001000,
                replacement=b"\x03\x04",
                expected_before=b"\xff\xff",
            ),
        )

    assert session.calls == [("read", 0x02001000, 2)]


def test_guarded_write_reads_before_writes_and_verifies_after() -> None:
    session = FakeWriteSession(b"\x01\x02", [])

    evidence = apply_guarded_write(
        session,
        RuntimeMemoryWrite(
            0x02001000,
            replacement=b"\x03\x04",
            expected_before=b"\x01\x02",
        ),
    )

    assert session.calls == [
        ("read", 0x02001000, 2),
        ("write", 0x02001000, b"\x03\x04"),
        ("read", 0x02001000, 2),
    ]
    assert evidence.before == b"\x01\x02"
    assert evidence.after == b"\x03\x04"
    assert len(evidence.before_sha256) == 64
    assert len(evidence.after_sha256) == 64


def test_guarded_write_failed_readback_raises() -> None:
    class BadReadbackSession(FakeWriteSession):
        reads: int = 0

        def read_memory(self, address: int, length: int) -> bytes:
            self.calls.append(("read", address, length))
            self.reads += 1
            return b"\x01\x02" if self.reads == 1 else b"\x99\x99"

    session = BadReadbackSession(b"\x01\x02", [])

    with pytest.raises(RuntimeScenarioError, match="read-back"):
        apply_guarded_write(
            session,
            RuntimeMemoryWrite(0x02001000, replacement=b"\x03\x04"),
        )
