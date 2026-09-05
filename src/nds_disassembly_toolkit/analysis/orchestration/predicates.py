from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Protocol, cast

from nds_disassembly_toolkit.analysis.runtime.model import RuntimeSnapshot
from nds_disassembly_toolkit.errors import RuntimeScenarioError


@dataclass(frozen=True, slots=True)
class PredicateObservation:
    satisfied: bool
    description: str
    observed: object


class RuntimePredicate(Protocol):
    def evaluate(self, context: object) -> PredicateObservation: ...


def _snapshot(context: object) -> RuntimeSnapshot:
    method = getattr(context, "snapshot", None)
    if not callable(method):
        raise RuntimeScenarioError("predicate context does not provide snapshot()")
    value = method()
    if not isinstance(value, RuntimeSnapshot):
        raise RuntimeScenarioError("predicate context returned an invalid runtime snapshot")
    return value


def _read_memory(context: object, address: int, length: int) -> bytes:
    method = getattr(context, "read_memory", None)
    if not callable(method):
        raise RuntimeScenarioError("predicate context does not provide read_memory()")
    value = method(address, length)
    if not isinstance(value, bytes):
        raise RuntimeScenarioError("predicate context returned invalid memory bytes")
    return value


def _bool_method(context: object, name: str) -> bool | None:
    method = getattr(context, name, None)
    if not callable(method):
        return None
    return bool(method())


@dataclass(frozen=True, slots=True)
class ProcessAlive:
    def evaluate(self, context: object) -> PredicateObservation:
        value = _bool_method(context, "process_alive")
        return PredicateObservation(
            satisfied=value is True,
            description="managed process is alive",
            observed=value,
        )


@dataclass(frozen=True, slots=True)
class DebuggerReachable:
    def evaluate(self, context: object) -> PredicateObservation:
        value = _bool_method(context, "debugger_reachable")
        return PredicateObservation(
            satisfied=value is True,
            description="runtime debugger is reachable",
            observed=value,
        )


@dataclass(frozen=True, slots=True)
class WindowReady:
    def evaluate(self, context: object) -> PredicateObservation:
        value = _bool_method(context, "window_ready")
        return PredicateObservation(
            satisfied=value is True,
            description="owned emulator window is ready",
            observed=value,
        )


@dataclass(frozen=True, slots=True)
class PcEquals:
    expected: int

    def __post_init__(self) -> None:
        if self.expected < 0:
            raise ValueError("PC value must be non-negative")

    def evaluate(self, context: object) -> PredicateObservation:
        observed = _snapshot(context).pc
        return PredicateObservation(
            satisfied=observed == self.expected,
            description=f"PC equals 0x{self.expected:08x}",
            observed=observed,
        )


@dataclass(frozen=True, slots=True)
class PcInRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError("PC range must be ordered and non-negative")

    def evaluate(self, context: object) -> PredicateObservation:
        observed = _snapshot(context).pc
        return PredicateObservation(
            satisfied=self.start <= observed <= self.end,
            description=f"PC is in 0x{self.start:08x}..0x{self.end:08x}",
            observed=observed,
        )


@dataclass(frozen=True, slots=True)
class RegisterEquals:
    register: str
    expected: int

    def __post_init__(self) -> None:
        if not self.register:
            raise ValueError("register name must not be empty")
        if self.expected < 0:
            raise ValueError("register value must be non-negative")

    def evaluate(self, context: object) -> PredicateObservation:
        observed = _snapshot(context).registers.value(self.register)
        return PredicateObservation(
            satisfied=observed == self.expected,
            description=f"{self.register} equals 0x{self.expected:x}",
            observed=observed,
        )


@dataclass(frozen=True, slots=True)
class MemoryEquals:
    address: int
    expected: bytes

    def __post_init__(self) -> None:
        if self.address < 0:
            raise ValueError("memory address must be non-negative")
        if not self.expected:
            raise ValueError("memory predicate bytes must not be empty")

    def evaluate(self, context: object) -> PredicateObservation:
        observed = _read_memory(context, self.address, len(self.expected))
        return PredicateObservation(
            satisfied=observed == self.expected,
            description=(
                f"memory 0x{self.address:08x} equals {self.expected.hex()}"
            ),
            observed=observed,
        )


@dataclass(frozen=True, slots=True)
class MemoryMaskedEquals:
    address: int
    expected: bytes
    mask: bytes

    def __post_init__(self) -> None:
        if self.address < 0:
            raise ValueError("memory address must be non-negative")
        if not self.expected or len(self.expected) != len(self.mask):
            raise ValueError("masked memory expected bytes and mask must have equal length")

    def evaluate(self, context: object) -> PredicateObservation:
        observed = _read_memory(context, self.address, len(self.expected))
        satisfied = len(observed) == len(self.expected) and all(
            (actual & mask) == (expected & mask)
            for actual, expected, mask in zip(
                observed,
                self.expected,
                self.mask,
                strict=True,
            )
        )
        return PredicateObservation(
            satisfied=satisfied,
            description=(
                f"masked memory 0x{self.address:08x} equals "
                f"{self.expected.hex()} mask {self.mask.hex()}"
            ),
            observed=observed,
        )


@dataclass(frozen=True, slots=True)
class AllOf:
    predicates: tuple[RuntimePredicate, ...]

    def evaluate(self, context: object) -> PredicateObservation:
        observations = tuple(predicate.evaluate(context) for predicate in self.predicates)
        return PredicateObservation(
            satisfied=all(item.satisfied for item in observations),
            description="all predicates are satisfied",
            observed=observations,
        )


@dataclass(frozen=True, slots=True)
class AnyOf:
    predicates: tuple[RuntimePredicate, ...]

    def evaluate(self, context: object) -> PredicateObservation:
        observations = tuple(predicate.evaluate(context) for predicate in self.predicates)
        return PredicateObservation(
            satisfied=any(item.satisfied for item in observations),
            description="at least one predicate is satisfied",
            observed=observations,
        )


def wait_for_predicate(
    predicate: RuntimePredicate,
    context: object,
    *,
    timeout: float,
    poll_interval: float,
    monotonic: callable = time.monotonic,
    sleep: callable = time.sleep,
) -> PredicateObservation:
    if timeout <= 0:
        raise ValueError("predicate timeout must be positive")
    if poll_interval <= 0:
        raise ValueError("predicate poll interval must be positive")

    start = cast(float, monotonic())
    last: PredicateObservation | None = None
    while True:
        last = predicate.evaluate(context)
        if last.satisfied:
            return last
        now = cast(float, monotonic())
        elapsed = now - start
        if elapsed >= timeout:
            raise RuntimeScenarioError(
                f"predicate timed out: {last.description}; last observed={last.observed!r}"
            )
        sleep(min(poll_interval, timeout - elapsed))


@dataclass(frozen=True, slots=True)
class RuntimeMemoryWrite:
    address: int
    replacement: bytes
    expected_before: bytes | None = None
    verify_after: bool = True

    def __post_init__(self) -> None:
        if self.address < 0:
            raise ValueError("memory write address must be non-negative")
        if not self.replacement:
            raise ValueError("memory write replacement must not be empty")
        if (
            self.expected_before is not None
            and len(self.expected_before) != len(self.replacement)
        ):
            raise ValueError("expected-before length must match replacement length")


@dataclass(frozen=True, slots=True)
class GuardedWriteEvidence:
    address: int
    before: bytes
    after: bytes
    replacement: bytes
    before_sha256: str
    after_sha256: str


class _WriteSession(Protocol):
    def read_memory(self, address: int, length: int) -> bytes: ...

    def write_memory(self, address: int, data: bytes) -> None: ...


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apply_guarded_write(
    session: _WriteSession,
    write: RuntimeMemoryWrite,
) -> GuardedWriteEvidence:
    length = len(write.replacement)
    before = session.read_memory(write.address, length)
    if len(before) != length:
        raise RuntimeScenarioError("guarded write read-before returned unexpected length")
    if write.expected_before is not None and before != write.expected_before:
        raise RuntimeScenarioError("guarded write expected-before bytes do not match")

    session.write_memory(write.address, write.replacement)

    if write.verify_after:
        after = session.read_memory(write.address, length)
        if len(after) != length or after != write.replacement:
            raise RuntimeScenarioError("guarded write read-back verification failed")
    else:
        after = write.replacement

    return GuardedWriteEvidence(
        address=write.address,
        before=before,
        after=after,
        replacement=write.replacement,
        before_sha256=_digest(before),
        after_sha256=_digest(after),
    )
