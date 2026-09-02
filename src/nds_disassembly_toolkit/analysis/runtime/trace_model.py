from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path

from nds_disassembly_toolkit.analysis.model import (
    FunctionCandidate,
    InstructionSet,
    Symbol,
)
from nds_disassembly_toolkit.analysis.project.model import LocationAnnotation
from nds_disassembly_toolkit.analysis.runtime.model import (
    BreakpointKind,
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeSnapshot,
    RuntimeStop,
)

TRACE_SCHEMA_VERSION = 1
_U32_MAX = 0xFFFFFFFF
_MAX_STEP_LIMIT = 100000
_MAX_EVENT_LIMIT = 10000
_MAX_MEMORY_REGIONS = 32
_MAX_MEMORY_REGION_LENGTH = 0x01000000
_MAX_TOTAL_MEMORY_BYTES = 0x02000000
_HEX_DIGITS = frozenset("0123456789abcdef")


class TraceCaptureMode(StrEnum):
    STEP = "step"
    BREAKPOINT = "breakpoint"
    WATCHPOINT = "watchpoint"


class TraceEventRole(StrEnum):
    EVIDENCE = "evidence"
    CONTROL_ADVANCE = "control_advance"


class MemorySnapshotPhase(StrEnum):
    BEFORE = "before"
    AFTER = "after"


class TraceTermination(StrEnum):
    LIMIT = "limit"
    TARGET_EXIT = "target_exit"


def _validate_u32(value: int, *, name: str) -> None:
    if not 0 <= value <= _U32_MAX:
        raise ValueError(f"{name} must be an unsigned 32-bit value")


def _validate_fingerprint(value: str | None) -> None:
    if value is None:
        return
    if len(value) != 64 or any(character not in _HEX_DIGITS for character in value):
        raise ValueError("project fingerprint must be 64 lowercase hexadecimal characters")


@dataclass(frozen=True, slots=True)
class TraceMemoryRegion:
    ordinal: int
    address: int
    length: int
    label: str | None = None

    def __post_init__(self) -> None:
        if self.ordinal < 0:
            raise ValueError("memory region ordinal must be non-negative")
        _validate_u32(self.address, name="memory region address")
        if not 1 <= self.length <= _MAX_MEMORY_REGION_LENGTH:
            raise ValueError(
                "memory region length must be between 1 and 0x01000000 bytes"
            )
        if self.address + self.length > _U32_MAX + 1:
            raise ValueError("memory region extends outside the unsigned 32-bit address space")
        if self.label == "":
            raise ValueError("memory region label cannot be empty")


@dataclass(frozen=True, slots=True)
class TraceCaptureConfig:
    cpu: RuntimeCpu
    mode: TraceCaptureMode
    limit: int
    timeout: float
    condition_kind: BreakpointKind | None = None
    condition_address: int | None = None
    condition_length: int | None = None
    memory_regions: tuple[TraceMemoryRegion, ...] = ()
    label: str | None = None
    project_fingerprint: str | None = None
    toolkit_version: str | None = None
    trace_schema_version: int = TRACE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.trace_schema_version != TRACE_SCHEMA_VERSION:
            raise ValueError("trace schema version is unsupported")
        if self.timeout <= 0:
            raise ValueError("trace timeout must be positive")
        if self.label == "":
            raise ValueError("trace label cannot be empty")
        if self.toolkit_version == "":
            raise ValueError("toolkit version cannot be empty")
        _validate_fingerprint(self.project_fingerprint)

        if len(self.memory_regions) > _MAX_MEMORY_REGIONS:
            raise ValueError(f"trace may contain at most {_MAX_MEMORY_REGIONS} memory regions")
        expected_ordinals = tuple(range(len(self.memory_regions)))
        actual_ordinals = tuple(region.ordinal for region in self.memory_regions)
        if actual_ordinals != expected_ordinals:
            raise ValueError("memory region ordinals must be contiguous from zero")
        if sum(region.length for region in self.memory_regions) > _MAX_TOTAL_MEMORY_BYTES:
            raise ValueError("total configured memory bytes exceed 0x02000000")

        if self.mode is TraceCaptureMode.STEP:
            if not 1 <= self.limit <= _MAX_STEP_LIMIT:
                raise ValueError("step limit must be between 1 and 100000")
            if any(
                value is not None
                for value in (
                    self.condition_kind,
                    self.condition_address,
                    self.condition_length,
                )
            ):
                raise ValueError("step trace cannot define a stop condition")
            return

        if not 1 <= self.limit <= _MAX_EVENT_LIMIT:
            raise ValueError("event limit must be between 1 and 10000")
        if self.condition_address is None or self.condition_length is None:
            raise ValueError("breakpoint/watchpoint trace requires a complete stop condition")
        _validate_u32(self.condition_address, name="stop condition address")
        if self.condition_length <= 0:
            raise ValueError("stop condition length must be positive")
        if self.condition_address + self.condition_length > _U32_MAX + 1:
            raise ValueError("stop condition extends outside the unsigned 32-bit address space")

        if self.mode is TraceCaptureMode.BREAKPOINT:
            if self.condition_kind is not BreakpointKind.CODE:
                raise ValueError("breakpoint trace requires a code breakpoint")
            return

        if self.condition_kind not in {
            BreakpointKind.READ,
            BreakpointKind.WRITE,
            BreakpointKind.ACCESS,
        }:
            raise ValueError("watchpoint trace requires read, write, or access condition")


@dataclass(frozen=True, slots=True)
class TraceEvent:
    ordinal: int
    role: TraceEventRole
    cpu: RuntimeCpu
    pc: int
    cpsr: int
    instruction_set: InstructionSet
    stop: RuntimeStop
    registers: RegisterSnapshot

    def __post_init__(self) -> None:
        if self.ordinal < 0:
            raise ValueError("trace event ordinal must be non-negative")
        _validate_u32(self.pc, name="trace event pc")
        _validate_u32(self.cpsr, name="trace event cpsr")
        if self.registers.value("pc") != self.pc:
            raise ValueError("trace event pc does not match register snapshot")
        if self.registers.value("cpsr") != self.cpsr:
            raise ValueError("trace event cpsr does not match register snapshot")
        expected_instruction_set = (
            InstructionSet.THUMB if self.cpsr & (1 << 5) else InstructionSet.ARM
        )
        if self.instruction_set is not expected_instruction_set:
            raise ValueError("trace event instruction set does not match cpsr")

    @classmethod
    def from_snapshot(
        cls,
        ordinal: int,
        role: TraceEventRole,
        snapshot: RuntimeSnapshot,
    ) -> TraceEvent:
        return cls(
            ordinal=ordinal,
            role=role,
            cpu=snapshot.cpu,
            pc=snapshot.pc,
            cpsr=snapshot.cpsr,
            instruction_set=snapshot.instruction_set,
            stop=snapshot.stop,
            registers=snapshot.registers,
        )


@dataclass(frozen=True, slots=True)
class MemorySnapshot:
    region: TraceMemoryRegion
    phase: MemorySnapshotPhase
    data: bytes
    sha256: str

    def __post_init__(self) -> None:
        if len(self.data) != self.region.length:
            raise ValueError("memory snapshot byte length does not match region")
        expected = sha256(self.data).hexdigest()
        if self.sha256 != expected:
            raise ValueError("memory snapshot sha256 does not match data")

    @classmethod
    def from_bytes(
        cls,
        region: TraceMemoryRegion,
        phase: MemorySnapshotPhase,
        data: bytes,
    ) -> MemorySnapshot:
        payload = bytes(data)
        return cls(
            region=region,
            phase=phase,
            data=payload,
            sha256=sha256(payload).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class TraceSummary:
    trace: Path
    cpu: RuntimeCpu
    capture_mode: TraceCaptureMode
    evidence_events: int
    control_events: int
    memory_regions: int
    terminated_by: TraceTermination
    project_fingerprint: str | None

    def __post_init__(self) -> None:
        if self.evidence_events < 0 or self.control_events < 0:
            raise ValueError("trace event counts must be non-negative")
        if self.memory_regions < 0:
            raise ValueError("trace memory region count must be non-negative")
        _validate_fingerprint(self.project_fingerprint)


@dataclass(frozen=True, slots=True)
class AlignedMemoryValueChange:
    address: int
    width: int
    before: int
    after: int

    def __post_init__(self) -> None:
        _validate_u32(self.address, name="aligned memory value address")
        if self.width not in {2, 4}:
            raise ValueError("aligned memory value width must be 2 or 4")
        if self.address % self.width:
            raise ValueError("aligned memory value address is misaligned")
        maximum = (1 << (self.width * 8)) - 1
        if not 0 <= self.before <= maximum or not 0 <= self.after <= maximum:
            raise ValueError("aligned memory value is outside its declared width")
        if self.before == self.after:
            raise ValueError("aligned memory value change must change value")


@dataclass(frozen=True, slots=True)
class MemoryChange:
    region_ordinal: int
    address: int
    before: bytes
    after: bytes
    values16: tuple[AlignedMemoryValueChange, ...] = ()
    values32: tuple[AlignedMemoryValueChange, ...] = ()

    def __post_init__(self) -> None:
        if self.region_ordinal < 0:
            raise ValueError("memory change region ordinal must be non-negative")
        _validate_u32(self.address, name="memory change address")
        if not self.before or len(self.before) != len(self.after):
            raise ValueError("memory change byte ranges must be non-empty and equal length")
        if self.before == self.after:
            raise ValueError("memory change must contain changed bytes")
        if self.address + len(self.before) > _U32_MAX + 1:
            raise ValueError("memory change extends outside the unsigned 32-bit address space")
        if any(value.width != 2 for value in self.values16):
            raise ValueError("values16 entries must be 2-byte changes")
        if any(value.width != 4 for value in self.values32):
            raise ValueError("values32 entries must be 4-byte changes")


@dataclass(frozen=True, slots=True)
class TraceEventComponentCorrelation:
    component: str
    functions: tuple[FunctionCandidate, ...]
    symbols: tuple[Symbol, ...]
    annotation: LocationAnnotation | None


@dataclass(frozen=True, slots=True)
class TraceEventCorrelation:
    pc: int
    instruction_set: InstructionSet
    candidates: tuple[TraceEventComponentCorrelation, ...]
    ambiguous: bool
    resolved_function: FunctionCandidate | None


@dataclass(frozen=True, slots=True)
class TraceAddressHit:
    cpu: RuntimeCpu
    pc: int
    instruction_set: InstructionSet
    count: int
    frequency: float

    def __post_init__(self) -> None:
        _validate_u32(self.pc, name="trace address hit pc")
        if self.count <= 0:
            raise ValueError("trace address hit count must be positive")
        if not 0.0 <= self.frequency <= 1.0:
            raise ValueError("trace address hit frequency must be between zero and one")


@dataclass(frozen=True, slots=True)
class TraceAddressInspection:
    hit: TraceAddressHit
    correlation: TraceEventCorrelation | None


@dataclass(frozen=True, slots=True)
class TraceMemoryRegionInspection:
    region: TraceMemoryRegion
    before_sha256: str
    after_sha256: str
    changed_ranges: int
    changed_bytes: int

    def __post_init__(self) -> None:
        if self.changed_ranges < 0 or self.changed_bytes < 0:
            raise ValueError("trace memory change counts must be non-negative")


@dataclass(frozen=True, slots=True)
class TraceInspection:
    config: TraceCaptureConfig
    trace_schema_version: int
    capture_status: str
    events: int
    evidence_events: int
    control_events: int
    addresses: tuple[TraceAddressInspection, ...]
    memory_regions: tuple[TraceMemoryRegionInspection, ...]
    integrity_ok: bool

    def __post_init__(self) -> None:
        if self.trace_schema_version <= 0:
            raise ValueError("trace inspection schema version must be positive")
        if not self.capture_status:
            raise ValueError("trace inspection capture status must not be empty")
        if min(self.events, self.evidence_events, self.control_events) < 0:
            raise ValueError("trace inspection event counts must be non-negative")
        if self.evidence_events + self.control_events != self.events:
            raise ValueError("trace inspection event role counts must equal event count")


@dataclass(frozen=True, slots=True)
class TraceAddressDelta:
    cpu: RuntimeCpu
    pc: int
    instruction_set: InstructionSet
    baseline_hits: int
    target_hits: int
    baseline_frequency: float
    target_frequency: float
    frequency_delta: float
    classification: str

    def __post_init__(self) -> None:
        _validate_u32(self.pc, name="trace address delta pc")
        if self.baseline_hits < 0 or self.target_hits < 0:
            raise ValueError("trace address delta hit counts must be non-negative")
        if self.baseline_hits == 0 and self.target_hits == 0:
            raise ValueError("trace address delta requires at least one hit")
        if not 0.0 <= self.baseline_frequency <= 1.0:
            raise ValueError("baseline trace frequency must be between zero and one")
        if not 0.0 <= self.target_frequency <= 1.0:
            raise ValueError("target trace frequency must be between zero and one")
        if self.classification not in {"baseline_only", "target_only", "shared"}:
            raise ValueError("trace address delta classification is invalid")


@dataclass(frozen=True, slots=True)
class TraceDiffReport:
    baseline_config: TraceCaptureConfig
    target_config: TraceCaptureConfig
    target_identity_verified: bool
    address_deltas: tuple[TraceAddressDelta, ...]
