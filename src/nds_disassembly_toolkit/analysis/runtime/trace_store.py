from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from nds_disassembly_toolkit.analysis.model import InstructionSet
from nds_disassembly_toolkit.analysis.runtime.model import (
    BreakpointKind,
    RegisterSnapshot,
    RuntimeCpu,
    RuntimeStop,
    StopReasonKind,
)
from nds_disassembly_toolkit.analysis.runtime.trace_model import (
    TRACE_SCHEMA_VERSION,
    MemorySnapshot,
    MemorySnapshotPhase,
    TraceCaptureConfig,
    TraceCaptureMode,
    TraceEvent,
    TraceEventRole,
    TraceMemoryRegion,
    TraceSummary,
    TraceTermination,
)
from nds_disassembly_toolkit.errors import RuntimeTraceFormatError

_REQUIRED_TABLES = frozenset(
    {
        "metadata",
        "capture_config",
        "events",
        "memory_regions",
        "memory_snapshots",
    }
)

_SCHEMA_SQL = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE capture_config (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    limit_count INTEGER NOT NULL CHECK(limit_count > 0),
    timeout REAL NOT NULL CHECK(timeout > 0),
    condition_kind TEXT,
    condition_address INTEGER,
    condition_length INTEGER
);

CREATE TABLE events (
    ordinal INTEGER PRIMARY KEY CHECK(ordinal >= 0),
    role TEXT NOT NULL,
    pc INTEGER NOT NULL CHECK(pc >= 0),
    cpsr INTEGER NOT NULL CHECK(cpsr >= 0),
    instruction_set TEXT NOT NULL,
    stop_kind TEXT NOT NULL,
    signal INTEGER,
    stop_address INTEGER,
    raw_stop TEXT NOT NULL,
    registers_json TEXT NOT NULL
);

CREATE TABLE memory_regions (
    id INTEGER PRIMARY KEY,
    ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal >= 0),
    label TEXT,
    base_address INTEGER NOT NULL CHECK(base_address >= 0),
    length INTEGER NOT NULL CHECK(length > 0)
);

CREATE TABLE memory_snapshots (
    region_id INTEGER NOT NULL,
    phase TEXT NOT NULL,
    data BLOB NOT NULL,
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    PRIMARY KEY(region_id, phase),
    FOREIGN KEY(region_id) REFERENCES memory_regions(id) ON DELETE CASCADE
);
"""


def _configure(connection: sqlite3.Connection, *, read_only: bool) -> None:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        connection.execute("PRAGMA journal_mode = DELETE")


def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        rows = connection.execute("SELECT key, value FROM metadata").fetchall()
    except sqlite3.Error as exc:
        raise RuntimeTraceFormatError("runtime trace metadata is missing") from exc
    return {str(row["key"]): str(row["value"]) for row in rows}


def _validate_schema(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    except sqlite3.Error as exc:
        raise RuntimeTraceFormatError("cannot inspect runtime trace schema") from exc
    tables = {str(row["name"]) for row in rows}
    missing = _REQUIRED_TABLES - tables
    if missing:
        raise RuntimeTraceFormatError(
            "runtime trace schema is incomplete: " + ", ".join(sorted(missing))
        )

    metadata = _metadata(connection)
    version_text = metadata.get("trace_schema_version")
    if version_text is None:
        raise RuntimeTraceFormatError("runtime trace schema version is missing")
    try:
        version = int(version_text)
    except ValueError as exc:
        raise RuntimeTraceFormatError("runtime trace schema version is malformed") from exc
    if version != TRACE_SCHEMA_VERSION:
        raise RuntimeTraceFormatError(
            f"runtime trace schema version {version} is unsupported"
        )
    return metadata


def _registers_json(registers: RegisterSnapshot) -> str:
    return json.dumps(
        [{"name": name, "value": value} for name, value in registers.values],
        sort_keys=True,
        separators=(",", ":"),
    )


def _registers_from_json(value: str) -> RegisterSnapshot:
    try:
        decoded = json.loads(value)
        if not isinstance(decoded, list):
            raise ValueError("register payload is not a list")
        entries: list[tuple[str, int]] = []
        for item in decoded:
            if not isinstance(item, dict):
                raise ValueError("register entry is not an object")
            name = item.get("name")
            register_value = item.get("value")
            if not isinstance(name, str) or isinstance(register_value, bool) or not isinstance(
                register_value, int
            ):
                raise ValueError("register entry is invalid")
            entries.append((name, register_value))
        return RegisterSnapshot(tuple(entries))
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeTraceFormatError("runtime trace register payload is invalid") from exc


def _event_from_row(row: sqlite3.Row, cpu: RuntimeCpu) -> TraceEvent:
    try:
        stop = RuntimeStop(
            kind=StopReasonKind(str(row["stop_kind"])),
            signal=None if row["signal"] is None else int(row["signal"]),
            address=None if row["stop_address"] is None else int(row["stop_address"]),
            raw=None if str(row["raw_stop"]) == "" else str(row["raw_stop"]),
        )
        return TraceEvent(
            ordinal=int(row["ordinal"]),
            role=TraceEventRole(str(row["role"])),
            cpu=cpu,
            pc=int(row["pc"]),
            cpsr=int(row["cpsr"]),
            instruction_set=InstructionSet(str(row["instruction_set"])),
            stop=stop,
            registers=_registers_from_json(str(row["registers_json"])),
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeTraceFormatError("runtime trace event record is invalid") from exc


class TraceStore:
    def __init__(
        self,
        destination: Path,
        working_path: Path,
        connection: sqlite3.Connection,
        config: TraceCaptureConfig,
        *,
        read_only: bool,
        finalized: bool,
    ) -> None:
        self._destination = destination
        self._working_path = working_path
        self._connection: sqlite3.Connection | None = connection
        self._config = config
        self._read_only = read_only
        self._finalized = finalized

    @classmethod
    @contextmanager
    def create_atomic(
        cls,
        destination: Path,
        config: TraceCaptureConfig,
    ) -> Iterator[TraceStore]:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.unlink(missing_ok=True)
        connection: sqlite3.Connection | None = None
        store: TraceStore | None = None
        try:
            connection = sqlite3.connect(temporary)
            _configure(connection, read_only=False)
            connection.executescript(_SCHEMA_SQL)
            metadata: list[tuple[str, str]] = [
                ("trace_schema_version", str(config.trace_schema_version)),
                ("toolkit_version", config.toolkit_version or ""),
                ("cpu", config.cpu.value),
                ("capture_mode", config.mode.value),
                ("capture_status", "incomplete"),
            ]
            if config.label is not None:
                metadata.append(("label", config.label))
            if config.project_fingerprint is not None:
                metadata.append(("project_fingerprint", config.project_fingerprint))
            connection.executemany(
                "INSERT INTO metadata(key, value) VALUES(?, ?)",
                metadata,
            )
            connection.execute(
                """
                INSERT INTO capture_config(
                    id, limit_count, timeout,
                    condition_kind, condition_address, condition_length
                ) VALUES(1, ?, ?, ?, ?, ?)
                """,
                (
                    config.limit,
                    config.timeout,
                    None if config.condition_kind is None else config.condition_kind.value,
                    config.condition_address,
                    config.condition_length,
                ),
            )
            connection.executemany(
                """
                INSERT INTO memory_regions(id, ordinal, label, base_address, length)
                VALUES(?, ?, ?, ?, ?)
                """,
                tuple(
                    (
                        region.ordinal + 1,
                        region.ordinal,
                        region.label,
                        region.address,
                        region.length,
                    )
                    for region in config.memory_regions
                ),
            )
            connection.commit()
            store = cls(
                path,
                temporary,
                connection,
                config,
                read_only=False,
                finalized=False,
            )
            connection = None
            yield store
        except sqlite3.Error as exc:
            raise RuntimeTraceFormatError("cannot create runtime trace database") from exc
        finally:
            if connection is not None:
                connection.close()
            if store is not None and store._connection is not None:
                store.close()
            if store is None or not store._finalized:
                temporary.unlink(missing_ok=True)

    @classmethod
    def open(cls, path: Path) -> TraceStore:
        trace_path = Path(path)
        if not trace_path.is_file():
            raise RuntimeTraceFormatError("runtime trace file is missing")
        connection: sqlite3.Connection | None = None
        try:
            uri = trace_path.resolve().as_uri() + "?mode=ro"
            connection = sqlite3.connect(uri, uri=True)
            _configure(connection, read_only=True)
            metadata = _validate_schema(connection)
            if metadata.get("capture_status") != "complete":
                raise RuntimeTraceFormatError("runtime trace capture is incomplete")
            config = cls._load_config(connection, metadata)
            store = cls(
                trace_path,
                trace_path,
                connection,
                config,
                read_only=True,
                finalized=True,
            )
            store.validate_complete()
            return store
        except RuntimeTraceFormatError:
            if connection is not None:
                connection.close()
            raise
        except (sqlite3.Error, ValueError) as exc:
            if connection is not None:
                connection.close()
            raise RuntimeTraceFormatError("cannot open runtime trace") from exc

    @staticmethod
    def _load_regions(connection: sqlite3.Connection) -> tuple[TraceMemoryRegion, ...]:
        try:
            rows = connection.execute(
                """
                SELECT ordinal, label, base_address, length
                FROM memory_regions
                ORDER BY ordinal
                """
            ).fetchall()
            return tuple(
                TraceMemoryRegion(
                    ordinal=int(row["ordinal"]),
                    address=int(row["base_address"]),
                    length=int(row["length"]),
                    label=None if row["label"] is None else str(row["label"]),
                )
                for row in rows
            )
        except (sqlite3.Error, ValueError) as exc:
            raise RuntimeTraceFormatError("runtime trace memory regions are invalid") from exc

    @classmethod
    def _load_config(
        cls,
        connection: sqlite3.Connection,
        metadata: dict[str, str],
    ) -> TraceCaptureConfig:
        try:
            row = connection.execute(
                """
                SELECT limit_count, timeout, condition_kind,
                       condition_address, condition_length
                FROM capture_config
                WHERE id = 1
                """
            ).fetchone()
            if row is None:
                raise RuntimeTraceFormatError("runtime trace capture config is missing")
            condition_text = row["condition_kind"]
            toolkit_text = metadata.get("toolkit_version", "")
            return TraceCaptureConfig(
                cpu=RuntimeCpu(metadata["cpu"]),
                mode=TraceCaptureMode(metadata["capture_mode"]),
                limit=int(row["limit_count"]),
                timeout=float(row["timeout"]),
                condition_kind=(
                    None if condition_text is None else BreakpointKind(str(condition_text))
                ),
                condition_address=(
                    None
                    if row["condition_address"] is None
                    else int(row["condition_address"])
                ),
                condition_length=(
                    None
                    if row["condition_length"] is None
                    else int(row["condition_length"])
                ),
                memory_regions=cls._load_regions(connection),
                label=metadata.get("label"),
                project_fingerprint=metadata.get("project_fingerprint"),
                toolkit_version=None if toolkit_text == "" else toolkit_text,
                trace_schema_version=TRACE_SCHEMA_VERSION,
            )
        except KeyError as exc:
            raise RuntimeTraceFormatError("runtime trace metadata is incomplete") from exc
        except (sqlite3.Error, ValueError) as exc:
            raise RuntimeTraceFormatError("runtime trace capture config is invalid") from exc

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeTraceFormatError("runtime trace store is closed")
        return self._connection

    def _require_writable(self) -> sqlite3.Connection:
        if self._read_only:
            raise RuntimeTraceFormatError("runtime trace store is read-only")
        return self._require_connection()

    @property
    def config(self) -> TraceCaptureConfig:
        return self._config

    @property
    def summary(self) -> TraceSummary:
        connection = self._require_connection()
        metadata = _metadata(connection)
        if metadata.get("capture_status") != "complete":
            raise RuntimeTraceFormatError("runtime trace capture is incomplete")
        try:
            return TraceSummary(
                trace=self._destination,
                cpu=self._config.cpu,
                capture_mode=self._config.mode,
                evidence_events=int(metadata["evidence_events"]),
                control_events=int(metadata["control_events"]),
                memory_regions=len(self._config.memory_regions),
                terminated_by=TraceTermination(metadata["terminated_by"]),
                project_fingerprint=self._config.project_fingerprint,
            )
        except (KeyError, ValueError) as exc:
            raise RuntimeTraceFormatError("runtime trace summary is invalid") from exc

    def append_event(self, event: TraceEvent) -> None:
        connection = self._require_writable()
        if event.cpu is not self._config.cpu:
            raise RuntimeTraceFormatError("runtime trace event CPU does not match capture config")
        try:
            connection.execute(
                """
                INSERT INTO events(
                    ordinal, role, pc, cpsr, instruction_set,
                    stop_kind, signal, stop_address, raw_stop, registers_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.ordinal,
                    event.role.value,
                    event.pc,
                    event.cpsr,
                    event.instruction_set.value,
                    event.stop.kind.value,
                    event.stop.signal,
                    event.stop.address,
                    event.stop.raw or "",
                    _registers_json(event.registers),
                ),
            )
            connection.commit()
        except sqlite3.Error as exc:
            raise RuntimeTraceFormatError("cannot append runtime trace event") from exc

    def store_memory_snapshot(self, snapshot: MemorySnapshot) -> None:
        connection = self._require_writable()
        if snapshot.region not in self._config.memory_regions:
            raise RuntimeTraceFormatError("memory snapshot region is not configured")
        try:
            connection.execute(
                """
                INSERT INTO memory_snapshots(region_id, phase, data, sha256)
                VALUES(?, ?, ?, ?)
                """,
                (
                    snapshot.region.ordinal + 1,
                    snapshot.phase.value,
                    snapshot.data,
                    snapshot.sha256,
                ),
            )
            connection.commit()
        except sqlite3.Error as exc:
            raise RuntimeTraceFormatError("cannot store runtime memory snapshot") from exc

    def events(self) -> tuple[TraceEvent, ...]:
        connection = self._require_connection()
        try:
            rows = connection.execute(
                """
                SELECT ordinal, role, pc, cpsr, instruction_set,
                       stop_kind, signal, stop_address, raw_stop, registers_json
                FROM events
                ORDER BY ordinal
                """
            ).fetchall()
            return tuple(_event_from_row(row, self._config.cpu) for row in rows)
        except RuntimeTraceFormatError:
            raise
        except sqlite3.Error as exc:
            raise RuntimeTraceFormatError("cannot query runtime trace events") from exc

    def memory_regions(self) -> tuple[TraceMemoryRegion, ...]:
        return self._config.memory_regions

    def memory_snapshot(
        self,
        region_ordinal: int,
        phase: MemorySnapshotPhase,
    ) -> MemorySnapshot | None:
        connection = self._require_connection()
        region = next(
            (item for item in self._config.memory_regions if item.ordinal == region_ordinal),
            None,
        )
        if region is None:
            return None
        try:
            row = connection.execute(
                """
                SELECT data, sha256
                FROM memory_snapshots
                WHERE region_id = ? AND phase = ?
                """,
                (region_ordinal + 1, phase.value),
            ).fetchone()
            if row is None:
                return None
            return MemorySnapshot(
                region=region,
                phase=phase,
                data=bytes(row["data"]),
                sha256=str(row["sha256"]),
            )
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise RuntimeTraceFormatError("runtime memory snapshot is invalid") from exc

    def _validate_event_rows(self) -> tuple[int, int]:
        events = self.events()
        ordinals = tuple(event.ordinal for event in events)
        if ordinals != tuple(range(len(events))):
            raise RuntimeTraceFormatError("runtime trace event ordinals are not contiguous")
        if any(event.cpu is not self._config.cpu for event in events):
            raise RuntimeTraceFormatError("runtime trace event CPU does not match capture config")
        evidence = sum(event.role is TraceEventRole.EVIDENCE for event in events)
        control = sum(event.role is TraceEventRole.CONTROL_ADVANCE for event in events)
        return evidence, control

    def _validate_memory_snapshots(self) -> None:
        for region in self._config.memory_regions:
            before = self.memory_snapshot(region.ordinal, MemorySnapshotPhase.BEFORE)
            after = self.memory_snapshot(region.ordinal, MemorySnapshotPhase.AFTER)
            if before is None or after is None:
                raise RuntimeTraceFormatError(
                    "runtime trace memory snapshots are incomplete"
                )

    def validate_complete(self) -> None:
        connection = self._require_connection()
        metadata = _validate_schema(connection)
        if metadata.get("capture_status") != "complete":
            raise RuntimeTraceFormatError("runtime trace capture is incomplete")
        evidence, control = self._validate_event_rows()
        self._validate_memory_snapshots()
        try:
            if int(metadata["evidence_events"]) != evidence or int(
                metadata["control_events"]
            ) != control:
                raise RuntimeTraceFormatError("runtime trace summary counts are inconsistent")
            TraceTermination(metadata["terminated_by"])
        except KeyError as exc:
            raise RuntimeTraceFormatError("runtime trace summary is incomplete") from exc
        except ValueError as exc:
            raise RuntimeTraceFormatError("runtime trace summary is invalid") from exc

    def finalize(self, summary: TraceSummary) -> None:
        connection = self._require_writable()
        if summary.trace != self._destination:
            raise RuntimeTraceFormatError("runtime trace summary path does not match destination")
        if summary.cpu is not self._config.cpu or summary.capture_mode is not self._config.mode:
            raise RuntimeTraceFormatError("runtime trace summary does not match capture config")
        if summary.project_fingerprint != self._config.project_fingerprint:
            raise RuntimeTraceFormatError("runtime trace summary fingerprint does not match config")
        if summary.memory_regions != len(self._config.memory_regions):
            raise RuntimeTraceFormatError(
                "runtime trace summary memory count does not match config"
            )

        evidence, control = self._validate_event_rows()
        if summary.evidence_events != evidence or summary.control_events != control:
            raise RuntimeTraceFormatError("runtime trace summary counts do not match stored events")
        self._validate_memory_snapshots()

        try:
            connection.executemany(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES(?, ?)",
                (
                    ("capture_status", "complete"),
                    ("evidence_events", str(evidence)),
                    ("control_events", str(control)),
                    ("terminated_by", summary.terminated_by.value),
                ),
            )
            connection.commit()
            row = connection.execute("PRAGMA integrity_check").fetchone()
            if row is None or str(row[0]).lower() != "ok":
                raise RuntimeTraceFormatError("runtime trace database integrity check failed")
        except RuntimeTraceFormatError:
            raise
        except sqlite3.Error as exc:
            raise RuntimeTraceFormatError("cannot finalize runtime trace") from exc

        self.close()
        try:
            self._working_path.replace(self._destination)
        except OSError:
            raise
        self._finalized = True

    def close(self) -> None:
        if self._connection is None:
            return
        connection = self._connection
        self._connection = None
        with suppress(sqlite3.Error):
            connection.close()
