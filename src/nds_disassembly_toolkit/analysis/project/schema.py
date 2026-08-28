from __future__ import annotations

import sqlite3

from nds_disassembly_toolkit.errors import AnalysisProjectError

SCHEMA_VERSION = 1
ANALYSIS_MODEL_VERSION = 1
REQUIRED_TABLES = frozenset(
    {
        "metadata",
        "components",
        "location_annotations",
        "functions",
        "strings",
        "generated_symbols",
        "xrefs",
    }
)

_SCHEMA_SQL = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE components (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    base_address INTEGER NOT NULL CHECK(base_address >= 0),
    size INTEGER NOT NULL CHECK(size >= 0),
    sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
    toolkit_version TEXT,
    analyzed_at TEXT
);

CREATE TABLE location_annotations (
    component_id INTEGER NOT NULL,
    address INTEGER NOT NULL CHECK(address >= 0),
    name_override TEXT,
    comment TEXT,
    tags_json TEXT NOT NULL,
    bookmarked INTEGER NOT NULL CHECK(bookmarked IN (0, 1)),
    PRIMARY KEY(component_id, address),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE TABLE functions (
    component_id INTEGER NOT NULL,
    address INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    instruction_set TEXT NOT NULL,
    confidence TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY(component_id, address, instruction_set),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE TABLE strings (
    component_id INTEGER NOT NULL,
    address INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY(component_id, address),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE TABLE generated_symbols (
    component_id INTEGER NOT NULL,
    address INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    instruction_set TEXT,
    confidence TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY(component_id, address, name),
    FOREIGN KEY(component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE TABLE xrefs (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    source_component_id INTEGER NOT NULL,
    source_address INTEGER NOT NULL,
    source_function_address INTEGER,
    source_instruction_set TEXT,
    target_address INTEGER NOT NULL,
    target_instruction_set TEXT,
    FOREIGN KEY(source_component_id) REFERENCES components(id) ON DELETE CASCADE
);

CREATE INDEX idx_symbol_name ON generated_symbols(name);
CREATE INDEX idx_xref_source ON xrefs(source_component_id, source_address);
CREATE INDEX idx_xref_target ON xrefs(target_address);
"""


def configure_connection(connection: sqlite3.Connection, *, read_only: bool) -> None:
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        connection.execute("PRAGMA journal_mode = DELETE")


def create_schema(connection: sqlite3.Connection) -> None:
    try:
        connection.executescript(_SCHEMA_SQL)
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            (
                ("schema_version", str(SCHEMA_VERSION)),
                ("analysis_model_version", str(ANALYSIS_MODEL_VERSION)),
            ),
        )
        connection.commit()
    except sqlite3.Error as exc:
        connection.rollback()
        raise AnalysisProjectError("cannot create analysis project schema") from exc


def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        rows = connection.execute("SELECT key, value FROM metadata").fetchall()
    except sqlite3.Error as exc:
        raise AnalysisProjectError("analysis project schema metadata is missing") from exc
    return {str(row["key"]): str(row["value"]) for row in rows}


def validate_schema(connection: sqlite3.Connection) -> None:
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    except sqlite3.Error as exc:
        raise AnalysisProjectError("cannot inspect analysis project schema") from exc
    tables = {str(row["name"]) for row in rows}
    missing = REQUIRED_TABLES - tables
    if missing:
        raise AnalysisProjectError(
            "analysis project schema is incomplete: " + ", ".join(sorted(missing))
        )

    metadata = _metadata(connection)
    schema_value = metadata.get("schema_version")
    analysis_value = metadata.get("analysis_model_version")
    if schema_value is None or analysis_value is None:
        raise AnalysisProjectError("analysis project schema metadata is missing")
    try:
        schema_version = int(schema_value)
        analysis_model_version = int(analysis_value)
    except ValueError as exc:
        raise AnalysisProjectError("analysis project schema metadata is malformed") from exc
    if schema_version != SCHEMA_VERSION:
        raise AnalysisProjectError(
            f"analysis project schema version {schema_version} is unsupported"
        )
    if analysis_model_version != ANALYSIS_MODEL_VERSION:
        raise AnalysisProjectError(
            f"analysis project model version {analysis_model_version} is unsupported"
        )
