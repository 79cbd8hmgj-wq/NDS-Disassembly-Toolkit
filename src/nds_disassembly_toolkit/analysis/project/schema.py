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
        "basic_blocks",
        "instructions",
        "cfg_edges",
        "unresolved_transfers",
        "decode_failures",
        "block_flow",
        "instruction_flow",
        "register_flow",
        "function_warnings",
        "stack_frames",
        "stack_slots",
        "stack_accesses",
        "argument_evidence",
        "argument_uses",
        "return_evidence",
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

CREATE TABLE basic_blocks (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    address INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    instruction_set TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        address,
        instruction_set
    ),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE TABLE instructions (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    block_address INTEGER NOT NULL,
    block_instruction_set TEXT NOT NULL,
    address INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    size INTEGER NOT NULL CHECK(size > 0),
    data_hex TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    operands TEXT NOT NULL,
    instruction_set TEXT NOT NULL,
    control_flow TEXT NOT NULL,
    direct_target INTEGER,
    target_instruction_set TEXT,
    conditional INTEGER NOT NULL CHECK(conditional IN (0, 1)),
    semantics_json TEXT NOT NULL,
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        address
    ),
    FOREIGN KEY(
        component_id,
        function_address,
        function_instruction_set,
        block_address,
        block_instruction_set
    ) REFERENCES basic_blocks(
        component_id,
        function_address,
        function_instruction_set,
        address,
        instruction_set
    ) ON DELETE CASCADE
);

CREATE TABLE cfg_edges (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    source_address INTEGER NOT NULL,
    source_instruction_address INTEGER NOT NULL,
    target_address INTEGER NOT NULL,
    target_instruction_set TEXT NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        source_instruction_address,
        target_address,
        target_instruction_set,
        kind
    ),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE TABLE unresolved_transfers (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    source_address INTEGER NOT NULL,
    instruction_set TEXT NOT NULL,
    control_flow TEXT NOT NULL,
    mnemonic TEXT NOT NULL,
    operands TEXT NOT NULL,
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        source_address
    ),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE TABLE decode_failures (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    address INTEGER NOT NULL,
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        address
    ),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE TABLE block_flow (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    block_address INTEGER NOT NULL,
    block_instruction_set TEXT NOT NULL,
    stack_entry_json TEXT,
    stack_exit_json TEXT,
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        block_address,
        block_instruction_set
    ),
    FOREIGN KEY(
        component_id,
        function_address,
        function_instruction_set,
        block_address,
        block_instruction_set
    ) REFERENCES basic_blocks(
        component_id,
        function_address,
        function_instruction_set,
        address,
        instruction_set
    ) ON DELETE CASCADE
);

CREATE TABLE instruction_flow (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    instruction_address INTEGER NOT NULL,
    stack_before_json TEXT,
    stack_after_json TEXT,
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        instruction_address
    ),
    FOREIGN KEY(
        component_id,
        function_address,
        function_instruction_set,
        instruction_address
    ) REFERENCES instructions(
        component_id,
        function_address,
        function_instruction_set,
        address
    ) ON DELETE CASCADE
);

CREATE TABLE register_flow (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_address INTEGER NOT NULL,
    scope_side TEXT NOT NULL,
    register TEXT NOT NULL,
    value_kind TEXT NOT NULL,
    value INTEGER,
    owner_component TEXT,
    provenance_json TEXT NOT NULL,
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        scope_kind,
        scope_address,
        scope_side,
        register
    ),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE TABLE function_warnings (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    text TEXT NOT NULL,
    PRIMARY KEY(component_id, function_address, function_instruction_set, ordinal),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE TABLE stack_frames (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    frame_size INTEGER,
    frame_pointer TEXT,
    stack_depth_known INTEGER NOT NULL CHECK(stack_depth_known IN (0, 1)),
    PRIMARY KEY(component_id, function_address, function_instruction_set),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE TABLE stack_slots (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    slot_offset INTEGER NOT NULL,
    kind TEXT NOT NULL,
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        slot_offset
    ),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE TABLE stack_accesses (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    slot_offset INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    instruction_address INTEGER NOT NULL,
    kind TEXT NOT NULL,
    width INTEGER NOT NULL CHECK(width > 0),
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        slot_offset,
        ordinal
    ),
    FOREIGN KEY(
        component_id,
        function_address,
        function_instruction_set,
        slot_offset
    ) REFERENCES stack_slots(
        component_id,
        function_address,
        function_instruction_set,
        slot_offset
    ) ON DELETE CASCADE
);

CREATE TABLE argument_evidence (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    arg_index INTEGER,
    kind TEXT NOT NULL,
    register TEXT,
    stack_offset INTEGER,
    PRIMARY KEY(component_id, function_address, function_instruction_set, ordinal),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE TABLE argument_uses (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    argument_ordinal INTEGER NOT NULL CHECK(argument_ordinal >= 0),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    instruction_address INTEGER NOT NULL,
    PRIMARY KEY(
        component_id,
        function_address,
        function_instruction_set,
        argument_ordinal,
        ordinal
    ),
    FOREIGN KEY(
        component_id,
        function_address,
        function_instruction_set,
        argument_ordinal
    ) REFERENCES argument_evidence(
        component_id,
        function_address,
        function_instruction_set,
        ordinal
    ) ON DELETE CASCADE
);

CREATE TABLE return_evidence (
    component_id INTEGER NOT NULL,
    function_address INTEGER NOT NULL,
    function_instruction_set TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    return_address INTEGER NOT NULL,
    value_kind TEXT NOT NULL,
    value INTEGER,
    owner_component TEXT,
    provenance_json TEXT NOT NULL,
    PRIMARY KEY(component_id, function_address, function_instruction_set, ordinal),
    FOREIGN KEY(component_id, function_address, function_instruction_set)
        REFERENCES functions(component_id, address, instruction_set)
        ON DELETE CASCADE
);

CREATE INDEX idx_symbol_name ON generated_symbols(name);
CREATE INDEX idx_xref_source ON xrefs(source_component_id, source_address);
CREATE INDEX idx_xref_target ON xrefs(target_address);
CREATE INDEX idx_block_flow_function
    ON block_flow(component_id, function_address, function_instruction_set);
CREATE INDEX idx_instruction_flow_function
    ON instruction_flow(component_id, function_address, function_instruction_set);
CREATE INDEX idx_register_flow_function
    ON register_flow(component_id, function_address, function_instruction_set);
CREATE INDEX idx_register_flow_register ON register_flow(register);
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
