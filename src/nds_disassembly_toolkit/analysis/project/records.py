from __future__ import annotations

import sqlite3

from nds_disassembly_toolkit.analysis.model import (
    CrossReference,
    CrossReferenceKind,
    FunctionCandidate,
    InstructionSet,
    StringRecord,
    Symbol,
    SymbolKind,
)
from nds_disassembly_toolkit.analysis.project.codec import dump_str_tuple, load_str_tuple
from nds_disassembly_toolkit.analysis.project.model import ComponentAnalysisBundle
from nds_disassembly_toolkit.errors import AnalysisProjectError


def component_id(connection: sqlite3.Connection, name: str) -> int:
    row = connection.execute(
        "SELECT id FROM components WHERE name = ?",
        (name,),
    ).fetchone()
    if row is None:
        raise AnalysisProjectError(f"analysis component {name!r} is not registered")
    return int(row["id"])


def delete_records(connection: sqlite3.Connection, component_id_value: int) -> None:
    connection.execute("DELETE FROM xrefs WHERE source_component_id = ?", (component_id_value,))
    connection.execute("DELETE FROM generated_symbols WHERE component_id = ?", (component_id_value,))
    connection.execute("DELETE FROM strings WHERE component_id = ?", (component_id_value,))
    connection.execute("DELETE FROM functions WHERE component_id = ?", (component_id_value,))


def insert_records(
    connection: sqlite3.Connection,
    component_id_value: int,
    bundle: ComponentAnalysisBundle,
) -> None:
    connection.executemany(
        """
        INSERT INTO functions(
            component_id,
            address,
            offset,
            instruction_set,
            confidence,
            evidence_json
        ) VALUES(?, ?, ?, ?, ?, ?)
        """,
        tuple(
            (
                component_id_value,
                function.address,
                function.offset,
                function.instruction_set.value,
                function.confidence,
                dump_str_tuple(function.evidence),
            )
            for function in bundle.functions
        ),
    )
    connection.executemany(
        """
        INSERT INTO strings(component_id, address, offset, text)
        VALUES(?, ?, ?, ?)
        """,
        tuple(
            (component_id_value, record.address, record.offset, record.text)
            for record in bundle.strings
        ),
    )
    connection.executemany(
        """
        INSERT INTO generated_symbols(
            component_id,
            address,
            offset,
            name,
            kind,
            instruction_set,
            confidence,
            evidence_json
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        tuple(
            (
                component_id_value,
                symbol.address,
                symbol.offset,
                symbol.name,
                symbol.kind.value,
                None if symbol.instruction_set is None else symbol.instruction_set.value,
                symbol.confidence,
                dump_str_tuple(symbol.evidence),
            )
            for symbol in bundle.symbols.symbols
        ),
    )
    connection.executemany(
        """
        INSERT INTO xrefs(
            kind,
            source_component_id,
            source_address,
            source_function_address,
            source_instruction_set,
            target_address,
            target_instruction_set
        ) VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        tuple(
            (
                reference.kind.value,
                component_id_value,
                reference.source_address,
                reference.source_function_address,
                (
                    None
                    if reference.source_instruction_set is None
                    else reference.source_instruction_set.value
                ),
                reference.target_address,
                (
                    None
                    if reference.target_instruction_set is None
                    else reference.target_instruction_set.value
                ),
            )
            for reference in bundle.xrefs
        ),
    )


def _optional_instruction_set(value: object) -> InstructionSet | None:
    if value is None:
        return None
    try:
        return InstructionSet(str(value))
    except ValueError as exc:
        raise AnalysisProjectError("persisted instruction-set value is invalid") from exc


def function_from_row(row: sqlite3.Row) -> FunctionCandidate:
    try:
        return FunctionCandidate(
            component=str(row["component"]),
            address=int(row["address"]),
            offset=int(row["offset"]),
            instruction_set=InstructionSet(str(row["instruction_set"])),
            confidence=str(row["confidence"]),
            evidence=load_str_tuple(str(row["evidence_json"])),
        )
    except ValueError as exc:
        raise AnalysisProjectError("persisted function record is invalid") from exc


def string_from_row(row: sqlite3.Row) -> StringRecord:
    return StringRecord(
        component=str(row["component"]),
        offset=int(row["offset"]),
        address=int(row["address"]),
        text=str(row["text"]),
    )


def symbol_from_row(row: sqlite3.Row) -> Symbol:
    try:
        return Symbol(
            component=str(row["component"]),
            address=int(row["address"]),
            offset=int(row["offset"]),
            name=str(row["name"]),
            kind=SymbolKind(str(row["kind"])),
            instruction_set=_optional_instruction_set(row["instruction_set"]),
            confidence=str(row["confidence"]),
            evidence=load_str_tuple(str(row["evidence_json"])),
        )
    except ValueError as exc:
        raise AnalysisProjectError("persisted symbol record is invalid") from exc


def xref_from_row(row: sqlite3.Row) -> CrossReference:
    try:
        return CrossReference(
            kind=CrossReferenceKind(str(row["kind"])),
            source_component=str(row["component"]),
            source_address=int(row["source_address"]),
            source_function_address=(
                None
                if row["source_function_address"] is None
                else int(row["source_function_address"])
            ),
            source_instruction_set=_optional_instruction_set(
                row["source_instruction_set"]
            ),
            target_address=int(row["target_address"]),
            target_instruction_set=_optional_instruction_set(
                row["target_instruction_set"]
            ),
        )
    except ValueError as exc:
        raise AnalysisProjectError("persisted xref record is invalid") from exc
