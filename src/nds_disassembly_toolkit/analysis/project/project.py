from __future__ import annotations

import json
import sqlite3
from contextlib import suppress
from pathlib import Path
from types import TracebackType

from nds_disassembly_toolkit.analysis.model import (
    Component,
    CrossReference,
    FunctionCandidate,
    FunctionControlFlowGraph,
    InstructionSet,
    StringRecord,
    Symbol,
)
from nds_disassembly_toolkit.analysis.project.cfg_records import (
    cfg_from_database,
    delete_cfgs,
    insert_cfgs,
    validate_cfg_bundle,
)
from nds_disassembly_toolkit.analysis.project.manifest import (
    load_manifest,
    resolve_database_path,
    write_manifest,
)
from nds_disassembly_toolkit.analysis.project.model import (
    AnalysisFreshness,
    AnalysisProjectMetadata,
    ComponentAnalysisBundle,
    ComponentAnalysisIdentity,
    LocationAnnotation,
)
from nds_disassembly_toolkit.analysis.project.records import (
    component_id,
    delete_records,
    function_from_row,
    insert_records,
    string_from_row,
    symbol_from_row,
    xref_from_row,
)
from nds_disassembly_toolkit.analysis.project.schema import (
    ANALYSIS_MODEL_VERSION,
    SCHEMA_VERSION,
    configure_connection,
    create_schema,
    validate_schema,
)
from nds_disassembly_toolkit.errors import AnalysisProjectError


class AnalysisProject:
    def __init__(
        self,
        root: Path,
        database_path: Path,
        connection: sqlite3.Connection,
        *,
        read_only: bool,
    ) -> None:
        self._root = root
        self._database_path = database_path
        self._connection: sqlite3.Connection | None = connection
        self._read_only = read_only

    @classmethod
    def create(cls, path: Path) -> AnalysisProject:
        root = Path(path)
        created_root = False
        if root.exists():
            if not root.is_dir():
                raise AnalysisProjectError("analysis project destination is not a directory")
            try:
                if any(root.iterdir()):
                    raise AnalysisProjectError(
                        "analysis project destination is non-empty"
                    )
            except OSError as exc:
                raise AnalysisProjectError(
                    "cannot inspect analysis project destination"
                ) from exc
        else:
            try:
                root.mkdir(parents=True)
            except OSError as exc:
                raise AnalysisProjectError(
                    "cannot create analysis project directory"
                ) from exc
            created_root = True

        manifest_path = root / "project.json"
        database_path = root / "analysis.sqlite"
        connection: sqlite3.Connection | None = None
        try:
            write_manifest(root)
            connection = sqlite3.connect(database_path)
            configure_connection(connection, read_only=False)
            create_schema(connection)
            validate_schema(connection)
            return cls(
                root,
                database_path,
                connection,
                read_only=False,
            )
        except AnalysisProjectError:
            if connection is not None:
                connection.close()
            cls._cleanup_failed_create(
                root,
                manifest_path,
                database_path,
                created_root=created_root,
            )
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            cls._cleanup_failed_create(
                root,
                manifest_path,
                database_path,
                created_root=created_root,
            )
            raise AnalysisProjectError("cannot create analysis project database") from exc

    @classmethod
    def open(cls, path: Path, *, read_only: bool = False) -> AnalysisProject:
        root = Path(path)
        manifest = load_manifest(root)
        database_path = resolve_database_path(root, manifest)
        if not database_path.is_file():
            raise AnalysisProjectError("analysis project database is missing")

        connection: sqlite3.Connection | None = None
        try:
            if read_only:
                uri = database_path.resolve().as_uri() + "?mode=ro"
                connection = sqlite3.connect(uri, uri=True)
            else:
                connection = sqlite3.connect(database_path)
            configure_connection(connection, read_only=read_only)
            validate_schema(connection)
        except AnalysisProjectError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise AnalysisProjectError("cannot open analysis project database") from exc

        return cls(root, database_path, connection, read_only=read_only)

    @staticmethod
    def _cleanup_failed_create(
        root: Path,
        manifest_path: Path,
        database_path: Path,
        *,
        created_root: bool,
    ) -> None:
        manifest_path.unlink(missing_ok=True)
        database_path.unlink(missing_ok=True)
        (root / "project.json.tmp").unlink(missing_ok=True)
        if created_root:
            with suppress(OSError):
                root.rmdir()

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise AnalysisProjectError("analysis project is closed")
        return self._connection

    def _require_writable(self) -> sqlite3.Connection:
        if self._read_only:
            raise AnalysisProjectError("analysis project is read-only")
        return self._require_connection()

    @property
    def metadata(self) -> AnalysisProjectMetadata:
        return AnalysisProjectMetadata(
            project_format_version=1,
            schema_version=SCHEMA_VERSION,
            analysis_model_version=ANALYSIS_MODEL_VERSION,
            read_only=self._read_only,
        )

    @property
    def root(self) -> Path:
        return self._root

    def store_component_analysis(self, bundle: ComponentAnalysisBundle) -> None:
        connection = self._require_writable()
        identity = ComponentAnalysisIdentity.from_component(bundle.component)
        validate_cfg_bundle(bundle)
        try:
            connection.execute(
                """
                INSERT INTO components(name, base_address, size, sha256)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    base_address = excluded.base_address,
                    size = excluded.size,
                    sha256 = excluded.sha256
                """,
                (
                    identity.name,
                    identity.base_address,
                    identity.size,
                    identity.sha256,
                ),
            )
            component_id_value = component_id(connection, identity.name)
            delete_cfgs(connection, component_id_value)
            delete_records(connection, component_id_value)
            insert_records(connection, component_id_value, bundle)
            insert_cfgs(connection, component_id_value, bundle.cfgs)
            connection.commit()
        except AnalysisProjectError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise AnalysisProjectError("cannot store analysis component") from exc

    def component_identities(self) -> tuple[ComponentAnalysisIdentity, ...]:
        connection = self._require_connection()
        try:
            rows = connection.execute(
                """
                SELECT name, base_address, size, sha256
                FROM components
                ORDER BY name
                """
            ).fetchall()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis components") from exc
        return tuple(
            ComponentAnalysisIdentity(
                name=str(row["name"]),
                base_address=int(row["base_address"]),
                size=int(row["size"]),
                sha256=str(row["sha256"]),
            )
            for row in rows
        )

    def component_status(self, component: Component) -> AnalysisFreshness:
        connection = self._require_connection()
        try:
            row = connection.execute(
                """
                SELECT name, base_address, size, sha256
                FROM components
                WHERE name = ?
                """,
                (component.name,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis component") from exc
        if row is None:
            return AnalysisFreshness.MISSING
        stored = ComponentAnalysisIdentity(
            name=str(row["name"]),
            base_address=int(row["base_address"]),
            size=int(row["size"]),
            sha256=str(row["sha256"]),
        )
        current = ComponentAnalysisIdentity.from_component(component)
        if stored == current:
            return AnalysisFreshness.CURRENT
        return AnalysisFreshness.STALE

    def functions(
        self,
        *,
        component: str | None = None,
    ) -> tuple[FunctionCandidate, ...]:
        connection = self._require_connection()
        query = """
            SELECT
                components.name AS component,
                functions.address,
                functions.offset,
                functions.instruction_set,
                functions.confidence,
                functions.evidence_json
            FROM functions
            JOIN components ON components.id = functions.component_id
        """
        parameters: tuple[str, ...] = ()
        if component is not None:
            query += " WHERE components.name = ?"
            parameters = (component,)
        query += " ORDER BY components.name, functions.address, functions.instruction_set"
        try:
            rows = connection.execute(query, parameters).fetchall()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis functions") from exc
        return tuple(function_from_row(row) for row in rows)

    def function(
        self,
        component: str,
        address: int,
        instruction_set: InstructionSet,
    ) -> FunctionCandidate | None:
        connection = self._require_connection()
        try:
            row = connection.execute(
                """
                SELECT
                    components.name AS component,
                    functions.address,
                    functions.offset,
                    functions.instruction_set,
                    functions.confidence,
                    functions.evidence_json
                FROM functions
                JOIN components ON components.id = functions.component_id
                WHERE components.name = ?
                  AND functions.address = ?
                  AND functions.instruction_set = ?
                """,
                (component, address, instruction_set.value),
            ).fetchone()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis function") from exc
        return None if row is None else function_from_row(row)

    def cfg(
        self,
        component: str,
        address: int,
        instruction_set: InstructionSet,
    ) -> FunctionControlFlowGraph | None:
        connection = self._require_connection()
        function = self.function(component, address, instruction_set)
        if function is None:
            return None
        try:
            return cfg_from_database(connection, function)
        except AnalysisProjectError:
            raise
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis CFG") from exc

    def strings(self, *, component: str | None = None) -> tuple[StringRecord, ...]:
        connection = self._require_connection()
        query = """
            SELECT
                components.name AS component,
                strings.address,
                strings.offset,
                strings.text
            FROM strings
            JOIN components ON components.id = strings.component_id
        """
        parameters: tuple[str, ...] = ()
        if component is not None:
            query += " WHERE components.name = ?"
            parameters = (component,)
        query += " ORDER BY components.name, strings.address"
        try:
            rows = connection.execute(query, parameters).fetchall()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis strings") from exc
        return tuple(string_from_row(row) for row in rows)

    def string_at(self, component: str, address: int) -> StringRecord | None:
        connection = self._require_connection()
        try:
            row = connection.execute(
                """
                SELECT
                    components.name AS component,
                    strings.address,
                    strings.offset,
                    strings.text
                FROM strings
                JOIN components ON components.id = strings.component_id
                WHERE components.name = ? AND strings.address = ?
                """,
                (component, address),
            ).fetchone()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis string") from exc
        return None if row is None else string_from_row(row)

    def symbols_at(self, component: str, address: int) -> tuple[Symbol, ...]:
        connection = self._require_connection()
        try:
            rows = connection.execute(
                """
                SELECT
                    components.name AS component,
                    generated_symbols.address,
                    generated_symbols.offset,
                    generated_symbols.name,
                    generated_symbols.kind,
                    generated_symbols.instruction_set,
                    generated_symbols.confidence,
                    generated_symbols.evidence_json
                FROM generated_symbols
                JOIN components ON components.id = generated_symbols.component_id
                WHERE components.name = ? AND generated_symbols.address = ?
                ORDER BY generated_symbols.name, generated_symbols.kind
                """,
                (component, address),
            ).fetchall()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis symbols") from exc
        return tuple(symbol_from_row(row) for row in rows)

    def symbols_named(
        self,
        name: str,
        *,
        component: str | None = None,
    ) -> tuple[Symbol, ...]:
        connection = self._require_connection()
        query = """
            SELECT
                components.name AS component,
                generated_symbols.address,
                generated_symbols.offset,
                generated_symbols.name,
                generated_symbols.kind,
                generated_symbols.instruction_set,
                generated_symbols.confidence,
                generated_symbols.evidence_json
            FROM generated_symbols
            JOIN components ON components.id = generated_symbols.component_id
            WHERE generated_symbols.name = ?
        """
        parameters: tuple[object, ...] = (name,)
        if component is not None:
            query += " AND components.name = ?"
            parameters = (name, component)
        query += " ORDER BY components.name, generated_symbols.address, generated_symbols.kind"
        try:
            rows = connection.execute(query, parameters).fetchall()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis symbols") from exc
        return tuple(symbol_from_row(row) for row in rows)

    def xrefs_from(self, component: str, address: int) -> tuple[CrossReference, ...]:
        connection = self._require_connection()
        try:
            rows = connection.execute(
                """
                SELECT
                    components.name AS component,
                    xrefs.kind,
                    xrefs.source_address,
                    xrefs.source_function_address,
                    xrefs.source_instruction_set,
                    xrefs.target_address,
                    xrefs.target_instruction_set
                FROM xrefs
                JOIN components ON components.id = xrefs.source_component_id
                WHERE components.name = ? AND xrefs.source_address = ?
                ORDER BY xrefs.target_address, xrefs.kind, xrefs.target_instruction_set
                """,
                (component, address),
            ).fetchall()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis xrefs") from exc
        return tuple(xref_from_row(row) for row in rows)

    def xrefs_to(
        self,
        address: int,
        *,
        source_component: str | None = None,
    ) -> tuple[CrossReference, ...]:
        connection = self._require_connection()
        query = """
            SELECT
                components.name AS component,
                xrefs.kind,
                xrefs.source_address,
                xrefs.source_function_address,
                xrefs.source_instruction_set,
                xrefs.target_address,
                xrefs.target_instruction_set
            FROM xrefs
            JOIN components ON components.id = xrefs.source_component_id
            WHERE xrefs.target_address = ?
        """
        parameters: tuple[object, ...] = (address,)
        if source_component is not None:
            query += " AND components.name = ?"
            parameters = (address, source_component)
        query += " ORDER BY components.name, xrefs.source_address, xrefs.kind"
        try:
            rows = connection.execute(query, parameters).fetchall()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis xrefs") from exc
        return tuple(xref_from_row(row) for row in rows)

    def set_annotation(self, annotation: LocationAnnotation) -> None:
        connection = self._require_writable()
        try:
            component_row = connection.execute(
                "SELECT id FROM components WHERE name = ?",
                (annotation.component,),
            ).fetchone()
            if component_row is None:
                raise AnalysisProjectError(
                    f"analysis component {annotation.component!r} is not registered"
                )
            connection.execute(
                """
                INSERT INTO location_annotations(
                    component_id,
                    address,
                    name_override,
                    comment,
                    tags_json,
                    bookmarked
                ) VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(component_id, address) DO UPDATE SET
                    name_override = excluded.name_override,
                    comment = excluded.comment,
                    tags_json = excluded.tags_json,
                    bookmarked = excluded.bookmarked
                """,
                (
                    int(component_row["id"]),
                    annotation.address,
                    annotation.name_override,
                    annotation.comment,
                    json.dumps(
                        annotation.tags,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    int(annotation.bookmarked),
                ),
            )
            connection.commit()
        except AnalysisProjectError:
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise AnalysisProjectError("cannot store analysis annotation") from exc

    @staticmethod
    def _annotation_from_row(row: sqlite3.Row) -> LocationAnnotation:
        try:
            raw_tags = json.loads(str(row["tags_json"]))
        except json.JSONDecodeError as exc:
            raise AnalysisProjectError("analysis annotation tags are malformed") from exc
        if not isinstance(raw_tags, list) or any(
            not isinstance(tag, str) for tag in raw_tags
        ):
            raise AnalysisProjectError("analysis annotation tags are malformed")
        return LocationAnnotation(
            component=str(row["component"]),
            address=int(row["address"]),
            name_override=(
                None if row["name_override"] is None else str(row["name_override"])
            ),
            comment=None if row["comment"] is None else str(row["comment"]),
            tags=tuple(raw_tags),
            bookmarked=bool(row["bookmarked"]),
        )

    def annotation(self, component: str, address: int) -> LocationAnnotation | None:
        connection = self._require_connection()
        try:
            row = connection.execute(
                """
                SELECT
                    components.name AS component,
                    location_annotations.address,
                    location_annotations.name_override,
                    location_annotations.comment,
                    location_annotations.tags_json,
                    location_annotations.bookmarked
                FROM location_annotations
                JOIN components ON components.id = location_annotations.component_id
                WHERE components.name = ? AND location_annotations.address = ?
                """,
                (component, address),
            ).fetchone()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis annotation") from exc
        if row is None:
            return None
        return self._annotation_from_row(row)

    def annotations(
        self,
        *,
        component: str | None = None,
    ) -> tuple[LocationAnnotation, ...]:
        connection = self._require_connection()
        query = """
            SELECT
                components.name AS component,
                location_annotations.address,
                location_annotations.name_override,
                location_annotations.comment,
                location_annotations.tags_json,
                location_annotations.bookmarked
            FROM location_annotations
            JOIN components ON components.id = location_annotations.component_id
        """
        parameters: tuple[str, ...] = ()
        if component is not None:
            query += " WHERE components.name = ?"
            parameters = (component,)
        query += " ORDER BY components.name, location_annotations.address"
        try:
            rows = connection.execute(query, parameters).fetchall()
        except sqlite3.Error as exc:
            raise AnalysisProjectError("cannot query analysis annotations") from exc
        return tuple(self._annotation_from_row(row) for row in rows)

    def close(self) -> None:
        connection = self._connection
        if connection is None:
            return
        connection.close()
        self._connection = None

    def __enter__(self) -> AnalysisProject:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
