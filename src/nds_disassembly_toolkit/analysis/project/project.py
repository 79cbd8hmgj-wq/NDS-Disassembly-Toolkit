from __future__ import annotations

import sqlite3
from contextlib import suppress
from pathlib import Path
from types import TracebackType

from nds_disassembly_toolkit.analysis.project.manifest import (
    load_manifest,
    resolve_database_path,
    write_manifest,
)
from nds_disassembly_toolkit.analysis.project.model import AnalysisProjectMetadata
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
