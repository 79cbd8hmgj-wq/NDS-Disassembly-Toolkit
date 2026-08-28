from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from nds_disassembly_toolkit.analysis.project import (
    AnalysisProject,
    AnalysisProjectError,
    AnalysisProjectMetadata,
)


def _manifest(root: Path) -> dict[str, object]:
    return json.loads((root / "project.json").read_text())


def test_create_and_reopen_project(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"

    with AnalysisProject.create(root) as project:
        assert project.metadata == AnalysisProjectMetadata(1, 1, 1, False)

    assert _manifest(root) == {
        "format": "nds-disassembly-toolkit-analysis-project",
        "project_format_version": 1,
        "database": "analysis.sqlite",
    }
    assert (root / "analysis.sqlite").is_file()

    with sqlite3.connect(root / "analysis.sqlite") as connection:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
    assert metadata["schema_version"] == "1"
    assert metadata["analysis_model_version"] == "1"

    with AnalysisProject.open(root, read_only=True) as project:
        assert project.metadata == AnalysisProjectMetadata(1, 1, 1, True)


def test_create_rejects_existing_nonempty_directory(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    root.mkdir()
    (root / "keep.txt").write_text("keep")

    with pytest.raises(AnalysisProjectError, match="non-empty"):
        AnalysisProject.create(root)

    assert (root / "keep.txt").read_text() == "keep"


def test_open_rejects_malformed_manifest_json(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    root.mkdir()
    (root / "project.json").write_text("{")

    with pytest.raises(AnalysisProjectError, match="manifest"):
        AnalysisProject.open(root)


def test_open_rejects_future_project_version(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    root.mkdir()
    (root / "project.json").write_text(
        json.dumps(
            {
                "format": "nds-disassembly-toolkit-analysis-project",
                "project_format_version": 2,
                "database": "analysis.sqlite",
            }
        )
    )

    with pytest.raises(AnalysisProjectError, match="project format version"):
        AnalysisProject.open(root)


@pytest.mark.parametrize("database", ["/tmp/analysis.sqlite", "../analysis.sqlite", "db/analysis.sqlite"])
def test_open_rejects_unsafe_database_path(tmp_path: Path, database: str) -> None:
    root = tmp_path / "game.ndsre"
    root.mkdir()
    (root / "project.json").write_text(
        json.dumps(
            {
                "format": "nds-disassembly-toolkit-analysis-project",
                "project_format_version": 1,
                "database": database,
            }
        )
    )

    with pytest.raises(AnalysisProjectError, match="database path"):
        AnalysisProject.open(root)


def test_open_rejects_missing_schema_metadata(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root):
        pass

    with sqlite3.connect(root / "analysis.sqlite") as connection:
        connection.execute("DELETE FROM metadata WHERE key = 'schema_version'")
        connection.commit()

    with pytest.raises(AnalysisProjectError, match="schema metadata"):
        AnalysisProject.open(root)


def test_open_rejects_future_schema_version(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    with AnalysisProject.create(root):
        pass

    with sqlite3.connect(root / "analysis.sqlite") as connection:
        connection.execute(
            "UPDATE metadata SET value = '2' WHERE key = 'schema_version'"
        )
        connection.commit()

    with pytest.raises(AnalysisProjectError, match="schema version"):
        AnalysisProject.open(root)


def test_read_only_open_does_not_create_missing_database(tmp_path: Path) -> None:
    root = tmp_path / "game.ndsre"
    root.mkdir()
    (root / "project.json").write_text(
        json.dumps(
            {
                "format": "nds-disassembly-toolkit-analysis-project",
                "project_format_version": 1,
                "database": "analysis.sqlite",
            }
        )
    )

    with pytest.raises(AnalysisProjectError, match="database"):
        AnalysisProject.open(root, read_only=True)

    assert not (root / "analysis.sqlite").exists()
