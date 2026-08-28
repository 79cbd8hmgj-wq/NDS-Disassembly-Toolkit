from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from nds_disassembly_toolkit.errors import AnalysisProjectError

PROJECT_FORMAT = "nds-disassembly-toolkit-analysis-project"
PROJECT_FORMAT_VERSION = 1
DEFAULT_DATABASE_NAME = "analysis.sqlite"


@dataclass(frozen=True)
class ProjectManifest:
    database: str


def _database_path(root: Path, database: str) -> Path:
    candidate = Path(database)
    if candidate.is_absolute() or len(candidate.parts) != 1 or candidate.name != database:
        raise AnalysisProjectError("analysis project database path is unsafe")
    if database in {"", ".", ".."}:
        raise AnalysisProjectError("analysis project database path is unsafe")
    return root / database


def write_manifest(root: Path) -> Path:
    payload = {
        "format": PROJECT_FORMAT,
        "project_format_version": PROJECT_FORMAT_VERSION,
        "database": DEFAULT_DATABASE_NAME,
    }
    path = root / "project.json"
    temporary = root / "project.json.tmp"
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise AnalysisProjectError("cannot write analysis project manifest") from exc
    return path


def load_manifest(root: Path) -> ProjectManifest:
    path = root / "project.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisProjectError("analysis project manifest is missing or malformed") from exc
    if not isinstance(raw, dict):
        raise AnalysisProjectError("analysis project manifest must be a JSON object")
    if raw.get("format") != PROJECT_FORMAT:
        raise AnalysisProjectError("analysis project manifest format is unsupported")
    version = raw.get("project_format_version")
    if version != PROJECT_FORMAT_VERSION:
        raise AnalysisProjectError(
            f"analysis project format version {version!r} is unsupported"
        )
    database = raw.get("database")
    if not isinstance(database, str):
        raise AnalysisProjectError("analysis project database path is invalid")
    _database_path(root, database)
    return ProjectManifest(database=database)


def resolve_database_path(root: Path, manifest: ProjectManifest) -> Path:
    return _database_path(root, manifest.database)
