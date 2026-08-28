from __future__ import annotations

import json

from nds_disassembly_toolkit.errors import AnalysisProjectError


def dump_str_tuple(values: tuple[str, ...]) -> str:
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def load_str_tuple(value: str) -> tuple[str, ...]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AnalysisProjectError("analysis project tuple JSON is malformed") from exc
    if not isinstance(decoded, list) or any(not isinstance(item, str) for item in decoded):
        raise AnalysisProjectError("analysis project tuple JSON has invalid values")
    return tuple(decoded)
