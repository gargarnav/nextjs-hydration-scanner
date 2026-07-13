"""
Sensitive field-name and value patterns, loaded from the canonical
sensitive-patterns.json at the monorepo root (bundled into the package).
"""

from __future__ import annotations

import json
import re
from importlib.resources import files
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# Each entry: (compiled_regex, severity, human_readable_label)
FieldPattern = tuple[re.Pattern[str], str, str]
ValuePattern = tuple[re.Pattern[str], str, str]


def _load() -> tuple[list[FieldPattern], list[ValuePattern]]:
    data_file = files("ssr_boundary_scanner").joinpath("sensitive-patterns.json")
    raw = json.loads(data_file.read_text(encoding="utf-8"))

    field_patterns: list[FieldPattern] = [
        (
            re.compile(entry["pattern"], re.I | _parse_flags(entry.get("flags", ""))),
            entry["severity"],
            entry["label"],
        )
        for entry in raw["field_patterns"]
    ]

    value_patterns: list[ValuePattern] = [
        (
            re.compile(entry["pattern"], _parse_flags(entry.get("flags", ""))),
            entry["severity"],
            entry["label"],
        )
        for entry in raw["value_patterns"]
    ]

    return field_patterns, value_patterns


def _parse_flags(flags_str: str) -> int:
    result = 0
    if "i" in flags_str:
        result |= re.I
    if "m" in flags_str:
        result |= re.M
    if "s" in flags_str:
        result |= re.S
    return result


SENSITIVE_FIELD_PATTERNS, SENSITIVE_VALUE_PATTERNS = _load()
