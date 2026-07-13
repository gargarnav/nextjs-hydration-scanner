"""
Core recursive walker and data structures.
Extracted verbatim from the original nextjs-hydration-scanner/scanner.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .patterns import SENSITIVE_FIELD_PATTERNS, SENSITIVE_VALUE_PATTERNS


@dataclass
class Finding:
    field_path:    str
    field_name:    str
    value_preview: str
    reason:        str
    severity:      str
    channel:       str
    match_type:    str


@dataclass
class TargetResult:
    url:                str
    scanned_at:         str
    status:             Literal["ok", "error", "no_payload"]
    error:              str | None
    pages_router_found: bool
    app_router_found:   bool
    sveltekit_found:    bool = False
    remix_found:        bool = False
    nuxt_found:         bool = False
    findings:           list[Finding] = field(default_factory=list)

    def _count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def critical_count(self) -> int:
        return self._count("CRITICAL")

    @property
    def high_count(self) -> int:
        return self._count("HIGH")

    @property
    def medium_count(self) -> int:
        return self._count("MEDIUM")


def _value_preview(value: Any) -> str:
    raw = str(value)
    length = len(raw)
    if length <= 12:
        return raw[:4] + "*" * (length - 4) if length > 4 else "****"
    return f"{raw[:6]}...{raw[-4:]}  [{length} chars]"


def _walk(
    node: Any,
    path: str,
    channel: str,
    findings: list[Finding],
    _field_flagged: set[str] | None = None,
) -> None:
    if _field_flagged is None:
        _field_flagged = set()

    if isinstance(node, dict):
        for key, value in node.items():
            current_path = f"{path}.{key}" if path else key

            for pattern, severity, label in SENSITIVE_FIELD_PATTERNS:
                if pattern.search(key):
                    findings.append(Finding(
                        field_path=current_path,
                        field_name=key,
                        value_preview=_value_preview(value),
                        reason=f"{label} — field name matches pattern /{pattern.pattern}/i",
                        severity=severity,
                        channel=channel,
                        match_type="field_name",
                    ))
                    _field_flagged.add(current_path)
                    break

            if isinstance(value, str) and current_path not in _field_flagged:
                for vpattern, vseverity, vlabel in SENSITIVE_VALUE_PATTERNS:
                    if vpattern.search(value):
                        findings.append(Finding(
                            field_path=current_path,
                            field_name=key,
                            value_preview=_value_preview(value),
                            reason=f"{vlabel} — value matches pattern /{vpattern.pattern}/",
                            severity=vseverity,
                            channel=channel,
                            match_type="value_pattern",
                        ))
                        break

            _walk(value, current_path, channel, findings, _field_flagged)

    elif isinstance(node, list):
        for index, item in enumerate(node):
            _walk(item, f"{path}[{index}]", channel, findings, _field_flagged)
