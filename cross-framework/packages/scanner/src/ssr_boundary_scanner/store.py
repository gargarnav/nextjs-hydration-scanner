"""Findings persistence — writes timestamped JSON reports and a cumulative index."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

FINDINGS_DIR = Path.cwd() / "findings"


def save_to_findings_store(report: dict[str, Any], label: str | None) -> Path:
    """Persist a scan report into the findings/ directory and update the index.

    Each invocation writes one timestamped JSON file and appends a one-line
    summary to findings/index.json so that all historical runs are queryable
    without loading individual report files.

    File naming: findings/YYYY-MM-DDTHH-MM-SS[_label].json
    """
    FINDINGS_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    slug = f"_{label}" if label else ""
    report_path = FINDINGS_DIR / f"{timestamp}{slug}.json"

    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    index_path = FINDINGS_DIR / "index.json"
    index: list[dict[str, Any]] = []
    if index_path.exists():
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.warning("findings/index.json was malformed; rebuilding from scratch.")
            index = []

    summary = report.get("summary", {})
    index.append({
        "file":            report_path.name,
        "scanned_at":      report.get("generated_at", timestamp),
        "label":           label,
        "targets_scanned": summary.get("targets_scanned", 0),
        "total_findings":  summary.get("total_findings", 0),
        "critical":        summary.get("critical", 0),
        "high":            summary.get("high", 0),
        "medium":          summary.get("medium", 0),
        "urls":            [r["url"] for r in report.get("results", [])],
    })

    with open(index_path, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2)

    return report_path
