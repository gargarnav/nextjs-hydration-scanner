"""Next.js extractor — Pages Router (__NEXT_DATA__) and App Router (RSC payload)."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

_RSC_PUSH_RE: re.Pattern[str] = re.compile(
    r'self\.__next_f\.push\(\s*(\[[\s\S]*?\])\s*\)',
    re.MULTILINE,
)


def extract_next_data(html: str) -> dict[str, Any] | None:
    """Extract and parse the __NEXT_DATA__ JSON blob from Pages Router HTML."""
    soup = BeautifulSoup(html, "html.parser")
    tag = soup.find("script", {"id": "__NEXT_DATA__"})
    if not tag or not tag.string:
        return None
    try:
        return json.loads(tag.string)
    except json.JSONDecodeError:
        logger.debug("__NEXT_DATA__ tag present but contained invalid JSON; skipping.")
        return None


def extract_rsc_payloads(html: str) -> list[Any]:
    """Extract decoded objects from App Router RSC inline script chunks."""
    decoded_objects: list[Any] = []

    for match in _RSC_PUSH_RE.finditer(html):
        try:
            chunk = json.loads(match.group(1))
        except json.JSONDecodeError:
            logger.debug("Skipping RSC chunk — outer array was not valid JSON.")
            continue

        if not isinstance(chunk, list) or len(chunk) < 2:
            continue

        row_type: Any = chunk[0]
        data: Any     = chunk[1]

        if row_type == 1 and isinstance(data, str):
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                colon_pos = line.find(":")
                if colon_pos == -1:
                    continue
                json_fragment = line[colon_pos + 1:]
                try:
                    decoded_objects.append(json.loads(json_fragment))
                except json.JSONDecodeError:
                    pass

        elif row_type == 0 and isinstance(data, (dict, list)):
            decoded_objects.append(data)

    return decoded_objects
