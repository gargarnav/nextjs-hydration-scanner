"""Nuxt 3/4 extractor — __NUXT_DATA__ script tag and window.__NUXT__ assignment."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Nuxt 3 may also write data as window.__NUXT__ = {...}
_WINDOW_NUXT_RE: re.Pattern[str] = re.compile(
    r'window\.__NUXT__\s*=\s*(\{[\s\S]*?\})\s*(?:;|</script>)',
    re.MULTILINE,
)


def extract_nuxt_data(html: str) -> list[Any]:
    """Extract data objects from Nuxt 3/4 hydration payloads.

    Tries two methods:
    1. BeautifulSoup finds <script id="__NUXT_DATA__" type="application/json">
    2. Regex extracts window.__NUXT__ = {...} inline script

    Nuxt uses a dehydrated array format similar to SvelteKit. We extract
    the raw "data" or "state" array and let the walker scan it.

    Returns a list of decoded Python objects (may be empty).
    """
    results: list[Any] = []

    # Method 1: <script id="__NUXT_DATA__"> tag (Nuxt 3.x+)
    soup = BeautifulSoup(html, "html.parser")
    nuxt_tag = soup.find("script", {"id": "__NUXT_DATA__"})
    if nuxt_tag and nuxt_tag.string:
        try:
            payload = json.loads(nuxt_tag.string)
            # Extract state key when present (matches window.__NUXT__ behaviour)
            state = payload.get("state") if isinstance(payload, dict) else None
            results.append(state if state is not None else payload)
        except json.JSONDecodeError:
            logger.debug("__NUXT_DATA__ tag present but not valid JSON; skipping.")

    # Method 2: window.__NUXT__ = {...}
    for match in _WINDOW_NUXT_RE.finditer(html):
        raw_json = match.group(1)
        raw_json = re.sub(r'\bundefined\b', 'null', raw_json)
        try:
            context = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.debug("window.__NUXT__ payload was not valid JSON; skipping.")
            continue

        if not isinstance(context, dict):
            results.append(context)
            continue

        # Nuxt embeds server state — extract it for targeted scanning.
        state = context.get("state")
        if state:
            results.append(state)
        else:
            results.append(context)

    return results
