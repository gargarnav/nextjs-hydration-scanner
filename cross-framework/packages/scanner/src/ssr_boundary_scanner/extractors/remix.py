"""Remix extractor — window.__remixContext serialized route data."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Remix serializes route loader data into a window.__remixContext = {...} assignment.
_REMIX_CONTEXT_RE: re.Pattern[str] = re.compile(
    r'window\.__remixContext\s*=\s*(\{[\s\S]*?\})\s*(?:;|</script>)',
    re.MULTILINE,
)


def extract_remix_data(html: str) -> list[Any]:
    """Extract data objects from Remix's window.__remixContext payload.

    Handles:
    - context.state.loaderData (v2 format)
    - context.matches[n].data (older format)
    - undefined → null substitution for JS-serialized values

    Returns a list of decoded Python objects (may be empty).
    """
    results: list[Any] = []

    for match in _REMIX_CONTEXT_RE.finditer(html):
        raw_json = match.group(1)
        # Remix may serialize `undefined` which is invalid JSON — replace with null.
        raw_json = re.sub(r'\bundefined\b', 'null', raw_json)
        try:
            context = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.debug("__remixContext payload was not valid JSON; skipping.")
            continue

        if not isinstance(context, dict):
            results.append(context)
            continue

        # v2 format: context.state.loaderData is a dict keyed by route ID.
        state = context.get("state", {})
        loader_data = state.get("loaderData") if isinstance(state, dict) else None
        if isinstance(loader_data, dict):
            for route_data in loader_data.values():
                if route_data is not None:
                    results.append(route_data)
            continue

        # Older format: context.matches[n].data
        matches = context.get("matches", [])
        if isinstance(matches, list):
            for route_match in matches:
                data = route_match.get("data") if isinstance(route_match, dict) else None
                if data is not None:
                    results.append(data)
            if results:
                continue

        # Fallback: scan the whole context object.
        results.append(context)

    return results
