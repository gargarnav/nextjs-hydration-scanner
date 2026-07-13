"""SvelteKit extractor — window.__sveltekit_data dehydrated payload."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# SvelteKit 2.x inlines a dehydrated data structure as:
#   <script>window.__sveltekit_data = {...}</script>
# The payload uses a compact encoding: data[0] is a key→index map and
# data[1+] are the actual values. We attempt to rehydrate, falling back
# to scanning the raw structure when the format doesn't match.
_SVELTEKIT_DATA_RE: re.Pattern[str] = re.compile(
    r'window\.__sveltekit_data\s*=\s*(\{[\s\S]*?\})\s*(?:;|</script>)',
    re.MULTILINE,
)


def extract_sveltekit_data(html: str) -> list[Any]:
    """Extract data objects from SvelteKit's window.__sveltekit_data payload.

    Returns a list of decoded Python objects (may be empty if none found).
    """
    results: list[Any] = []

    for match in _SVELTEKIT_DATA_RE.finditer(html):
        raw_json = match.group(1)
        # SvelteKit sometimes writes undefined JS values — substitute null.
        raw_json = re.sub(r'\bundefined\b', 'null', raw_json)
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError:
            logger.debug("__sveltekit_data payload was not valid JSON; skipping.")
            continue

        if not isinstance(payload, dict):
            results.append(payload)
            continue

        # Attempt SvelteKit 2.x dehydration: payload has "type" and "data" keys.
        # data[0] is a key→index map; data[1..] are actual values.
        data_array = payload.get("data")
        if isinstance(data_array, list) and len(data_array) >= 2:
            key_map = data_array[0]
            values = data_array[1:]

            if isinstance(key_map, dict):
                try:
                    rehydrated = {
                        k: values[idx] if idx < len(values) else None
                        for k, idx in key_map.items()
                        if isinstance(idx, int)
                    }
                    results.append(rehydrated)
                    continue
                except Exception:
                    logger.debug("SvelteKit rehydration failed; falling back to raw scan.")

        # Fallback: scan the raw structure (may include some noise but no false negatives)
        results.append(payload)

    return results
