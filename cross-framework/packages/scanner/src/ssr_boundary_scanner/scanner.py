"""Orchestrator — fetches a URL and probes all 5 SSR hydration channels."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Literal

import requests

from .extractors.nextjs import extract_next_data, extract_rsc_payloads
from .extractors.nuxt import extract_nuxt_data
from .extractors.remix import extract_remix_data
from .extractors.sveltekit import extract_sveltekit_data
from .walker import Finding, TargetResult, _walk

logger = logging.getLogger(__name__)

_HEADERS = {
    "User-Agent": (
        "SSR-Boundary-Scanner/0.1 "
        "(Security Research; github.com/gargarnav/ssr-boundary)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def _fetch(url: str, timeout: int = 15) -> tuple[str | None, str | None]:
    try:
        response = requests.get(url, headers=_HEADERS, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
        return response.text, None
    except requests.RequestException as exc:
        return None, str(exc)


def scan_url(url: str, timeout: int = 15) -> TargetResult:
    """Fetch *url* and scan all known SSR hydration channels for sensitive fields.

    Probes:
      1. Next.js Pages Router  — __NEXT_DATA__
      2. Next.js App Router    — RSC self.__next_f.push([...])
      3. SvelteKit             — window.__sveltekit_data
      4. Remix                 — window.__remixContext
      5. Nuxt 3/4              — <script id="__NUXT_DATA__"> / window.__NUXT__
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    html, error = _fetch(url, timeout=timeout)

    if error:
        logger.warning("Failed to fetch %s: %s", url, error)
        return TargetResult(
            url=url,
            scanned_at=scanned_at,
            status="error",
            error=error,
            pages_router_found=False,
            app_router_found=False,
        )

    findings: list[Finding] = []
    pages_router_found = False
    app_router_found   = False
    sveltekit_found    = False
    remix_found        = False
    nuxt_found         = False

    # Channel 1: Next.js Pages Router
    next_data = extract_next_data(html)
    if next_data:
        pages_router_found = True
        logger.debug("Pages Router payload detected at %s", url)
        _walk(next_data, "__NEXT_DATA__", "__NEXT_DATA__", findings)

    # Channel 2: Next.js App Router (RSC)
    rsc_objects = extract_rsc_payloads(html)
    if rsc_objects:
        app_router_found = True
        logger.debug("App Router RSC payload detected at %s (%d objects)", url, len(rsc_objects))
        for idx, obj in enumerate(rsc_objects):
            _walk(obj, f"RSC[{idx}]", "RSC_PAYLOAD", findings)

    # Channel 3: SvelteKit
    sk_objects = extract_sveltekit_data(html)
    if sk_objects:
        sveltekit_found = True
        logger.debug("SvelteKit payload detected at %s (%d objects)", url, len(sk_objects))
        for idx, obj in enumerate(sk_objects):
            _walk(obj, f"SVELTEKIT_DATA[{idx}]", "SVELTEKIT_DATA", findings)

    # Channel 4: Remix
    remix_objects = extract_remix_data(html)
    if remix_objects:
        remix_found = True
        logger.debug("Remix context detected at %s (%d objects)", url, len(remix_objects))
        for idx, obj in enumerate(remix_objects):
            _walk(obj, f"REMIX_CONTEXT[{idx}]", "REMIX_CONTEXT", findings)

    # Channel 5: Nuxt
    nuxt_objects = extract_nuxt_data(html)
    if nuxt_objects:
        nuxt_found = True
        logger.debug("Nuxt payload detected at %s (%d objects)", url, len(nuxt_objects))
        for idx, obj in enumerate(nuxt_objects):
            _walk(obj, f"NUXT_DATA[{idx}]", "NUXT_DATA", findings)

    any_found = (
        pages_router_found or app_router_found
        or sveltekit_found or remix_found or nuxt_found
    )
    status: Literal["ok", "no_payload"] = "ok" if any_found else "no_payload"

    return TargetResult(
        url=url,
        scanned_at=scanned_at,
        status=status,
        error=None,
        pages_router_found=pages_router_found,
        app_router_found=app_router_found,
        sveltekit_found=sveltekit_found,
        remix_found=remix_found,
        nuxt_found=nuxt_found,
        findings=findings,
    )
