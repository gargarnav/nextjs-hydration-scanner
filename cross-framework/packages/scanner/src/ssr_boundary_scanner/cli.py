"""CLI entry point for ssr-boundary-scanner."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from .reporter import build_json_report, print_console_report
from .scanner import scan_url
from .store import save_to_findings_store
from .walker import TargetResult

logger = logging.getLogger(__name__)


def main() -> None:
    """Parse command-line arguments, run the scanner, and emit reports.

    Supports two mutually exclusive input modes:
      --urls    One or more URLs provided directly on the command line.
      --targets Path to a plain-text file containing one URL per line
                (lines beginning with '#' and blank lines are ignored).

    Exit codes:
      0 — Scan completed (findings may or may not exist).
      1 — Fatal error (bad arguments, unreadable targets file, no URLs).
    """
    parser = argparse.ArgumentParser(
        description=(
            "SSR Boundary Scanner — detect sensitive DB fields in SSR hydration payloads\n"
            "Supports Next.js, SvelteKit, Remix, and Nuxt 3/4"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--urls", nargs="+", metavar="URL",
        help="One or more target URLs to scan.",
    )
    input_group.add_argument(
        "--targets", metavar="FILE",
        help="Path to a file containing one URL per line.",
    )

    parser.add_argument(
        "--output", metavar="FILE", default=None,
        help="Also write the JSON report to this explicit path.",
    )
    parser.add_argument(
        "--label", metavar="TEXT", default=None,
        help=(
            "Short label embedded in the auto-saved filename, e.g. "
            "'vulnerable' or 'post-patch'. Helps distinguish runs in the index."
        ),
    )
    parser.add_argument(
        "--delay", type=float, default=0.5, metavar="SECONDS",
        help="Delay in seconds between consecutive requests (default: 0.5).",
    )
    parser.add_argument(
        "--timeout", type=int, default=15, metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 15).",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG-level logging output.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    if args.urls:
        urls: list[str] = args.urls
    else:
        try:
            with open(args.targets, encoding="utf-8") as fh:
                urls = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except OSError as exc:
            logger.error("Cannot read targets file: %s", exc)
            sys.exit(1)

    if not urls:
        logger.error("No URLs to scan.")
        sys.exit(1)

    results: list[TargetResult] = []
    for index, url in enumerate(urls, start=1):
        logger.info("[%d/%d] Scanning %s …", index, len(urls), url)
        result = scan_url(url, timeout=args.timeout)
        logger.info(
            "  → status: %s  |  findings: %d  (CRITICAL: %d  HIGH: %d  MEDIUM: %d)",
            result.status,
            len(result.findings),
            result.critical_count,
            result.high_count,
            result.medium_count,
        )
        results.append(result)
        if index < len(urls):
            time.sleep(args.delay)

    print_console_report(results)

    report = build_json_report(results)

    saved_path = save_to_findings_store(report, args.label)
    logger.info("[ok] Report auto-saved : %s", saved_path)
    logger.info("[ok] Index updated     : findings/index.json")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        logger.info("[ok] Report also saved : %s", args.output)


if __name__ == "__main__":
    main()
