"""Console and JSON reporting for scan results."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from .walker import TargetResult

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "RESET":    "\033[0m",
}


def _color(text: str, severity: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{SEVERITY_COLORS['RESET']}"


def print_console_report(results: list[TargetResult]) -> None:
    divider = "=" * 72
    print(f"\n{divider}")
    print("  SSR Boundary Scanner — Results")
    print(f"  Scanned {len(results)} target(s)  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(divider)

    for result in results:
        print(f"\n{'─' * 72}")
        print(f"  URL   : {result.url}")
        print(f"  Status: {result.status}")
        if result.error:
            print(f"  Error : {result.error}")
            continue

        channels: list[str] = []
        if result.pages_router_found:
            channels.append("Next.js Pages Router (__NEXT_DATA__)")
        if result.app_router_found:
            channels.append("Next.js App Router (RSC)")
        if result.sveltekit_found:
            channels.append("SvelteKit (__sveltekit_data)")
        if result.remix_found:
            channels.append("Remix (__remixContext)")
        if result.nuxt_found:
            channels.append("Nuxt (__NUXT_DATA__)")
        print(f"  Channels detected: {', '.join(channels) if channels else 'none'}")
        print(
            f"  Findings: {result.critical_count} CRITICAL  "
            f"{result.high_count} HIGH  "
            f"{result.medium_count} MEDIUM"
        )

        if not result.findings:
            print("  No sensitive fields detected in hydration payloads.")
            continue

        for finding in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)):
            print(f"\n    {_color(f'[{finding.severity}]', finding.severity)}  {finding.field_path}")
            print(f"      Reason  : {finding.reason}")
            print(f"      Channel : {finding.channel}")
            print(f"      Preview : {finding.value_preview}")

    total_findings = sum(len(r.findings) for r in results)
    print(f"\n{divider}")
    print(f"  TOTAL FINDINGS: {total_findings} across {len(results)} target(s)")
    print(divider + "\n")


def build_json_report(results: list[TargetResult]) -> dict[str, Any]:
    return {
        "scanner":      "ssr-boundary-scanner",
        "version":      "0.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "targets_scanned":       len(results),
            "targets_with_findings": sum(1 for r in results if r.findings),
            "total_findings":        sum(len(r.findings) for r in results),
            "critical":              sum(r.critical_count for r in results),
            "high":                  sum(r.high_count for r in results),
            "medium":                sum(r.medium_count for r in results),
        },
        "results": [
            {
                "url":                result.url,
                "scanned_at":         result.scanned_at,
                "status":             result.status,
                "error":              result.error,
                "pages_router_found": result.pages_router_found,
                "app_router_found":   result.app_router_found,
                "sveltekit_found":    result.sveltekit_found,
                "remix_found":        result.remix_found,
                "nuxt_found":         result.nuxt_found,
                "finding_counts": {
                    "critical": result.critical_count,
                    "high":     result.high_count,
                    "medium":   result.medium_count,
                },
                "findings": [asdict(f) for f in result.findings],
            }
            for result in results
        ],
    }
