"""
nextjs-hydration-scanner  —  Phase 2 Tool
==========================================
Automated vulnerability scanner for hydration leakage in Next.js applications.

Targets two serialization channels:
  1. Pages Router  — <script id="__NEXT_DATA__" type="application/json"> tag
  2. App Router    — self.__next_f.push([...]) RSC streaming payload chunks

For each target URL the scanner:
  - Fetches the HTML and any RSC payload (via the ?_rsc= header trick)
  - Extracts and deserialises all Next.js hydration data
  - Recursively walks the data tree looking for sensitive field names and values
  - Assigns a severity level (CRITICAL / HIGH / MEDIUM) to each finding
  - Emits a structured JSON report and a human-readable console summary

Usage:
  python scanner.py --urls http://localhost:3000/vulnerable-pages \
                           http://localhost:3000/vulnerable \
                    --output report.json

  Or with a targets file (one URL per line):
  python scanner.py --targets targets.txt --output report.json
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Findings store — auto-saves every run to findings/ and updates index.json
# ---------------------------------------------------------------------------

FINDINGS_DIR = Path(__file__).parent / "findings"


def _save_to_findings_store(report: dict, label: str | None) -> Path:
    """
    Persist a scan report into the findings/ directory.

    File name: findings/YYYY-MM-DDTHH-MM-SS[_label].json
    Also updates findings/index.json with a one-line summary of every run.
    """
    FINDINGS_DIR.mkdir(exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    slug = f"_{label}" if label else ""
    report_path = FINDINGS_DIR / f"{ts}{slug}.json"

    with open(report_path, "w") as fh:
        json.dump(report, fh, indent=2)

    # --- update index.json ---
    index_path = FINDINGS_DIR / "index.json"
    index: list[dict] = []
    if index_path.exists():
        try:
            index = json.loads(index_path.read_text())
        except json.JSONDecodeError:
            index = []

    summary = report.get("summary", {})
    index.append({
        "file": report_path.name,
        "scanned_at": report.get("generated_at", ts),
        "label": label,
        "targets_scanned": summary.get("targets_scanned", 0),
        "total_findings": summary.get("total_findings", 0),
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
        "medium": summary.get("medium", 0),
        "urls": [r["url"] for r in report.get("results", [])],
    })

    with open(index_path, "w") as fh:
        json.dump(index, fh, indent=2)

    return report_path


# ---------------------------------------------------------------------------
# Sensitive field-name patterns
# ---------------------------------------------------------------------------
# Each entry is (compiled_regex, severity, label).
# ORDER MATTERS: the first matching pattern wins (break after match).
# More specific patterns must appear before their substrings.
#   e.g. "password_hash" before "password", "two_factor_secret" before "secret".
SENSITIVE_FIELD_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # CRITICAL — direct credential / secret material (specific before general)
    (re.compile(r"password_hash",         re.I), "CRITICAL", "Password hash"),
    (re.compile(r"hashed_password",       re.I), "CRITICAL", "Password hash"),
    (re.compile(r"password",              re.I), "CRITICAL", "Password field"),
    (re.compile(r"passwd",                re.I), "CRITICAL", "Password field"),
    (re.compile(r"two_factor_secret",     re.I), "CRITICAL", "2FA seed / TOTP secret"),
    (re.compile(r"totp_secret",           re.I), "CRITICAL", "2FA seed / TOTP secret"),
    (re.compile(r"otp_secret",            re.I), "CRITICAL", "2FA seed / TOTP secret"),
    (re.compile(r"private_key",           re.I), "CRITICAL", "Private key"),
    (re.compile(r"api_key",              re.I), "CRITICAL", "API key"),
    (re.compile(r"apikey",               re.I), "CRITICAL", "API key"),
    (re.compile(r"social_security",       re.I), "CRITICAL", "Social Security Number"),
    (re.compile(r"ssn",                  re.I), "CRITICAL", "Social Security Number"),
    (re.compile(r"credit_card",           re.I), "CRITICAL", "Credit card number"),
    (re.compile(r"card_number",           re.I), "CRITICAL", "Credit card number"),
    (re.compile(r"cvv",                  re.I), "CRITICAL", "CVV / CVC"),
    # HIGH — tokens and auth material (specific before general)
    (re.compile(r"access_token",          re.I), "HIGH",     "Access token"),
    (re.compile(r"refresh_token",         re.I), "HIGH",     "Refresh token"),
    (re.compile(r"auth_token",            re.I), "HIGH",     "Auth token"),
    (re.compile(r"session_token",         re.I), "HIGH",     "Session token"),
    (re.compile(r"\btoken\b",            re.I), "HIGH",     "Token field"),
    (re.compile(r"jwt",                  re.I), "HIGH",     "JWT"),
    (re.compile(r"bearer",               re.I), "HIGH",     "Bearer credential"),
    (re.compile(r"encryption_key",        re.I), "HIGH",     "Encryption key"),
    (re.compile(r"signing_key",           re.I), "HIGH",     "Signing key"),
    # MEDIUM — internal / structural data that should not be client-visible
    # webhook_secret before secret so it gets MEDIUM (not CRITICAL) severity
    (re.compile(r"webhook_secret",        re.I), "MEDIUM",   "Webhook secret"),
    (re.compile(r"secret",               re.I), "CRITICAL", "Secret / key material"),
    (re.compile(r"internal_id",           re.I), "MEDIUM",   "Internal identifier"),
    (re.compile(r"is_admin",             re.I), "MEDIUM",   "Admin flag"),
    (re.compile(r"admin",                re.I), "MEDIUM",   "Admin flag / role"),
    (re.compile(r"stripe_customer",       re.I), "MEDIUM",   "Stripe customer ID"),
]

# ---------------------------------------------------------------------------
# Sensitive value patterns (regex against the *value* string)
# ---------------------------------------------------------------------------
SENSITIVE_VALUE_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^\$2[aby]\$\d+\$.{53}$"),                              "CRITICAL", "Bcrypt hash"),
    (re.compile(r"^sk_(live|test)_[A-Za-z0-9]{16,}$"),                  "CRITICAL", "Stripe-style live API key"),
    (re.compile(r"^\d{3}-\d{2}-\d{4}$"),                                "CRITICAL", "SSN (XXX-XX-XXXX format)"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),                                 "CRITICAL", "GitHub Personal Access Token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),                                   "CRITICAL", "AWS Access Key ID"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "HIGH",     "JWT token"),
    (re.compile(r"^[0-9]{13,16}$"),                                     "HIGH",     "Possible credit card number"),
    (re.compile(r"^[A-Z2-7]+=*$",                           re.I),      "HIGH",     "Base32 string (possible TOTP secret)"),
]

# Module-level compiled regex for RSC payload extraction (avoids recompilation per URL)
_RSC_PUSH_RE = re.compile(
    r'self\.__next_f\.push\(\s*(\[[\s\S]*?\])\s*\)',
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    field_path: str    # dot-notation path inside the JSON tree
    field_name: str    # last key segment
    value_preview: str # redacted preview of value
    reason: str        # human-readable description of why it flagged
    severity: str      # CRITICAL | HIGH | MEDIUM
    channel: str       # "__NEXT_DATA__" | "RSC_PAYLOAD"
    match_type: str    # "field_name" | "value_pattern"


@dataclass
class TargetResult:
    url: str
    scanned_at: str
    status: Literal["ok", "error", "no_payload"]
    error: str | None
    pages_router_found: bool
    app_router_found: bool
    findings: list[Finding] = field(default_factory=list)

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


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------

def _value_preview(value: Any) -> str:
    """Return a safe, truncated preview of a value (never full secrets in reports)."""
    s = str(value)
    if len(s) <= 12:
        return s[:4] + "*" * (len(s) - 4) if len(s) > 4 else "****"
    return s[:6] + "..." + s[-4:] + f"  [{len(s)} chars]"


def _walk(
    node: Any,
    path: str,
    channel: str,
    findings: list[Finding],
    _field_flagged: set[str] | None = None,  # paths already flagged by field-name; O(1) dedup
) -> None:
    """
    Recursively walk a decoded JSON structure.
    At each dict key, check:
      1. Does the key name match a sensitive field pattern?
      2. Does the string value match a sensitive value pattern?
    """
    if _field_flagged is None:
        _field_flagged = set()

    if isinstance(node, dict):
        for key, value in node.items():
            current_path = f"{path}.{key}" if path else key

            # --- field name check ---
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
                    break  # first (highest-severity) pattern wins

            # --- value pattern check (only for string leaves not already flagged) ---
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
        for i, item in enumerate(node):
            _walk(item, f"{path}[{i}]", channel, findings, _field_flagged)


def _extract_next_data(html: str) -> dict | None:
    """Extract and parse the __NEXT_DATA__ JSON blob from Pages Router HTML."""
    soup = BeautifulSoup(html, "html.parser")
    tag = soup.find("script", {"id": "__NEXT_DATA__"})
    if not tag or not tag.string:
        return None
    try:
        return json.loads(tag.string)
    except json.JSONDecodeError:
        return None


def _extract_rsc_payloads(html: str) -> list[Any]:
    """
    Extract decoded objects from App Router RSC inline script chunks.

    Next.js App Router inlines RSC as:
        self.__next_f.push([<row_type>, <data>])
    Row type 1 carries the actual React tree JSON as a string.
    We collect all parseable JSON objects found within these chunks.
    """
    results: list[Any] = []

    for m in _RSC_PUSH_RE.finditer(html):
        try:
            chunk = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue

        if not isinstance(chunk, list) or len(chunk) < 2:
            continue

        row_type, data = chunk[0], chunk[1]

        # Row type 1 = module / component tree data (string-encoded JSON)
        if row_type == 1 and isinstance(data, str):
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Each RSC line is:  <row_id>:<json_value>
                colon_pos = line.find(":")
                if colon_pos == -1:
                    continue
                try:
                    results.append(json.loads(line[colon_pos + 1:]))
                except json.JSONDecodeError:
                    pass  # React element shorthand or non-JSON row; skip

        # Row type 0 = serialized tree (already a Python object after json.loads)
        elif row_type == 0 and isinstance(data, (dict, list)):
            results.append(data)

    return results


def _fetch(url: str, timeout: int = 15) -> tuple[str | None, str | None]:
    """Fetch URL, return (html, error_string)."""
    headers = {
        "User-Agent": (
            "NextJS-Hydration-Scanner/1.0 "
            "(Academic Security Research; CAIS-2026)"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        return resp.text, None
    except requests.RequestException as exc:
        return None, str(exc)


def scan_url(url: str) -> TargetResult:
    """Full scan of a single URL. Returns a TargetResult."""
    # scanned_at records request initiation time, not completion
    now = datetime.now(timezone.utc).isoformat()
    html, err = _fetch(url)

    if err:
        return TargetResult(
            url=url, scanned_at=now, status="error", error=err,
            pages_router_found=False, app_router_found=False,
        )

    findings: list[Finding] = []
    pages_found = False
    app_found = False

    # --- Channel 1: Pages Router __NEXT_DATA__ ---
    next_data = _extract_next_data(html)
    if next_data:
        pages_found = True
        _walk(next_data, "__NEXT_DATA__", "__NEXT_DATA__", findings)

    # --- Channel 2: App Router RSC payloads ---
    rsc_objects = _extract_rsc_payloads(html)
    if rsc_objects:
        app_found = True
        for i, obj in enumerate(rsc_objects):
            _walk(obj, f"RSC[{i}]", "RSC_PAYLOAD", findings)

    status: Literal["ok", "no_payload"] = "no_payload" if (not pages_found and not app_found) else "ok"

    return TargetResult(
        url=url,
        scanned_at=now,
        status=status,
        error=None,
        pages_router_found=pages_found,
        app_router_found=app_found,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "RESET":    "\033[0m",
}


def _color(text: str, severity: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{SEVERITY_COLORS['RESET']}"


def print_console_report(results: list[TargetResult]) -> None:
    divider = "=" * 72

    print(f"\n{divider}")
    print("  Next.js Hydration Leakage Scanner — Results")
    print(f"  Scanned {len(results)} target(s)  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(divider)

    for result in results:
        print(f"\n{'─' * 72}")
        print(f"  URL   : {result.url}")
        print(f"  Status: {result.status}")
        if result.error:
            print(f"  Error : {result.error}")
            continue

        channels = []
        if result.pages_router_found:
            channels.append("Pages Router (__NEXT_DATA__)")
        if result.app_router_found:
            channels.append("App Router (RSC payload)")
        print(f"  Channels detected: {', '.join(channels) if channels else 'none'}")
        print(f"  Findings: {result.critical_count} CRITICAL  "
              f"{result.high_count} HIGH  "
              f"{result.medium_count} MEDIUM")

        if not result.findings:
            print("  ✓ No sensitive fields detected in hydration payloads.")
            continue

        for f in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)):
            print(f"\n    {_color(f'[{f.severity}]', f.severity)}  {f.field_path}")
            print(f"      Reason  : {f.reason}")
            print(f"      Channel : {f.channel}")
            print(f"      Preview : {f.value_preview}")

    total_findings = sum(len(r.findings) for r in results)
    print(f"\n{divider}")
    print(f"  TOTAL FINDINGS: {total_findings} across {len(results)} target(s)")
    print(divider + "\n")


def build_json_report(results: list[TargetResult]) -> dict:
    return {
        "scanner": "nextjs-hydration-scanner",
        "version": "1.0.0",
        "paper": "Hydration Leakage and Over-fetching in Next.js (CAIS-2026)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "targets_scanned": len(results),
            "targets_with_findings": sum(1 for r in results if r.findings),
            "total_findings": sum(len(r.findings) for r in results),
            "critical": sum(r.critical_count for r in results),
            "high": sum(r.high_count for r in results),
            "medium": sum(r.medium_count for r in results),
        },
        "results": [
            {
                "url": result.url,
                "scanned_at": result.scanned_at,
                "status": result.status,
                "error": result.error,
                "pages_router_found": result.pages_router_found,
                "app_router_found": result.app_router_found,
                "finding_counts": {
                    "critical": result.critical_count,
                    "high": result.high_count,
                    "medium": result.medium_count,
                },
                "findings": [asdict(f) for f in result.findings],
            }
            for result in results
        ],
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Next.js Hydration Leakage Scanner (CAIS-2026 Research Tool)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--urls", nargs="+", metavar="URL",
        help="One or more target URLs to scan.",
    )
    group.add_argument(
        "--targets", metavar="FILE",
        help="Path to a file containing one URL per line.",
    )
    parser.add_argument(
        "--output", metavar="FILE", default=None,
        help="Also write JSON report to this explicit path.",
    )
    parser.add_argument(
        "--label", metavar="TEXT", default=None,
        help=(
            "Short label embedded in the auto-saved filename, e.g. "
            "'vulnerable' or 'secure-phase3'. Helps distinguish runs in the index."
        ),
    )
    parser.add_argument(
        "--delay", type=float, default=0.5, metavar="SECONDS",
        help="Delay in seconds between requests (default: 0.5).",
    )
    parser.add_argument(
        "--timeout", type=int, default=15, metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 15).",
    )
    args = parser.parse_args()

    if args.urls:
        urls = args.urls
    else:
        try:
            with open(args.targets) as fh:
                urls = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except OSError as exc:
            print(f"[ERROR] Cannot read targets file: {exc}", file=sys.stderr)
            sys.exit(1)

    if not urls:
        print("[ERROR] No URLs to scan.", file=sys.stderr)
        sys.exit(1)

    results: list[TargetResult] = []
    for i, url in enumerate(urls):
        print(f"[{i+1}/{len(urls)}] Scanning {url} ...", end=" ", flush=True)
        result = scan_url(url)
        print(f"{result.status}  —  {len(result.findings)} finding(s)")
        results.append(result)
        if i < len(urls) - 1:
            time.sleep(args.delay)

    print_console_report(results)

    report = build_json_report(results)

    saved_path = _save_to_findings_store(report, args.label)
    print(f"[✓] Report auto-saved : {saved_path}")
    print(f"[✓] Index updated     : {FINDINGS_DIR / 'index.json'}")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"[✓] Report also saved : {args.output}")


if __name__ == "__main__":
    main()
