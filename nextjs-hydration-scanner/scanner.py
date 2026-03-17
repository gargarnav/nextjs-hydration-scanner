"""
nextjs-hydration-scanner
========================
Automated vulnerability scanner for hydration leakage in Next.js applications.

Targets two serialization channels:
  1. Pages Router  — <script id="__NEXT_DATA__" type="application/json"> tag
  2. App Router    — self.__next_f.push([...]) RSC streaming payload chunks

For each target URL the scanner:
  - Fetches the HTML and parses any embedded Next.js hydration data
  - Recursively walks the deserialised data tree searching for sensitive field
    names and value patterns (credentials, keys, PII)
  - Assigns a severity level (CRITICAL / HIGH / MEDIUM) to each finding
  - Emits a structured JSON report and a human-readable console summary
  - Auto-saves every run to findings/ and maintains a cumulative index.json

Usage:
  python scanner.py --urls http://localhost:3000/vulnerable-pages \\
                           http://localhost:3000/vulnerable \\
                    --output report.json

  Or with a targets file (one URL per line):
  python scanner.py --targets targets.txt --output report.json --label my-run

  Enable verbose logging:
  python scanner.py --urls http://localhost:3000/ --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
# The root logger is configured in main(); this module-level logger inherits
# its level and handlers at runtime so that library imports stay silent.
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Findings store — auto-saves every run to findings/ and updates index.json
# ---------------------------------------------------------------------------

FINDINGS_DIR = Path(__file__).parent / "findings"


def _save_to_findings_store(report: dict[str, Any], label: str | None) -> Path:
    """Persist a scan report into the findings/ directory and update the index.

    Each invocation writes one timestamped JSON file and appends a one-line
    summary to findings/index.json so that all historical runs are queryable
    without loading individual report files.

    File-naming convention: findings/YYYY-MM-DDTHH-MM-SS[_label].json

    Args:
        report: The complete scan report dict as returned by build_json_report().
        label:  Optional short string embedded in the output filename to help
                distinguish runs (e.g. "vulnerable-baseline", "post-patch").

    Returns:
        The Path of the newly written report file.
    """
    FINDINGS_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    slug = f"_{label}" if label else ""
    report_path = FINDINGS_DIR / f"{timestamp}{slug}.json"

    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    # Maintain a cumulative index so callers can list all runs at a glance.
    index_path = FINDINGS_DIR / "index.json"
    index: list[dict[str, Any]] = []
    if index_path.exists():
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            # Corrupt index — start fresh rather than propagating bad data.
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


# ---------------------------------------------------------------------------
# Sensitive field-name patterns
# ---------------------------------------------------------------------------
# Each entry is (compiled_regex, severity, human_readable_label).
#
# ORDERING IS CRITICAL: the list is scanned top-to-bottom and the first match
# wins (break after match).  More specific patterns must precede their
# substrings, e.g.:
#   "password_hash" before "password"  — avoids mis-labelling a hash as a
#                                        generic "Password field"
#   "two_factor_secret" before "secret" — preserves a more descriptive label
#   "webhook_secret" before "secret"   — webhook secrets are MEDIUM, not CRITICAL
SENSITIVE_FIELD_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # ── CRITICAL: direct credential / secret material ─────────────────────
    # Hash fields before generic "password" to get the more precise label.
    (re.compile(r"password_hash",     re.I), "CRITICAL", "Password hash"),
    (re.compile(r"hashed_password",   re.I), "CRITICAL", "Password hash"),
    (re.compile(r"password",          re.I), "CRITICAL", "Password field"),
    (re.compile(r"passwd",            re.I), "CRITICAL", "Password field"),
    # TOTP seed fields — must precede the generic "secret" entry below.
    (re.compile(r"two_factor_secret", re.I), "CRITICAL", "2FA seed / TOTP secret"),
    (re.compile(r"totp_secret",       re.I), "CRITICAL", "2FA seed / TOTP secret"),
    (re.compile(r"otp_secret",        re.I), "CRITICAL", "2FA seed / TOTP secret"),
    (re.compile(r"private_key",       re.I), "CRITICAL", "Private key"),
    (re.compile(r"api_key",           re.I), "CRITICAL", "API key"),
    (re.compile(r"apikey",            re.I), "CRITICAL", "API key"),
    (re.compile(r"social_security",   re.I), "CRITICAL", "Social Security Number"),
    (re.compile(r"ssn",               re.I), "CRITICAL", "Social Security Number"),
    (re.compile(r"credit_card",       re.I), "CRITICAL", "Credit card number"),
    (re.compile(r"card_number",       re.I), "CRITICAL", "Credit card number"),
    (re.compile(r"cvv",               re.I), "CRITICAL", "CVV / CVC"),
    # ── HIGH: tokens and auth material ────────────────────────────────────
    # Specific token types precede the generic "\btoken\b" catch-all.
    (re.compile(r"access_token",      re.I), "HIGH",     "Access token"),
    (re.compile(r"refresh_token",     re.I), "HIGH",     "Refresh token"),
    (re.compile(r"auth_token",        re.I), "HIGH",     "Auth token"),
    (re.compile(r"session_token",     re.I), "HIGH",     "Session token"),
    (re.compile(r"\btoken\b",         re.I), "HIGH",     "Token field"),
    (re.compile(r"jwt",               re.I), "HIGH",     "JWT"),
    (re.compile(r"bearer",            re.I), "HIGH",     "Bearer credential"),
    (re.compile(r"encryption_key",    re.I), "HIGH",     "Encryption key"),
    (re.compile(r"signing_key",       re.I), "HIGH",     "Signing key"),
    # ── MEDIUM: internal / structural data that should not be client-visible
    # "webhook_secret" listed *before* the generic "secret" so it gets MEDIUM.
    (re.compile(r"webhook_secret",    re.I), "MEDIUM",   "Webhook secret"),
    (re.compile(r"secret",            re.I), "CRITICAL", "Secret / key material"),
    (re.compile(r"internal_id",       re.I), "MEDIUM",   "Internal identifier"),
    (re.compile(r"is_admin",          re.I), "MEDIUM",   "Admin flag"),
    (re.compile(r"admin",             re.I), "MEDIUM",   "Admin flag / role"),
    (re.compile(r"stripe_customer",   re.I), "MEDIUM",   "Stripe customer ID"),
]

# ---------------------------------------------------------------------------
# Sensitive value patterns (matched against the string *value*, not the key)
# ---------------------------------------------------------------------------
# These patterns catch credentials that have been stored under innocuous field
# names (e.g. a bcrypt hash stored in a field called "data").  Each entry is
# (compiled_regex, severity, human_readable_label).
SENSITIVE_VALUE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # Bcrypt hashes begin with $2a$, $2b$, or $2y$ followed by a cost factor
    # and exactly 53 characters of base-64 encoded salt+digest.
    (re.compile(r"^\$2[aby]\$\d+\$.{53}$"),
     "CRITICAL", "Bcrypt hash"),

    # Stripe live/test secret keys: sk_live_… or sk_test_… + ≥16 alnum chars.
    (re.compile(r"^sk_(live|test)_[A-Za-z0-9]{16,}$"),
     "CRITICAL", "Stripe-style live API key"),

    # US Social Security Numbers in canonical XXX-XX-XXXX format.
    (re.compile(r"^\d{3}-\d{2}-\d{4}$"),
     "CRITICAL", "SSN (XXX-XX-XXXX format)"),

    # GitHub Personal Access Tokens (classic format: ghp_ prefix + 36 chars).
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),
     "CRITICAL", "GitHub Personal Access Token"),

    # AWS Access Key IDs always start with AKIA followed by 16 uppercase chars.
    (re.compile(r"AKIA[0-9A-Z]{16}"),
     "CRITICAL", "AWS Access Key ID"),

    # JWTs: three base64url segments separated by dots, beginning with "eyJ"
    # (the base64url encoding of '{"').
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
     "HIGH",     "JWT token"),

    # Numeric strings in the 13–16 digit range overlap with PAN (payment card)
    # numbers.  Flag HIGH since false positives are possible (e.g. timestamps).
    (re.compile(r"^[0-9]{13,16}$"),
     "HIGH",     "Possible credit card number"),

    # Base32 alphabet (A-Z, 2-7) with optional padding matches TOTP secrets
    # stored as RFC-4648 Base32.  Case-insensitive to catch lower-case variants.
    (re.compile(r"^[A-Z2-7]+=*$", re.I),
     "HIGH",     "Base32 string (possible TOTP secret)"),
]

# Pre-compiled regex for RSC payload extraction.
# Matches the inline script pattern Next.js App Router uses to stream React
# Server Component data: self.__next_f.push([<row_type>, <data>])
# The [\s\S]*? (non-greedy dot-all) captures multi-line array literals without
# over-matching into adjacent push() calls.
_RSC_PUSH_RE: re.Pattern[str] = re.compile(
    r'self\.__next_f\.push\(\s*(\[[\s\S]*?\])\s*\)',
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single detected credential or sensitive-data exposure.

    Attributes:
        field_path:    Dot-notation path to the field within the JSON tree
                       (e.g. "__NEXT_DATA__.props.pageProps.user.password").
        field_name:    The bare key name at the leaf (e.g. "password").
        value_preview: A redacted, truncated preview of the exposed value.
                       Never contains the full secret.
        reason:        Human-readable explanation of why the field was flagged
                       (pattern matched, value format, etc.).
        severity:      One of "CRITICAL", "HIGH", or "MEDIUM".
        channel:       Data channel where the exposure was found:
                       "__NEXT_DATA__" (Pages Router) or "RSC_PAYLOAD" (App Router).
        match_type:    Whether the finding was triggered by the field name
                       ("field_name") or the value's format ("value_pattern").
    """

    field_path:    str
    field_name:    str
    value_preview: str
    reason:        str
    severity:      str
    channel:       str
    match_type:    str


@dataclass
class TargetResult:
    """Aggregated scan outcome for a single target URL.

    Attributes:
        url:                The URL that was scanned.
        scanned_at:         ISO-8601 timestamp of when the HTTP request was initiated.
        status:             "ok" — payload found and analysed;
                            "no_payload" — no Next.js hydration data detected;
                            "error" — HTTP fetch failed.
        error:              Error message string when status is "error", else None.
        pages_router_found: True if a __NEXT_DATA__ script tag was present.
        app_router_found:   True if RSC self.__next_f.push() chunks were present.
        findings:           List of Finding instances discovered during the scan.
    """

    url:                str
    scanned_at:         str
    status:             Literal["ok", "error", "no_payload"]
    error:              str | None
    pages_router_found: bool
    app_router_found:   bool
    findings:           list[Finding] = field(default_factory=list)

    def _count(self, severity: str) -> int:
        """Return the number of findings with the given severity level.

        Args:
            severity: One of "CRITICAL", "HIGH", or "MEDIUM".

        Returns:
            Count of matching findings.
        """
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def critical_count(self) -> int:
        """Number of CRITICAL-severity findings."""
        return self._count("CRITICAL")

    @property
    def high_count(self) -> int:
        """Number of HIGH-severity findings."""
        return self._count("HIGH")

    @property
    def medium_count(self) -> int:
        """Number of MEDIUM-severity findings."""
        return self._count("MEDIUM")


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------


def _value_preview(value: Any) -> str:
    """Generate a redacted, truncated preview of a potentially sensitive value.

    The preview intentionally never exposes more than a few characters of the
    original value so that report files can be shared without leaking secrets.

    Args:
        value: The raw value associated with a sensitive field.

    Returns:
        A redacted string, e.g. "pass**  [8 chars]" or "ab12...xy89  [32 chars]".
    """
    raw = str(value)
    length = len(raw)
    if length <= 12:
        # Short values: keep up to 4 chars then mask the remainder.
        return raw[:4] + "*" * (length - 4) if length > 4 else "****"
    # Longer values: show a few chars from each end with length annotation.
    return f"{raw[:6]}...{raw[-4:]}  [{length} chars]"


def _walk(
    node: Any,
    path: str,
    channel: str,
    findings: list[Finding],
    _field_flagged: set[str] | None = None,
) -> None:
    """Recursively walk a decoded JSON structure and collect sensitive findings.

    At each dict key the function applies two independent detection strategies:

    1. **Field-name matching**: checks whether the key matches any entry in
       SENSITIVE_FIELD_PATTERNS.  The first (highest-severity) match wins so
       that, e.g., "password_hash" is labelled as a hash rather than a plain
       password field.

    2. **Value-pattern matching**: for string leaf values not already flagged
       by strategy 1, checks whether the value itself looks like a known
       credential format (bcrypt hash, JWT, AWS key, etc.) via
       SENSITIVE_VALUE_PATTERNS.

    The ``_field_flagged`` set is used to prevent double-reporting: once a
    path has been flagged by field-name matching it is excluded from value-
    pattern matching at that same path.

    Args:
        node:           The current node in the JSON tree (any JSON type).
        path:           Dot-notation path accumulated so far (empty string at root).
        channel:        Serialization channel label ("__NEXT_DATA__" or "RSC_PAYLOAD").
        findings:       Mutable list that receives appended Finding objects.
        _field_flagged: Internal dedup set; initialised on first call, threaded
                        through all recursive invocations.
    """
    if _field_flagged is None:
        _field_flagged = set()

    if isinstance(node, dict):
        for key, value in node.items():
            current_path = f"{path}.{key}" if path else key

            # Strategy 1 — field-name check.
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
                    break  # First (highest-severity) match wins.

            # Strategy 2 — value-pattern check (string leaves only, not
            # already claimed by field-name matching above).
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

            # Recurse into nested structures regardless of whether this node
            # was flagged — children may independently contain sensitive data.
            _walk(value, current_path, channel, findings, _field_flagged)

    elif isinstance(node, list):
        for index, item in enumerate(node):
            _walk(item, f"{path}[{index}]", channel, findings, _field_flagged)


def _extract_next_data(html: str) -> dict[str, Any] | None:
    """Extract and parse the __NEXT_DATA__ JSON blob from Pages Router HTML.

    Next.js Pages Router embeds its serialized server-side props as a JSON
    object inside a <script id="__NEXT_DATA__" type="application/json"> tag.
    This function locates that tag, extracts its text content, and parses it.

    Args:
        html: Raw HTML response body from the target URL.

    Returns:
        Parsed JSON object as a dict, or None if the tag is absent or unparseable.
    """
    soup = BeautifulSoup(html, "html.parser")
    tag = soup.find("script", {"id": "__NEXT_DATA__"})
    if not tag or not tag.string:
        return None
    try:
        return json.loads(tag.string)
    except json.JSONDecodeError:
        logger.debug("__NEXT_DATA__ tag present but contained invalid JSON; skipping.")
        return None


def _extract_rsc_payloads(html: str) -> list[Any]:
    """Extract decoded objects from App Router RSC inline script chunks.

    Next.js App Router streams React Server Component data by inlining script
    tags that call:

        self.__next_f.push([<row_type>, <data>])

    Row semantics used by this scanner:
      - Row type 0: ``data`` is already a Python object after json.loads().
      - Row type 1: ``data`` is a multi-line string where each line follows the
                    format ``<row_id>:<json_value>``.  The JSON after the colon
                    is the actual component payload.

    Lines that are not valid JSON (React element shorthand, binary markers,
    etc.) are silently skipped.

    Args:
        html: Raw HTML response body from the target URL.

    Returns:
        List of all successfully decoded Python objects found within RSC chunks.
        Empty list if no RSC data is present or all chunks are non-JSON.
    """
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
            # Row type 1: multi-line string-encoded payload.
            # Each line: <row_id>:<json_value>  (colon is the separator)
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
                    # React element shorthand (e.g. "$L5"), binary row, or
                    # other non-JSON RSC protocol row type — not an error.
                    pass

        elif row_type == 0 and isinstance(data, (dict, list)):
            # Row type 0: serialized tree already deserialised by json.loads().
            decoded_objects.append(data)

    return decoded_objects


def _fetch(url: str, timeout: int = 15) -> tuple[str | None, str | None]:
    """Perform an HTTP GET request and return the response body.

    Args:
        url:     The target URL to fetch.
        timeout: Request timeout in seconds (default: 15).

    Returns:
        A tuple (html, error) where exactly one element is non-None:
          - On success: (response_text, None)
          - On failure: (None, error_message_string)
    """
    headers = {
        # Identify the scanner in server logs to facilitate responsible disclosure.
        "User-Agent": (
            "NextJS-Hydration-Scanner/1.0 "
            "(Academic Security Research; CAIS-2026)"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
        response.raise_for_status()
        return response.text, None
    except requests.RequestException as exc:
        return None, str(exc)


def scan_url(url: str, timeout: int = 15) -> TargetResult:
    """Perform a full hydration-leakage scan of a single Next.js URL.

    Fetches the page HTML, probes both the Pages Router (__NEXT_DATA__) and
    App Router (RSC payload) serialization channels, and returns a TargetResult
    containing all detected sensitive-data findings.

    Args:
        url:     The fully-qualified URL to scan (including scheme).
        timeout: HTTP request timeout forwarded to _fetch() (default: 15 s).

    Returns:
        A TargetResult populated with findings (may be empty) or with
        status="error" if the HTTP request failed.
    """
    # Record request-initiation time so it reflects actual scan time, not
    # the time at which results are processed.
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

    # ── Channel 1: Pages Router — __NEXT_DATA__ ───────────────────────────
    next_data = _extract_next_data(html)
    if next_data:
        pages_router_found = True
        logger.debug("Pages Router payload detected at %s", url)
        _walk(next_data, "__NEXT_DATA__", "__NEXT_DATA__", findings)

    # ── Channel 2: App Router — React Server Component payloads ──────────
    rsc_objects = _extract_rsc_payloads(html)
    if rsc_objects:
        app_router_found = True
        logger.debug("App Router RSC payload detected at %s (%d objects)", url, len(rsc_objects))
        for index, obj in enumerate(rsc_objects):
            _walk(obj, f"RSC[{index}]", "RSC_PAYLOAD", findings)

    status: Literal["ok", "no_payload"] = (
        "no_payload" if not pages_router_found and not app_router_found else "ok"
    )

    return TargetResult(
        url=url,
        scanned_at=scanned_at,
        status=status,
        error=None,
        pages_router_found=pages_router_found,
        app_router_found=app_router_found,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

# ANSI escape codes for terminal colorisation.
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "RESET":    "\033[0m",
}


def _color(text: str, severity: str) -> str:
    """Wrap text in ANSI color codes appropriate for the given severity level.

    Args:
        text:     The string to colorize.
        severity: One of "CRITICAL", "HIGH", or "MEDIUM".

    Returns:
        The text wrapped in the corresponding ANSI escape sequence, with a
        reset code appended.  Falls back to plain text for unknown severities.
    """
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{SEVERITY_COLORS['RESET']}"


def print_console_report(results: list[TargetResult]) -> None:
    """Print a human-readable, ANSI-colorised summary of all scan results.

    The report is written directly to stdout so that it can be piped or
    redirected independently of the logging stream.  Each target receives a
    section showing its status, detected channels, finding counts, and
    individual findings sorted by descending severity.

    Args:
        results: List of TargetResult objects from one or more scan_url() calls.
    """
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

        detected_channels: list[str] = []
        if result.pages_router_found:
            detected_channels.append("Pages Router (__NEXT_DATA__)")
        if result.app_router_found:
            detected_channels.append("App Router (RSC payload)")
        print(f"  Channels detected: {', '.join(detected_channels) if detected_channels else 'none'}")
        print(
            f"  Findings: {result.critical_count} CRITICAL  "
            f"{result.high_count} HIGH  "
            f"{result.medium_count} MEDIUM"
        )

        if not result.findings:
            print("  ✓ No sensitive fields detected in hydration payloads.")
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
    """Construct the structured JSON report from scan results.

    Produces a report dict suitable for serialisation to disk, containing
    scanner metadata, an aggregate summary, and per-target detail including
    all individual findings.

    Args:
        results: List of TargetResult objects from one or more scan_url() calls.

    Returns:
        A dict with keys: scanner, version, paper, generated_at, summary,
        and results (list of per-target dicts with serialised Finding objects).
    """
    return {
        "scanner":      "nextjs-hydration-scanner",
        "version":      "1.0.0",
        "paper":        "Hydration Leakage and Over-fetching in Next.js (CAIS-2026)",
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


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse command-line arguments, run the scanner, and emit reports.

    Supports two mutually exclusive input modes:
      --urls    One or more URLs provided directly on the command line.
      --targets Path to a plain-text file containing one URL per line
                (lines beginning with '#' and blank lines are ignored).

    Optional flags control output paths, run labelling, inter-request delay,
    HTTP timeout, and logging verbosity.

    Exit codes:
      0 — Scan completed (findings may or may not exist).
      1 — Fatal error (bad arguments, unreadable targets file, no URLs).
    """
    parser = argparse.ArgumentParser(
        description="Next.js Hydration Leakage Scanner (CAIS-2026 Research Tool)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
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
            "'vulnerable' or 'secure-phase3'. Helps distinguish runs in the index."
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

    # Configure logging based on verbosity flag.
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    # Resolve the list of target URLs from either --urls or --targets.
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

    saved_path = _save_to_findings_store(report, args.label)
    logger.info("[✓] Report auto-saved : %s", saved_path)
    logger.info("[✓] Index updated     : %s", FINDINGS_DIR / "index.json")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        logger.info("[✓] Report also saved : %s", args.output)


if __name__ == "__main__":
    main()
