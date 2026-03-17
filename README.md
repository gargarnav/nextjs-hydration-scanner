# Next.js Hydration Leakage Scanner

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Conference: CAIS 2026](https://img.shields.io/badge/conference-CAIS%202026-orange)

Automated detection of credential exposure in Next.js applications through server-to-client data serialization vulnerabilities.

---

## Academic Citation

This tool accompanies the research paper:

> **Hydration Leakage and Over-fetching in Next.js: The Security Implications of Server-to-Client Data Serialization**
>
> Submitted to: 3rd International Conference on Cybersecurity and Artificial Intelligence Strategies (CAIS 2026)
> Publication: Springer ACSAR Proceedings (pending acceptance)

If you use this tool in academic research, please cite:

```
[Citation will be updated upon acceptance]
```

---

## Overview

When Next.js developers return raw database records as component props, sensitive fields — password hashes, API keys, SSNs, 2FA secrets — are silently embedded in plain-text HTML and delivered to every client browser. No authentication bypass is required; the data is present in the initial page load for any visitor.

This scanner detects these exposures across both Next.js routing architectures:

- **Pages Router**: `__NEXT_DATA__` JSON script tag embedded in HTML
- **App Router**: React Server Component (RSC) streaming payloads (`self.__next_f.push(...)`)

---

## What It Detects

### By field name (key-based matching)

| Severity | Examples |
|----------|----------|
| CRITICAL | `password`, `password_hash`, `api_key`, `ssn`, `credit_card`, `private_key`, `two_factor_secret` |
| HIGH     | `access_token`, `refresh_token`, `jwt`, `bearer`, `signing_key` |
| MEDIUM   | `is_admin`, `internal_id`, `stripe_customer`, `webhook_secret` |

### By value pattern (format-based matching)

| Severity | Pattern |
|----------|---------|
| CRITICAL | Bcrypt hashes (`$2b$…`), Stripe API keys (`sk_live_…`), AWS Access Key IDs (`AKIA…`), GitHub PATs (`ghp_…`), SSNs (`XXX-XX-XXXX`) |
| HIGH     | JWT tokens (`eyJ…`), Base32 strings (possible TOTP secrets), 13–16 digit numbers (possible PANs) |

---

## Quick Start

### Installation

```bash
git clone https://github.com/gargarnav/next-js_vulnerabilities.git
cd next-js_vulnerabilities

pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan a single URL
python scanner.py --urls https://example.com

# Scan multiple URLs
python scanner.py --urls https://example.com/profile https://example.com/dashboard

# Scan from a targets file (one URL per line)
python scanner.py --targets targets.txt

# Export results to JSON
python scanner.py --urls https://example.com --output results.json

# Add a label to distinguish runs in the findings index
python scanner.py --targets targets.txt --label post-patch --output results.json

# Enable verbose (DEBUG-level) logging
python scanner.py --urls https://example.com --verbose
```

### Example Output

```
========================================================================
  Next.js Hydration Leakage Scanner — Results
  Scanned 2 target(s)  |  2026-03-17 14:32:01
========================================================================

────────────────────────────────────────────────────────────────────────
  URL   : http://localhost:3000/vulnerable-pages
  Status: ok
  Channels detected: Pages Router (__NEXT_DATA__)
  Findings: 8 CRITICAL  2 HIGH  1 MEDIUM

    [CRITICAL]  __NEXT_DATA__.props.pageProps.user.password_hash
      Reason  : Password hash — field name matches pattern /password_hash/i
      Channel : __NEXT_DATA__
      Preview : $2b$10...3bKm  [60 chars]

    [CRITICAL]  __NEXT_DATA__.props.pageProps.user.two_factor_secret
      Reason  : 2FA seed / TOTP secret — field name matches pattern /two_factor_secret/i
      Channel : __NEXT_DATA__
      Preview : JBSWY3...YPYI  [32 chars]

========================================================================
  TOTAL FINDINGS: 24 across 2 target(s)
========================================================================
```

---

## CLI Reference

```
usage: scanner.py [-h] (--urls URL [URL ...] | --targets FILE)
                  [--output FILE] [--label TEXT]
                  [--delay SECONDS] [--timeout SECONDS] [--verbose]

options:
  --urls URL [URL ...]  One or more target URLs to scan
  --targets FILE        File containing one URL per line (# comments ignored)
  --output FILE         Write JSON report to this path (in addition to auto-save)
  --label TEXT          Short label embedded in the auto-saved filename
  --delay SECONDS       Delay between requests in seconds (default: 0.5)
  --timeout SECONDS     HTTP request timeout in seconds (default: 15)
  --verbose             Enable DEBUG-level logging
```

---

## Output Format

Every run automatically saves a timestamped JSON report to `findings/` and updates `findings/index.json`:

```
findings/
├── index.json                              ← cumulative run index
├── 2026-03-17T14-32-01_post-patch.json     ← labelled run
└── 2026-03-17T09-15-44.json               ← unlabelled run
```

The JSON report structure:

```json
{
  "scanner": "nextjs-hydration-scanner",
  "version": "1.0.0",
  "generated_at": "2026-03-17T14:32:01+00:00",
  "summary": {
    "targets_scanned": 2,
    "targets_with_findings": 2,
    "total_findings": 24,
    "critical": 16,
    "high": 5,
    "medium": 3
  },
  "results": [
    {
      "url": "http://localhost:3000/vulnerable-pages",
      "status": "ok",
      "pages_router_found": true,
      "app_router_found": false,
      "findings": [
        {
          "field_path": "__NEXT_DATA__.props.pageProps.user.password_hash",
          "field_name": "password_hash",
          "value_preview": "$2b$10...3bKm  [60 chars]",
          "reason": "Password hash — field name matches pattern /password_hash/i",
          "severity": "CRITICAL",
          "channel": "__NEXT_DATA__",
          "match_type": "field_name"
        }
      ]
    }
  ]
}
```

---

## Detection Architecture

```
HTTP GET ─→ HTML
              │
              ├── BeautifulSoup ─→ <script id="__NEXT_DATA__"> ─→ JSON tree
              │                                                         │
              └── Regex _RSC_PUSH_RE ─→ self.__next_f.push([...])      │
                                              │                         │
                                         RSC row parser                 │
                                              │                         │
                                         Decoded objects ───────────────┘
                                                                        │
                                              ┌─────────────────────────┘
                                              ▼
                                        _walk() recursive traversal
                                              │
                                    ┌─────────┴──────────┐
                                    ▼                    ▼
                             Field-name match      Value-pattern match
                             (SENSITIVE_FIELD_     (SENSITIVE_VALUE_
                              PATTERNS)             PATTERNS)
                                    │                    │
                                    └─────────┬──────────┘
                                              ▼
                                        Finding objects
                                              │
                                    ┌─────────┴──────────┐
                                    ▼                    ▼
                             Console report         JSON report
                             (colorised)         (findings/ + --output)
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `requests` | ≥ 2.31.0 | HTTP fetching |
| `beautifulsoup4` | ≥ 4.12.0 | HTML parsing for `__NEXT_DATA__` extraction |
| `lxml` | ≥ 5.0.0 | Fast HTML parser backend for BeautifulSoup |

---

## Responsible Use

This tool is intended for:

- Security research on applications you own or have written permission to test
- Academic study of Next.js serialization vulnerabilities
- Penetration testing engagements with appropriate authorization

Scanning applications without authorization may violate computer fraud laws. Always obtain written permission before testing systems you do not own.

---

## Contact

- **Author**: Arnav Garg
- **Institution**: BITS Pilani, Pilani Campus
- **Email**: gargarnav2007@gmail.com
- **GitHub**: [@gargarnav](https://github.com/gargarnav)
- **LinkedIn**: [arnavrg](https://linkedin.com/in/arnavrg)
- **Portfolio**: [arnavgarg.in](https://arnavgarg.in)

---

## License

MIT License. See `LICENSE` for details.
