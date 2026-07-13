"""Integration-style tests for scan_url with mocked HTTP."""

from pathlib import Path
from unittest.mock import patch

import pytest

from ssr_boundary_scanner.scanner import scan_url

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> tuple[str | None, str | None]:
    return (FIXTURES / name).read_text(), None


# ── Next.js ───────────────────────────────────────────────────────────────────

def test_nextjs_vulnerable_has_critical_findings():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=_load_fixture("nextjs_vulnerable.html")):
        result = scan_url("http://example.com/")
    assert result.status == "ok"
    assert result.pages_router_found is True
    assert result.critical_count > 0
    field_names = {f.field_name for f in result.findings}
    assert "password_hash" in field_names
    assert "api_key" in field_names
    assert "ssn" in field_names


def test_nextjs_secure_has_zero_findings():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=_load_fixture("nextjs_secure.html")):
        result = scan_url("http://example.com/secure")
    assert result.status == "ok"
    assert result.pages_router_found is True
    assert result.critical_count == 0
    assert result.high_count == 0
    assert result.medium_count == 0


# ── SvelteKit ─────────────────────────────────────────────────────────────────

def test_sveltekit_vulnerable_has_critical_findings():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=_load_fixture("sveltekit_vulnerable.html")):
        result = scan_url("http://localhost:5173/")
    assert result.status == "ok"
    assert result.sveltekit_found is True
    assert result.pages_router_found is False
    assert result.critical_count > 0


def test_sveltekit_secure_has_zero_findings():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=_load_fixture("sveltekit_secure.html")):
        result = scan_url("http://localhost:5173/secure")
    assert result.status == "ok"
    assert result.sveltekit_found is True
    assert result.critical_count == 0


# ── Remix ─────────────────────────────────────────────────────────────────────

def test_remix_vulnerable_has_critical_findings():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=_load_fixture("remix_vulnerable.html")):
        result = scan_url("http://localhost:3000/")
    assert result.status == "ok"
    assert result.remix_found is True
    assert result.critical_count > 0


def test_remix_secure_has_zero_findings():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=_load_fixture("remix_secure.html")):
        result = scan_url("http://localhost:3000/secure")
    assert result.status == "ok"
    assert result.remix_found is True
    assert result.critical_count == 0


# ── Nuxt ──────────────────────────────────────────────────────────────────────

def test_nuxt_vulnerable_has_critical_findings():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=_load_fixture("nuxt_vulnerable.html")):
        result = scan_url("http://localhost:3001/")
    assert result.status == "ok"
    assert result.nuxt_found is True
    assert result.critical_count > 0


def test_nuxt_secure_has_zero_findings():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=_load_fixture("nuxt_secure.html")):
        result = scan_url("http://localhost:3001/api/users-secure")
    assert result.status == "ok"
    assert result.nuxt_found is True
    assert result.critical_count == 0


# ── Error / edge cases ────────────────────────────────────────────────────────

def test_scan_returns_error_on_fetch_failure():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=(None, "Connection refused")):
        result = scan_url("http://localhost:9999/")
    assert result.status == "error"
    assert result.error == "Connection refused"
    assert result.findings == []
    assert result.pages_router_found is False


def test_scan_no_payload_for_plain_html():
    with patch("ssr_boundary_scanner.scanner._fetch", return_value=("<html><body>Hello</body></html>", None)):
        result = scan_url("http://example.com/plain")
    assert result.status == "no_payload"
    assert result.findings == []
