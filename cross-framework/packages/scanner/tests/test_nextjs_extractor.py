"""Tests for the Next.js extractor (Pages Router + App Router)."""

from pathlib import Path

import pytest

from ssr_boundary_scanner.extractors.nextjs import extract_next_data, extract_rsc_payloads

FIXTURES = Path(__file__).parent / "fixtures"


# ── extract_next_data ─────────────────────────────────────────────────────────

def test_returns_none_when_no_next_data_tag():
    assert extract_next_data("<html><body></body></html>") is None


def test_returns_none_on_invalid_json():
    html = '<script id="__NEXT_DATA__" type="application/json">not-valid-json</script>'
    assert extract_next_data(html) is None


def test_returns_none_when_tag_has_no_content():
    html = '<script id="__NEXT_DATA__" type="application/json"></script>'
    assert extract_next_data(html) is None


def test_parses_vulnerable_fixture():
    html = (FIXTURES / "nextjs_vulnerable.html").read_text()
    data = extract_next_data(html)
    assert data is not None
    users = data["props"]["pageProps"]["users"]
    assert len(users) == 2
    assert "password_hash" in users[0]
    assert "api_key" in users[0]
    assert "ssn" in users[0]
    assert "two_factor_secret" in users[0]


def test_does_not_contain_sensitive_fields_in_secure_fixture():
    html = (FIXTURES / "nextjs_secure.html").read_text()
    data = extract_next_data(html)
    assert data is not None
    users = data["props"]["pageProps"]["users"]
    assert "password_hash" not in users[0]
    assert "api_key" not in users[0]


# ── extract_rsc_payloads ──────────────────────────────────────────────────────

def test_rsc_returns_empty_when_no_chunks():
    assert extract_rsc_payloads("<html></html>") == []


def test_rsc_skips_malformed_outer_array():
    html = "<script>self.__next_f.push([not valid json])</script>"
    assert extract_rsc_payloads(html) == []


def test_rsc_decodes_type0_dict():
    html = (
        '<script>self.__next_f.push([0, {"users": [{"id": 1, "password_hash": "abc"}]}])</script>'
    )
    result = extract_rsc_payloads(html)
    assert len(result) == 1
    assert result[0]["users"][0]["password_hash"] == "abc"


def test_rsc_decodes_type1_json_line():
    html = (
        '<script>self.__next_f.push([1, "0:{\\"id\\":1,\\"email\\":\\"a@b.com\\"}\\n"])</script>'
    )
    result = extract_rsc_payloads(html)
    assert len(result) >= 1
    assert any(isinstance(r, dict) and r.get("id") == 1 for r in result)
