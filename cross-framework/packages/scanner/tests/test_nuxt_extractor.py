"""Tests for the Nuxt extractor."""

from pathlib import Path

import pytest

from ssr_boundary_scanner.extractors.nuxt import extract_nuxt_data

FIXTURES = Path(__file__).parent / "fixtures"


def test_returns_empty_when_no_nuxt_data():
    assert extract_nuxt_data("<html></html>") == []


def test_extracts_from_script_tag_in_vulnerable_fixture():
    html = (FIXTURES / "nuxt_vulnerable.html").read_text()
    result = extract_nuxt_data(html)
    assert len(result) == 1
    assert "users" in result[0]
    assert len(result[0]["users"]) == 2
    assert "password_hash" in result[0]["users"][0]
    assert "api_key" in result[0]["users"][0]


def test_no_sensitive_fields_in_secure_fixture():
    html = (FIXTURES / "nuxt_secure.html").read_text()
    result = extract_nuxt_data(html)
    assert len(result) == 1
    assert "password_hash" not in result[0]["users"][0]
    assert "api_key" not in result[0]["users"][0]


def test_extracts_from_window_nuxt_state():
    html = (
        '<script>window.__NUXT__ = '
        '{"state":{"users":[{"id":1,"api_key":"sk_live_xyz"}]}};</script>'
    )
    result = extract_nuxt_data(html)
    assert len(result) == 1
    assert "users" in result[0]
    assert result[0]["users"][0]["api_key"] == "sk_live_xyz"


def test_extracts_full_context_when_no_state_key():
    html = (
        '<script>window.__NUXT__ = '
        '{"data":{"users":[{"id":1}]},"fetchState":{}};</script>'
    )
    result = extract_nuxt_data(html)
    assert len(result) == 1
    assert "data" in result[0]


def test_handles_invalid_json_in_window_nuxt():
    html = "<script>window.__NUXT__ = {not valid};</script>"
    assert extract_nuxt_data(html) == []


def test_handles_undefined_substitution():
    html = (
        '<script>window.__NUXT__ = '
        '{"state":{"val":undefined}};</script>'
    )
    result = extract_nuxt_data(html)
    assert len(result) == 1
    assert result[0]["val"] is None
