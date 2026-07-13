"""Tests for the Remix extractor."""

from pathlib import Path

import pytest

from ssr_boundary_scanner.extractors.remix import extract_remix_data

FIXTURES = Path(__file__).parent / "fixtures"


def test_returns_empty_when_no_remix_context():
    assert extract_remix_data("<html></html>") == []


def test_returns_empty_on_invalid_json():
    html = "<script>window.__remixContext = {not valid};</script>"
    assert extract_remix_data(html) == []


def test_extracts_v2_loader_data_from_vulnerable_fixture():
    html = (FIXTURES / "remix_vulnerable.html").read_text()
    result = extract_remix_data(html)
    assert len(result) > 0
    user_data = next((r for r in result if isinstance(r, dict) and "users" in r), None)
    assert user_data is not None
    assert len(user_data["users"]) == 2
    assert "password_hash" in user_data["users"][0]
    assert "api_key" in user_data["users"][0]


def test_no_sensitive_fields_in_secure_fixture():
    html = (FIXTURES / "remix_secure.html").read_text()
    result = extract_remix_data(html)
    user_data = next((r for r in result if isinstance(r, dict) and "users" in r), None)
    assert user_data is not None
    assert "password_hash" not in user_data["users"][0]
    assert "api_key" not in user_data["users"][0]


def test_handles_undefined_substitution():
    html = (
        '<script>window.__remixContext = '
        '{"state":{"loaderData":{"r":{"val":undefined}}}};</script>'
    )
    result = extract_remix_data(html)
    assert len(result) == 1
    assert result[0] == {"val": None}


def test_falls_back_to_full_context_when_no_loader_data():
    html = (
        '<script>window.__remixContext = '
        '{"url":"/","state":{"errors":null}};</script>'
    )
    result = extract_remix_data(html)
    # No loaderData and no matches → fallback to full context
    assert len(result) == 1


def test_handles_legacy_matches_format():
    html = (
        '<script>window.__remixContext = '
        '{"matches":[{"data":{"users":[{"id":1,"password_hash":"abc"}]}}]};</script>'
    )
    result = extract_remix_data(html)
    assert len(result) == 1
    assert "users" in result[0]
    assert result[0]["users"][0]["password_hash"] == "abc"
