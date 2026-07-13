"""Tests for the SvelteKit extractor."""

from pathlib import Path

import pytest

from ssr_boundary_scanner.extractors.sveltekit import extract_sveltekit_data

FIXTURES = Path(__file__).parent / "fixtures"


def test_returns_empty_when_no_sveltekit_data():
    assert extract_sveltekit_data("<html></html>") == []


def test_returns_empty_on_invalid_json():
    html = "<script>window.__sveltekit_data = {not valid json};</script>"
    assert extract_sveltekit_data(html) == []


def test_rehydrates_dehydrated_format():
    html = (
        '<script>window.__sveltekit_data = '
        '{"type":"data","data":[{"items":0},["a","b","c"]]};</script>'
    )
    result = extract_sveltekit_data(html)
    assert len(result) == 1
    assert result[0] == {"items": ["a", "b", "c"]}


def test_finds_sensitive_fields_in_vulnerable_fixture():
    html = (FIXTURES / "sveltekit_vulnerable.html").read_text()
    result = extract_sveltekit_data(html)
    assert len(result) == 1
    users = result[0]["users"]
    assert len(users) == 2
    assert "password_hash" in users[0]
    assert "api_key" in users[0]
    assert "two_factor_secret" in users[0]
    assert "ssn" in users[0]


def test_no_sensitive_fields_in_secure_fixture():
    html = (FIXTURES / "sveltekit_secure.html").read_text()
    result = extract_sveltekit_data(html)
    assert len(result) == 1
    users = result[0]["users"]
    assert "password_hash" not in users[0]
    assert "api_key" not in users[0]


def test_falls_back_to_raw_when_data_not_list():
    html = '<script>window.__sveltekit_data = {"key": "value"};</script>'
    result = extract_sveltekit_data(html)
    assert len(result) == 1
    assert result[0] == {"key": "value"}


def test_handles_undefined_substitution():
    # SvelteKit may emit `undefined` for missing values
    html = '<script>window.__sveltekit_data = {"x": undefined};</script>'
    result = extract_sveltekit_data(html)
    assert len(result) == 1
    assert result[0]["x"] is None
