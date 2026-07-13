"""Tests for the recursive walker and data structures."""

import pytest

from ssr_boundary_scanner.walker import Finding, TargetResult, _value_preview, _walk


# ── _value_preview ────────────────────────────────────────────────────────────

def test_value_preview_very_short():
    # Length <= 4 → masked entirely
    assert _value_preview("abc") == "****"
    assert _value_preview("ab") == "****"


def test_value_preview_medium_string():
    # 5–12 chars → first 4 shown, rest masked
    preview = _value_preview("secret12")
    assert preview.startswith("secr")
    assert "*" in preview


def test_value_preview_long_string():
    long = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/o6GxEOG5a"
    preview = _value_preview(long)
    assert "chars" in preview
    assert "..." in preview
    assert str(len(long)) in preview


# ── _walk — basic ─────────────────────────────────────────────────────────────

def test_walk_empty_dict():
    findings: list[Finding] = []
    _walk({}, "root", "TEST", findings)
    assert findings == []


def test_walk_empty_list():
    findings: list[Finding] = []
    _walk([], "root", "TEST", findings)
    assert findings == []


def test_walk_detects_password_hash():
    findings: list[Finding] = []
    _walk({"password_hash": "abc"}, "root", "TEST", findings)
    assert len(findings) == 1
    assert findings[0].field_name == "password_hash"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].match_type == "field_name"
    assert findings[0].channel == "TEST"


def test_walk_detects_api_key():
    findings: list[Finding] = []
    _walk({"api_key": "sk_live_abc"}, "root", "TEST", findings)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


def test_walk_detects_ssn():
    findings: list[Finding] = []
    _walk({"ssn": "123-45-6789"}, "root", "TEST", findings)
    assert len(findings) == 1
    assert findings[0].field_name == "ssn"
    assert findings[0].severity == "CRITICAL"


def test_walk_non_sensitive_fields_produce_no_findings():
    findings: list[Finding] = []
    _walk({"id": 1, "name": "Alice", "email": "a@b.com", "role": "user"}, "root", "TEST", findings)
    assert findings == []


# ── _walk — nesting ───────────────────────────────────────────────────────────

def test_walk_nested_object_builds_correct_path():
    findings: list[Finding] = []
    _walk({"pageProps": {"user": {"password_hash": "abc"}}}, "root", "TEST", findings)
    assert len(findings) == 1
    assert findings[0].field_path == "root.pageProps.user.password_hash"


def test_walk_array_of_users_finds_all():
    findings: list[Finding] = []
    users = [
        {"id": 1, "password_hash": "abc"},
        {"id": 2, "password_hash": "xyz"},
    ]
    _walk(users, "users", "TEST", findings)
    assert len(findings) == 2
    assert findings[0].field_path == "users[0].password_hash"
    assert findings[1].field_path == "users[1].password_hash"


# ── _walk — value patterns ────────────────────────────────────────────────────

def test_walk_detects_bcrypt_value_under_neutral_field():
    findings: list[Finding] = []
    _walk(
        {"data": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/o6GxEOG5a"},
        "root", "TEST", findings,
    )
    assert len(findings) == 1
    assert findings[0].match_type == "value_pattern"
    assert findings[0].severity == "CRITICAL"


def test_walk_detects_stripe_key_value():
    findings: list[Finding] = []
    _walk({"token": "sk_live_AbCdEfGhIjKlMnOp"}, "root", "TEST", findings)
    # "token" matches the \btoken\b field pattern (HIGH), so it's flagged by field name.
    # No separate value_pattern finding.
    assert len(findings) == 1
    assert findings[0].match_type == "field_name"


def test_walk_no_duplicate_finding_for_password_hash_with_bcrypt_value():
    findings: list[Finding] = []
    _walk(
        {"password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/o6GxEOG5a"},
        "root", "TEST", findings,
    )
    # field_name match fires; value_pattern is skipped because path is already flagged
    assert len(findings) == 1
    assert findings[0].match_type == "field_name"


# ── TargetResult ──────────────────────────────────────────────────────────────

def test_target_result_counts():
    findings = [
        Finding("p.a", "a", "***", "r", "CRITICAL", "C", "field_name"),
        Finding("p.b", "b", "***", "r", "HIGH",     "C", "field_name"),
        Finding("p.c", "c", "***", "r", "MEDIUM",   "C", "field_name"),
        Finding("p.d", "d", "***", "r", "CRITICAL", "C", "field_name"),
    ]
    result = TargetResult(
        url="http://x.com", scanned_at="2024-01-01T00:00:00Z",
        status="ok", error=None,
        pages_router_found=True, app_router_found=False,
        findings=findings,
    )
    assert result.critical_count == 2
    assert result.high_count == 1
    assert result.medium_count == 1
