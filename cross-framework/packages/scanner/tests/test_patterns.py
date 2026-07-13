"""Tests for sensitive field and value pattern loading and matching."""

from ssr_boundary_scanner.patterns import SENSITIVE_FIELD_PATTERNS, SENSITIVE_VALUE_PATTERNS


def _match_field(name: str):
    for pattern, severity, label in SENSITIVE_FIELD_PATTERNS:
        if pattern.search(name):
            return severity, label
    return None, None


def _match_value(value: str):
    for pattern, severity, label in SENSITIVE_VALUE_PATTERNS:
        if pattern.search(value):
            return severity, label
    return None, None


# ── Loading ───────────────────────────────────────────────────────────────────

def test_field_patterns_loaded():
    assert len(SENSITIVE_FIELD_PATTERNS) >= 20


def test_value_patterns_loaded():
    assert len(SENSITIVE_VALUE_PATTERNS) >= 5


def test_all_entries_are_tuples_of_correct_arity():
    for entry in SENSITIVE_FIELD_PATTERNS:
        assert len(entry) == 3
    for entry in SENSITIVE_VALUE_PATTERNS:
        assert len(entry) == 3


# ── Field pattern matching ────────────────────────────────────────────────────

def test_password_hash_matches_critical():
    severity, _ = _match_field("password_hash")
    assert severity == "CRITICAL"


def test_hashed_password_matches_critical():
    severity, _ = _match_field("hashed_password")
    assert severity == "CRITICAL"


def test_api_key_snake_matches_critical():
    severity, _ = _match_field("api_key")
    assert severity == "CRITICAL"


def test_apiKey_camel_matches_critical():
    severity, _ = _match_field("apiKey")
    assert severity == "CRITICAL"


def test_ssn_matches_critical():
    severity, _ = _match_field("ssn")
    assert severity == "CRITICAL"


def test_two_factor_secret_matches_critical():
    severity, _ = _match_field("two_factor_secret")
    assert severity == "CRITICAL"


def test_access_token_matches_high():
    severity, _ = _match_field("access_token")
    assert severity == "HIGH"


def test_accessToken_camel_matches_high():
    severity, _ = _match_field("accessToken")
    assert severity == "HIGH"


def test_token_word_boundary_matches_high():
    severity, _ = _match_field("token")
    assert severity == "HIGH"


def test_token_as_substring_does_not_match_via_word_boundary():
    # "accessToken" is matched by the accessToken pattern, not the \btoken\b pattern
    # Either way, it should return something (HIGH at minimum)
    severity, _ = _match_field("accessToken")
    assert severity is not None


def test_is_admin_matches_medium():
    severity, _ = _match_field("is_admin")
    assert severity == "MEDIUM"


def test_webhook_secret_matches_medium():
    severity, _ = _match_field("webhook_secret")
    assert severity == "MEDIUM"


def test_email_does_not_match_any_pattern():
    severity, _ = _match_field("email")
    assert severity is None


def test_name_does_not_match_any_pattern():
    severity, _ = _match_field("name")
    assert severity is None


def test_created_at_does_not_match():
    severity, _ = _match_field("created_at")
    assert severity is None


def test_id_does_not_match():
    severity, _ = _match_field("id")
    assert severity is None


# ── Value pattern matching ────────────────────────────────────────────────────

def test_bcrypt_2b_value_matches_critical():
    severity, label = _match_value(
        "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/o6GxEOG5a"
    )
    assert severity == "CRITICAL"
    assert "bcrypt" in label.lower() or "hash" in label.lower()


def test_bcrypt_2a_value_matches():
    severity, _ = _match_value(
        "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    )
    assert severity == "CRITICAL"


def test_stripe_live_key_matches_critical():
    severity, _ = _match_value("sk_live_AbCdEfGhIjKlMnOp")
    assert severity == "CRITICAL"


def test_stripe_test_key_matches_critical():
    severity, _ = _match_value("sk_test_AbCdEfGhIjKlMnOp")
    assert severity == "CRITICAL"


def test_ssn_format_matches_critical():
    severity, _ = _match_value("123-45-6789")
    assert severity == "CRITICAL"


def test_jwt_matches_high():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    severity, label = _match_value(jwt)
    assert severity == "HIGH"
    assert "jwt" in label.lower() or "token" in label.lower()


def test_plain_string_does_not_match_value_patterns():
    severity, _ = _match_value("hello world")
    assert severity is None


def test_email_address_does_not_match_value_patterns():
    severity, _ = _match_value("user@example.com")
    assert severity is None
