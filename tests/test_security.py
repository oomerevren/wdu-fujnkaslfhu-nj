"""Tests for subprocess injection protection.

Tests the validate_auth_header() function and the security helpers
in all three workers (nuclei, zap, promptfoo).
"""

import pytest
from app.utils.security import validate_auth_header


# ── validate_auth_header ─────────────────────────────────────────────────


class TestValidateAuthHeader:
    """Tests for the auth_header injection validation."""

    # ── Valid cases ────────────────────────────────────────────────────

    @pytest.mark.parametrize("header", [
        None,
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
        "X-API-Key: my-api-key-12345",
        "Cookie: session=abc123; path=/",
        "Authorization: Bearer token-with-dashes_and_underscores",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
        "token-12345_with.dots@host.com",
    ])
    def test_valid_headers(self, header):
        """Valid headers must pass validation."""
        is_valid, msg = validate_auth_header(header)
        assert is_valid, f"Expected valid, got error: {msg}"

    # ── Invalid: None handling ─────────────────────────────────────────

    def test_none_header(self):
        """None must return valid (no header = safe)."""
        is_valid, msg = validate_auth_header(None)
        assert is_valid
        assert msg == ""

    # ── Invalid: type ──────────────────────────────────────────────────

    def test_non_string_header(self):
        """Non-string values must be rejected."""
        is_valid, msg = validate_auth_header(12345)
        assert not is_valid
        assert "must be a string" in msg

    # ── Invalid: empty ─────────────────────────────────────────────────

    def test_empty_string(self):
        """Empty string must be rejected."""
        is_valid, msg = validate_auth_header("")
        assert not is_valid
        assert "empty" in msg.lower()

    def test_whitespace_only(self):
        """Whitespace-only string must be rejected."""
        is_valid, msg = validate_auth_header("   ")
        assert not is_valid
        assert "empty" in msg.lower()

    # ── Invalid: length ────────────────────────────────────────────────

    def test_too_long_header(self):
        """Header exceeding 500 chars must be rejected."""
        long_value = "Bearer " + "A" * 500
        is_valid, msg = validate_auth_header(long_value)
        assert not is_valid
        assert "exceeds maximum length" in msg

    # ── Invalid: dangerous characters (injection vectors) ──────────────

    @pytest.mark.parametrize("injection_char,desc", [
        ("\n", "CRLF injection - LF"),
        ("\r", "CRLF injection - CR"),
        ("\0", "Null-byte injection"),
        ("|", "Shell pipe injection"),
        (";", "Shell command separator injection"),
        ("`", "Shell command substitution injection"),
        ("$", "Shell variable expansion injection"),
        ("(", "Shell subshell injection"),
        (")", "Shell subshell injection"),
        ("{", "Shell brace expansion injection"),
        ("}", "Shell brace expansion injection"),
    ])
    def test_dangerous_chars_blocked(self, injection_char, desc):
        """Dangerous injection characters must be blocked."""
        header = f"Authorization: Bearer{injection_char}extra"
        is_valid, msg = validate_auth_header(header)
        assert not is_valid, f"Should block {desc}"
        assert "blocked character" in msg

    @pytest.mark.parametrize("header", [
        "Authorization: Bearer token\nInjected: true",
        "Authorization: Bearer token\r\nX-Malicious: true",
        "Authorization: Bearer token|rm -rf /",
        "Authorization: Bearer token; echo hacked",
        "Authorization: Bearer token`id`",
        "Authorization: Bearer token$(whoami)",
        "Authorization: Bearer token{malicious}",
    ])
    def test_injection_attempts_blocked(self, header):
        """Known injection patterns must be blocked."""
        is_valid, msg = validate_auth_header(header)
        assert not is_valid, f"Should block injection: {header!r}"

    # ── Invalid: header name validation ────────────────────────────────

    @pytest.mark.parametrize("name", [
        "",
        " ",
        "123",
        "Auth@Header",
        "Header Name",
        "header\nname",
        "<script>",
    ])
    def test_invalid_header_name(self, name):
        """Invalid header names must be rejected."""
        header = f"{name}: value"
        is_valid, msg = validate_auth_header(header)
        assert not is_valid, f"Should reject header name: {name!r}"

    def test_missing_colon(self):
        """A header without a colon might still be valid as value-only."""
        # "Bearer token" is valid as value-only format
        is_valid, msg = validate_auth_header("Bearer token")
        assert is_valid

    # ── Invalid: header value ──────────────────────────────────────────

    def test_empty_value_after_colon(self):
        """Header with colon but empty value must be rejected."""
        is_valid, msg = validate_auth_header("Authorization: ")
        assert not is_valid
        assert "empty" in msg.lower()

    @pytest.mark.parametrize("bad_value", [
        "Authorization: value\nnewline",
        "Authorization: value|pipe",
        "Authorization: value;command",
        "Authorization: value`backtick`",
    ])
    def test_invalid_value_chars(self, bad_value):
        """Header values with dangerous characters must be rejected."""
        is_valid, msg = validate_auth_header(bad_value)
        assert not is_valid


# ── Worker security helpers ──────────────────────────────────────────────


class TestNucleiWorkerSecurity:
    """Tests for nuclei_worker security helpers."""

    def test_validate_target_url_valid(self):
        """Valid URL must pass validation."""
        from app.workers.nuclei_worker import _validate_target_url
        # Should not raise
        _validate_target_url("https://example.com")
        _validate_target_url("http://192.168.1.1:8080/path?q=1")
        _validate_target_url("https://sub.domain.com/path/to/resource")

    def test_validate_target_url_invalid(self):
        """Invalid URLs must raise ValueError."""
        from app.workers.nuclei_worker import _validate_target_url
        with pytest.raises(ValueError, match="must be a non-empty string"):
            _validate_target_url("")
        with pytest.raises(ValueError, match="must be a non-empty string"):
            _validate_target_url(None)  # type: ignore
        with pytest.raises(ValueError, match="blocked character"):
            _validate_target_url("https://example.com$(whoami)")
        with pytest.raises(ValueError, match="blocked character"):
            _validate_target_url("https://example.com;rm -rf /")

    def test_sanitize_auth_header_none(self):
        """None auth_header must return None."""
        from app.workers.nuclei_worker import _sanitize_auth_header_for_nuclei
        result = _sanitize_auth_header_for_nuclei(None, "https://example.com")
        assert result is None

    def test_sanitize_auth_header_valid(self):
        """Valid auth_header must return unchanged."""
        from app.workers.nuclei_worker import _sanitize_auth_header_for_nuclei
        result = _sanitize_auth_header_for_nuclei(
            "Authorization: Bearer test123", "https://example.com"
        )
        assert result == "Authorization: Bearer test123"

    def test_sanitize_auth_header_invalid(self):
        """Invalid auth_header must return None."""
        from app.workers.nuclei_worker import _sanitize_auth_header_for_nuclei
        result = _sanitize_auth_header_for_nuclei(
            "Authorization: Bearer\ninjected", "https://example.com"
        )
        assert result is None


class TestZapWorkerSecurity:
    """Tests for zap_worker security."""

    def test_validate_auth_header_valid(self):
        """Valid auth_header must pass validation."""
        is_valid, msg = validate_auth_header("Authorization: Bearer test123")
        assert is_valid

    def test_validate_auth_header_invalid(self):
        """Invalid auth_header must be rejected."""
        is_valid, msg = validate_auth_header("Authorization: Bearer\rinjected")
        assert not is_valid


class TestPromptFooWorkerSecurity:
    """Tests for promptfoo_worker security helpers."""

    def test_sanitize_auth_header_none(self):
        """None auth_header must return None."""
        from app.workers.promptfoo_worker import _sanitize_auth_header_for_promptfoo
        result = _sanitize_auth_header_for_promptfoo(None, "https://example.com")
        assert result is None

    def test_sanitize_auth_header_valid(self):
        """Valid auth_header must return unchanged."""
        from app.workers.promptfoo_worker import _sanitize_auth_header_for_promptfoo
        result = _sanitize_auth_header_for_promptfoo(
            "Bearer test123", "https://example.com"
        )
        assert result == "Bearer test123"

    def test_sanitize_auth_header_invalid(self):
        """Invalid auth_header must return None."""
        from app.workers.promptfoo_worker import _sanitize_auth_header_for_promptfoo
        result = _sanitize_auth_header_for_promptfoo(
            "Bearer test123\ninjected", "https://example.com"
        )
        assert result is None
