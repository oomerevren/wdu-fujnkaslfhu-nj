import re
from typing import Optional
from cryptography.fernet import Fernet

from app.config import settings

# ── Auth Header Validation ─────────────────────────────────────────────────

# Dangerous characters that must never appear in any header value
# These could be used for CRLF injection, shell injection, or YAML injection
DANGEROUS_HEADER_CHARS = frozenset([
    '\n',  # CRLF injection
    '\r',  # CRLF injection
    '\0',  # Null-byte injection
    '|',   # Shell pipe
    ';',   # Shell command separator
    '`',   # Shell command substitution
    '$',   # Shell variable expansion
    '(',   # Shell subshell
    ')',   # Shell subshell
    '{',   # Shell brace expansion
    '}',   # Shell brace expansion
])

# Pattern for valid header names (RFC 7230: token)
HEADER_NAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]*$')

# Pattern for safe header value characters
# Allows: alphanumeric, common punctuation used in tokens and credentials
SAFE_HEADER_VALUE_PATTERN = re.compile(r'^[a-zA-Z0-9_:;/\-.,=+@!%~#*\[\] ]+$')

MAX_HEADER_LENGTH = 500


def validate_auth_header(header_value: Optional[str]) -> tuple[bool, str]:
    """Validate an HTTP auth header value for injection attacks.

    Accepts two formats:
      1. Full header: ``"HeaderName: value"`` (e.g. ``"Authorization: Bearer xxx"``)
      2. Value only:  ``"Bearer xxx"`` (used in PromptFoo worker config)

    Validation rules:
      - ``None`` is valid (no header provided).
      - Max length of 500 characters.
      - Header name (if present) must be alphanumeric with hyphens/underscores.
      - Header value must contain only safe characters.
      - Dangerous shell/CRLF/YAML injection characters are blocked.

    Args:
        header_value: The header string to validate, or ``None``.

    Returns:
        Tuple of ``(is_valid, error_message)``.
    """
    if header_value is None:
        return True, ""

    if not isinstance(header_value, str):
        return False, "Auth header must be a string"

    if not header_value.strip():
        return False, "Auth header cannot be empty"

    if len(header_value) > MAX_HEADER_LENGTH:
        return False, (
            f"Auth header exceeds maximum length of {MAX_HEADER_LENGTH} "
            f"characters (got {len(header_value)})"
        )

    # ── Check for dangerous characters first ───────────────────────────
    for ch in DANGEROUS_HEADER_CHARS:
        if ch in header_value:
            if ch == ';' and header_value.lower().startswith("cookie:"):
                continue
            return False, f"Auth header contains blocked character: {repr(ch)}"

    # ── Determine format and validate accordingly ──────────────────────
    if ":" in header_value:
        # Full format: "HeaderName: value"
        name, _, value_part = header_value.partition(":")
        name_stripped = name.strip()
        value_stripped = value_part.strip()

        if not name_stripped:
            return False, "Header name cannot be empty"

        if not HEADER_NAME_PATTERN.match(name_stripped):
            return False, (
                "Header name contains invalid characters. "
                "Use only letters, digits, hyphens and underscores."
            )

        if not value_stripped:
            return False, "Header value cannot be empty after the colon"

        if not SAFE_HEADER_VALUE_PATTERN.match(value_stripped):
            return False, (
                "Header value contains invalid characters. "
                "Use only alphanumeric characters and common punctuations."
            )
    else:
        # Value-only format: "Bearer eyJ..."
        if not SAFE_HEADER_VALUE_PATTERN.match(header_value.strip()):
            return False, (
                "Auth header value contains invalid characters."
            )

    return True, ""


# ── Encryption ────────────────────────────────────────────────────────────


def encrypt_value(value: str) -> str:
    """Encrypt a sensitive string using Fernet symmetric encryption.

    In production, ENCRYPTION_KEY must be set — raises ValueError if missing.
    In development, falls back to plaintext for convenience.
    """
    if not settings.ENCRYPTION_KEY:
        if settings.ENV == "production":
            raise ValueError("ENCRYPTION_KEY is required in production mode")
        return value
    f = Fernet(settings.ENCRYPTION_KEY.encode())
    return f.encrypt(value.encode()).decode()


def decrypt_value(encrypted_value: str) -> str:
    """Decrypt a string that was encrypted with encrypt_value.

    Falls back to the original value if ENCRYPTION_KEY is not set
    or if the value is already plain text (non-encrypted).
    """
    if not settings.ENCRYPTION_KEY:
        return encrypted_value
    try:
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.decrypt(encrypted_value.encode()).decode()
    except Exception:
        return encrypted_value


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength.
    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password):
        return False, "Password must contain at least one special character"
    return True, ""
