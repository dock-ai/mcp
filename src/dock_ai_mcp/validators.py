"""
Validation utilities for Dock AI MCP Server

Provides input validation patterns and security checks.
"""

import re

# ========================================
# VALIDATION PATTERNS
# ========================================

# Domain pattern: standard domain format
DOMAIN_PATTERN = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$",
    re.IGNORECASE,
)

# UUID pattern: standard UUID format
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Action slug pattern: alphanumeric + underscore, starts with letter, 1-50 chars
ACTION_SLUG_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,49}$")

# ========================================
# SECURITY: SENSITIVE FIELD DETECTION
# ========================================

# Sensitive field names that should NEVER be in params
# These could be used to phish user data via malicious capabilities
SENSITIVE_FIELD_PATTERNS = [
    "password",
    "pwd",
    "passwd",
    "secret",
    "credit_card",
    "card_number",
    "cc_number",
    "cvv",
    "cvc",
    "cv2",
    "ssn",
    "social_security",
    "national_id",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "bearer",
    "private_key",
    "secret_key",
    "bank_account",
    "routing_number",
    "iban",
    "swift",
]


def contains_sensitive_field(params: dict, depth: int = 3) -> list[str]:
    """
    Recursively check for sensitive field names in params.

    Args:
        params: Dictionary of parameters to check
        depth: Maximum recursion depth (prevents infinite loops)

    Returns:
        List of sensitive field names found
    """
    if depth <= 0 or not isinstance(params, dict):
        return []

    found = []
    for key in params.keys():
        normalized = key.lower().replace("-", "_").replace(" ", "_")
        for pattern in SENSITIVE_FIELD_PATTERNS:
            if pattern in normalized:
                found.append(key)
                break
        # Check nested dicts
        if isinstance(params[key], dict):
            found.extend(contains_sensitive_field(params[key], depth - 1))
    return found


def is_valid_domain(domain: str) -> bool:
    """Check if a domain string matches the valid domain pattern."""
    return bool(DOMAIN_PATTERN.match(domain))


def is_valid_uuid(value: str) -> bool:
    """Check if a string is a valid UUID."""
    return bool(UUID_PATTERN.match(value))


def is_valid_action_slug(slug: str) -> bool:
    """Check if an action slug matches the valid pattern."""
    return bool(ACTION_SLUG_PATTERN.match(slug))
