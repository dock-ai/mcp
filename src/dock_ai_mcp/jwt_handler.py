"""
JWT Handler for MCP Server

Handles generation and validation of MCP-signed JWTs.
This module is independent of Supabase - MCP has its own JWT keys.
"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt  # PyJWT

logger = logging.getLogger(__name__)

# Token expiration settings
ACCESS_TOKEN_EXPIRY = timedelta(hours=1)
REFRESH_TOKEN_EXPIRY = timedelta(days=30)


@dataclass
class JWTClaims:
    """Parsed JWT claims."""

    sub: str  # user_id
    email: str | None
    org_id: str | None
    client_id: str
    scopes: list[str]
    token_type: str  # "access" or "refresh"
    exp: int
    iat: int
    iss: str


@dataclass
class GeneratedToken:
    """Generated token with expiration."""

    token: str
    expires_at: datetime


def get_private_key() -> str:
    """Get MCP JWT private key from environment."""
    private_key = os.environ.get("MCP_JWT_PRIVATE_KEY")
    if not private_key:
        raise RuntimeError("MCP_JWT_PRIVATE_KEY not configured")

    # Handle PEM key formatting (env vars often have escaped newlines)
    if "\\n" in private_key:
        private_key = private_key.replace("\\n", "\n")

    return private_key


def get_public_key() -> str | None:
    """Get MCP JWT public key from environment."""
    public_key = os.environ.get("MCP_JWT_PUBLIC_KEY")
    if not public_key:
        logger.error("MCP_JWT_PUBLIC_KEY not configured")
        return None

    # Handle PEM key formatting
    if "\\n" in public_key:
        public_key = public_key.replace("\\n", "\n")

    return public_key


def generate_mcp_jwt(
    user_id: str,
    user_email: str | None,
    client_id: str,
    scopes: list[str],
    token_type: str,  # "access" or "refresh"
    issuer: str,
    org_id: str | None = None,
) -> GeneratedToken:
    """
    Generate MCP-signed JWT.

    Args:
        user_id: User's ID (sub claim)
        user_email: User's email (optional)
        client_id: OAuth client ID
        scopes: List of scopes
        token_type: "access" or "refresh"
        issuer: Token issuer (MCP server base URL)
        org_id: Organization ID for v2 dynamic tools (optional)

    Returns:
        GeneratedToken with token string and expiration datetime
    """
    now = datetime.now(timezone.utc)

    if token_type == "access":
        exp = now + ACCESS_TOKEN_EXPIRY
    else:  # refresh
        exp = now + REFRESH_TOKEN_EXPIRY

    # Normalize issuer (remove trailing slash for consistency)
    issuer = issuer.rstrip("/")

    payload = {
        "sub": user_id,
        "email": user_email,
        "org_id": org_id,
        "client_id": client_id,
        "scope": " ".join(scopes) if scopes else None,
        "type": token_type,
        "iss": issuer,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    private_key = get_private_key()
    token = jwt.encode(payload, private_key, algorithm="RS256")

    return GeneratedToken(token=token, expires_at=exp)


def validate_access_token(token: str, expected_issuer: str) -> JWTClaims | None:
    """
    Validate an MCP-signed access token.

    Args:
        token: JWT token string
        expected_issuer: Expected issuer (MCP server base URL)

    Returns:
        JWTClaims if valid, None if invalid
    """
    try:
        public_key = get_public_key()
        if not public_key:
            return None

        # Normalize issuer
        expected_issuer = expected_issuer.rstrip("/")

        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=expected_issuer,
        )

        # Verify that it's an access token
        if claims.get("type") != "access":
            logger.debug("Token is not an access token")
            return None

        scopes = claims.get("scope", "").split() if claims.get("scope") else []

        return JWTClaims(
            sub=claims.get("sub", ""),
            email=claims.get("email"),
            org_id=claims.get("org_id"),
            client_id=claims.get("client_id", ""),
            scopes=scopes,
            token_type="access",
            exp=claims.get("exp", 0),
            iat=claims.get("iat", 0),
            iss=claims.get("iss", ""),
        )

    except jwt.ExpiredSignatureError:
        logger.debug("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug(f"JWT validation failed: {e}")
        return None
    except Exception as e:
        logger.debug(f"Failed to validate token: {e}")
        return None


def validate_refresh_token(
    token: str,
    expected_issuer: str,
    expected_client_id: str | None = None,
) -> JWTClaims | None:
    """
    Validate an MCP-signed refresh token.

    Args:
        token: JWT token string
        expected_issuer: Expected issuer (MCP server base URL)
        expected_client_id: If provided, verify client_id matches

    Returns:
        JWTClaims if valid, None if invalid
    """
    import secrets as secrets_module

    try:
        public_key = get_public_key()
        if not public_key:
            return None

        # Normalize issuer
        expected_issuer = expected_issuer.rstrip("/")

        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=expected_issuer,
        )

        # Verify it's a refresh token
        if claims.get("type") != "refresh":
            logger.debug("Token is not a refresh token")
            return None

        # Verify client matches if provided
        if expected_client_id:
            token_client_id = claims.get("client_id", "")
            if not secrets_module.compare_digest(token_client_id, expected_client_id):
                logger.warning("Client ID mismatch in refresh token")
                return None

        scopes = claims.get("scope", "").split() if claims.get("scope") else []

        return JWTClaims(
            sub=claims.get("sub", ""),
            email=claims.get("email"),
            org_id=claims.get("org_id"),
            client_id=claims.get("client_id", ""),
            scopes=scopes,
            token_type="refresh",
            exp=claims.get("exp", 0),
            iat=claims.get("iat", 0),
            iss=claims.get("iss", ""),
        )

    except jwt.ExpiredSignatureError:
        logger.info("Refresh token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug(f"Refresh token JWT validation failed: {e}")
        return None
    except Exception as e:
        logger.debug(f"Failed to validate refresh token: {e}")
        return None
