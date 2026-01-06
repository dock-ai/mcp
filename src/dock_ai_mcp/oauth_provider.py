"""
Supabase OAuth Provider for Dock AI MCP

Implements OAuth 2.1 Authorization Server with:
- Dynamic Client Registration (DCR)
- Authorization Code Flow with PKCE
- Token management (access + refresh)
- Supabase storage for clients/codes/tokens
"""

import os
import secrets
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from pydantic import AnyUrl

from fastmcp.server.auth import OAuthProvider, AccessToken
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.server.auth.provider import AuthorizationParams


# Token expiration settings
ACCESS_TOKEN_EXPIRY = timedelta(hours=1)
REFRESH_TOKEN_EXPIRY = timedelta(days=30)
AUTH_CODE_EXPIRY = timedelta(minutes=10)


class RefreshToken:
    """Refresh token model."""
    def __init__(self, token: str, client_id: str, user_id: str, user_email: str | None, scopes: list[str], expires_at: int | None):
        self.token = token
        self.client_id = client_id
        self.user_id = user_id
        self.user_email = user_email
        self.scopes = scopes
        self.expires_at = expires_at


class AuthorizationCode:
    """Authorization code model."""
    def __init__(
        self,
        code: str,
        client_id: str,
        user_id: str,
        user_email: str | None,
        redirect_uri: str,
        scope: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
        expires_at: datetime,
    ):
        self.code = code
        self.client_id = client_id
        self.user_id = user_id
        self.user_email = user_email
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.expires_at = expires_at


class SupabaseOAuthProvider(OAuthProvider):
    """
    OAuth 2.1 Authorization Server backed by Supabase.

    Stores OAuth clients, authorization codes, and tokens in Supabase tables.
    Delegates user authentication to dockai-api /auth page.
    """

    def __init__(
        self,
        supabase_url: str,
        supabase_service_key: str,
        jwt_secret: str,
        api_base: str,
        base_url: str,
    ):
        """
        Initialize the Supabase OAuth provider.

        Args:
            supabase_url: Supabase project URL
            supabase_service_key: Supabase service role key (for DB access)
            jwt_secret: Secret key for signing our own JWTs
            api_base: dockai-api URL (for auth page redirect)
            base_url: This MCP server's base URL (issuer)
        """
        super().__init__(base_url=base_url)
        self.supabase_url = supabase_url
        self.supabase_service_key = supabase_service_key
        self.jwt_secret = jwt_secret
        self.api_base = api_base
        self.base_url = base_url

    def _supabase_headers(self) -> dict[str, str]:
        """Headers for Supabase REST API calls."""
        return {
            "apikey": self.supabase_service_key,
            "Authorization": f"Bearer {self.supabase_service_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }

    async def _supabase_request(
        self,
        method: str,
        table: str,
        params: dict | None = None,
        json_data: dict | None = None,
    ) -> dict | list | None:
        """Make a request to Supabase REST API."""
        url = f"{self.supabase_url}/rest/v1/{table}"
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=url,
                headers=self._supabase_headers(),
                params=params,
                json=json_data,
                timeout=10.0,
            )
            if response.status_code == 204:
                return None
            if response.status_code >= 400:
                return None
            return response.json()

    # ==================== Client Management ====================

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Retrieve client from Supabase oauth_clients table."""
        result = await self._supabase_request(
            "GET",
            "oauth_clients",
            params={"client_id": f"eq.{client_id}", "select": "*"},
        )
        if not result or not isinstance(result, list) or len(result) == 0:
            return None

        row = result[0]
        return OAuthClientInformationFull(
            client_id=row["client_id"],
            client_secret=row.get("client_secret"),
            client_name=row.get("client_name"),
            redirect_uris=[AnyUrl(uri) for uri in row.get("redirect_uris", [])],
            grant_types=row.get("grant_types", ["authorization_code", "refresh_token"]),
            response_types=row.get("response_types", ["code"]),
            token_endpoint_auth_method=row.get("token_endpoint_auth_method", "client_secret_post"),
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Store new client in Supabase oauth_clients table (DCR)."""
        # Generate client_id and client_secret if not provided
        client_id = client_info.client_id or f"mcp_{secrets.token_urlsafe(16)}"
        client_secret = client_info.client_secret or secrets.token_urlsafe(32)

        # Update the client_info with generated values
        client_info.client_id = client_id
        client_info.client_secret = client_secret
        client_info.client_id_issued_at = int(datetime.now(timezone.utc).timestamp())

        # Store in Supabase
        redirect_uris = [str(uri) for uri in (client_info.redirect_uris or [])]
        await self._supabase_request(
            "POST",
            "oauth_clients",
            json_data={
                "client_id": client_id,
                "client_secret": client_secret,
                "client_name": client_info.client_name or "MCP Client",
                "redirect_uris": redirect_uris,
                "grant_types": client_info.grant_types or ["authorization_code", "refresh_token"],
                "response_types": client_info.response_types or ["code"],
                "token_endpoint_auth_method": client_info.token_endpoint_auth_method or "client_secret_post",
            },
        )

    # ==================== Authorization Flow ====================

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """
        Handle authorization request.

        Redirects to dockai-api /auth page for user authentication.
        After user logs in, dockai-api calls back to create auth code.
        """
        # Build redirect URL to dockai-api auth page
        auth_params = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "code_challenge_method": "S256",
            "mcp_callback": f"{self.base_url}/oauth/callback",
        }
        if params.state:
            auth_params["state"] = params.state
        if params.scopes:
            auth_params["scope"] = " ".join(params.scopes)

        return f"{self.api_base}/auth?{urlencode(auth_params)}"

    async def create_authorization_code(
        self,
        client_id: str,
        user_id: str,
        user_email: str | None,
        redirect_uri: str,
        scope: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
    ) -> str:
        """
        Create and store an authorization code.

        Called by dockai-api after successful user authentication.
        """
        code = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + AUTH_CODE_EXPIRY

        await self._supabase_request(
            "POST",
            "oauth_codes",
            json_data={
                "code": code,
                "client_id": client_id,
                "user_id": user_id,
                "user_email": user_email,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "expires_at": expires_at.isoformat(),
            },
        )
        return code

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        """Load authorization code from Supabase oauth_codes table."""
        result = await self._supabase_request(
            "GET",
            "oauth_codes",
            params={
                "code": f"eq.{authorization_code}",
                "client_id": f"eq.{client.client_id}",
                "select": "*",
            },
        )
        if not result or not isinstance(result, list) or len(result) == 0:
            return None

        row = result[0]
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))

        # Check if expired
        if expires_at < datetime.now(timezone.utc):
            # Delete expired code
            await self._supabase_request(
                "DELETE",
                "oauth_codes",
                params={"code": f"eq.{authorization_code}"},
            )
            return None

        return AuthorizationCode(
            code=row["code"],
            client_id=row["client_id"],
            user_id=row["user_id"],
            user_email=row.get("user_email"),
            redirect_uri=row["redirect_uri"],
            scope=row.get("scope"),
            code_challenge=row.get("code_challenge"),
            code_challenge_method=row.get("code_challenge_method"),
            expires_at=expires_at,
        )

    # ==================== Token Exchange ====================

    def _verify_pkce(self, code_verifier: str, code_challenge: str, method: str) -> bool:
        """Verify PKCE code_verifier against code_challenge."""
        if method == "S256":
            digest = hashlib.sha256(code_verifier.encode()).digest()
            computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            return computed == code_challenge
        elif method == "plain":
            return code_verifier == code_challenge
        return False

    def _create_jwt(
        self,
        user_id: str,
        user_email: str | None,
        client_id: str,
        scopes: list[str],
        expires_in: timedelta,
    ) -> str:
        """Create a signed JWT token."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "email": user_email,
            "client_id": client_id,
            "scope": " ".join(scopes),
            "iss": self.base_url,
            "aud": "dock-ai-mcp",
            "iat": int(now.timestamp()),
            "exp": int((now + expires_in).timestamp()),
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """Exchange authorization code for access and refresh tokens."""
        scopes = authorization_code.scope.split() if authorization_code.scope else []

        # Create access token JWT
        access_token = self._create_jwt(
            user_id=authorization_code.user_id,
            user_email=authorization_code.user_email,
            client_id=authorization_code.client_id,
            scopes=scopes,
            expires_in=ACCESS_TOKEN_EXPIRY,
        )

        # Create refresh token
        refresh_token = secrets.token_urlsafe(32)

        # Store tokens in Supabase
        now = datetime.now(timezone.utc)
        access_expires = now + ACCESS_TOKEN_EXPIRY
        refresh_expires = now + REFRESH_TOKEN_EXPIRY

        # Store access token
        await self._supabase_request(
            "POST",
            "oauth_tokens",
            json_data={
                "token": access_token,
                "token_type": "access",
                "client_id": authorization_code.client_id,
                "user_id": authorization_code.user_id,
                "user_email": authorization_code.user_email,
                "scope": authorization_code.scope,
                "expires_at": access_expires.isoformat(),
            },
        )

        # Store refresh token
        await self._supabase_request(
            "POST",
            "oauth_tokens",
            json_data={
                "token": refresh_token,
                "token_type": "refresh",
                "client_id": authorization_code.client_id,
                "user_id": authorization_code.user_id,
                "user_email": authorization_code.user_email,
                "scope": authorization_code.scope,
                "expires_at": refresh_expires.isoformat(),
            },
        )

        # Delete used authorization code
        await self._supabase_request(
            "DELETE",
            "oauth_codes",
            params={"code": f"eq.{authorization_code.code}"},
        )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=int(ACCESS_TOKEN_EXPIRY.total_seconds()),
            scope=authorization_code.scope,
            refresh_token=refresh_token,
        )

    # ==================== Token Validation ====================

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Validate access token and return AccessToken if valid."""
        # First verify JWT signature and claims
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"],
                audience="dock-ai-mcp",
                issuer=self.base_url,
            )
        except jwt.InvalidTokenError:
            return None

        # Check if token is revoked in database
        result = await self._supabase_request(
            "GET",
            "oauth_tokens",
            params={
                "token": f"eq.{token}",
                "token_type": "eq.access",
                "select": "revoked_at",
            },
        )

        # If token found in DB and revoked, reject it
        if result and isinstance(result, list) and len(result) > 0:
            if result[0].get("revoked_at"):
                return None

        scopes = payload.get("scope", "").split() if payload.get("scope") else []

        return AccessToken(
            token=token,
            client_id=payload.get("client_id", ""),
            scopes=scopes,
            expires_at=payload.get("exp"),
            claims={
                "sub": payload.get("sub"),
                "email": payload.get("email"),
            },
        )

    # ==================== Refresh Token ====================

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        """Load refresh token from database."""
        result = await self._supabase_request(
            "GET",
            "oauth_tokens",
            params={
                "token": f"eq.{refresh_token}",
                "token_type": "eq.refresh",
                "client_id": f"eq.{client.client_id}",
                "select": "*",
            },
        )

        if not result or not isinstance(result, list) or len(result) == 0:
            return None

        row = result[0]

        # Check if revoked
        if row.get("revoked_at"):
            return None

        # Check if expired
        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if expires_at < datetime.now(timezone.utc):
            return None

        scopes = row.get("scope", "").split() if row.get("scope") else []

        return RefreshToken(
            token=row["token"],
            client_id=row["client_id"],
            user_id=row["user_id"],
            user_email=row.get("user_email"),
            scopes=scopes,
            expires_at=int(expires_at.timestamp()),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token for new access token (with rotation)."""
        # Use original scopes if none requested
        final_scopes = scopes if scopes else refresh_token.scopes

        # Create new access token
        access_token = self._create_jwt(
            user_id=refresh_token.user_id,
            user_email=refresh_token.user_email,
            client_id=refresh_token.client_id,
            scopes=final_scopes,
            expires_in=ACCESS_TOKEN_EXPIRY,
        )

        # Create new refresh token (rotation)
        new_refresh_token = secrets.token_urlsafe(32)

        now = datetime.now(timezone.utc)
        access_expires = now + ACCESS_TOKEN_EXPIRY
        refresh_expires = now + REFRESH_TOKEN_EXPIRY

        # Store new access token
        await self._supabase_request(
            "POST",
            "oauth_tokens",
            json_data={
                "token": access_token,
                "token_type": "access",
                "client_id": refresh_token.client_id,
                "user_id": refresh_token.user_id,
                "user_email": refresh_token.user_email,
                "scope": " ".join(final_scopes),
                "expires_at": access_expires.isoformat(),
            },
        )

        # Store new refresh token
        await self._supabase_request(
            "POST",
            "oauth_tokens",
            json_data={
                "token": new_refresh_token,
                "token_type": "refresh",
                "client_id": refresh_token.client_id,
                "user_id": refresh_token.user_id,
                "user_email": refresh_token.user_email,
                "scope": " ".join(final_scopes),
                "expires_at": refresh_expires.isoformat(),
            },
        )

        # Revoke old refresh token
        await self._supabase_request(
            "PATCH",
            "oauth_tokens",
            params={"token": f"eq.{refresh_token.token}"},
            json_data={"revoked_at": now.isoformat()},
        )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=int(ACCESS_TOKEN_EXPIRY.total_seconds()),
            scope=" ".join(final_scopes),
            refresh_token=new_refresh_token,
        )

    # ==================== Token Revocation ====================

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoke a token by marking it in the database."""
        now = datetime.now(timezone.utc)
        await self._supabase_request(
            "PATCH",
            "oauth_tokens",
            params={"token": f"eq.{token.token}"},
            json_data={"revoked_at": now.isoformat()},
        )
