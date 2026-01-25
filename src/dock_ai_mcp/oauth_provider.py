"""
OAuth Provider for Dock AI MCP

Implements OAuth 2.1 Authorization Server with:
- Dynamic Client Registration (DCR)
- Authorization Code Flow with PKCE
- MCP-signed JWTs (independent from Supabase tokens)
- All DB operations delegated to dockai-api

The MCP server generates its own JWTs:
- User authenticates via Supabase on dockai-api (initial auth only)
- MCP generates independent JWTs with user_id/email
- MCP tokens can be refreshed without Supabase
- dockai-api validates both MCP JWTs and Supabase JWTs
"""

import logging
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
from pydantic import AnyUrl

from fastmcp.server.auth import AccessToken, OAuthProvider
from mcp.server.auth.provider import AuthorizationCode as SDKAuthorizationCode
from mcp.server.auth.provider import AuthorizationParams
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .jwt_handler import (
    ACCESS_TOKEN_EXPIRY,
    generate_mcp_jwt,
    validate_access_token,
    validate_refresh_token,
)

# Configure logging
logger = logging.getLogger(__name__)


class RefreshToken:
    """Refresh token model for MCP-signed tokens (independent of Supabase)."""

    def __init__(
        self,
        token: str,
        client_id: str,
        user_id: str,
        user_email: str | None,
        scopes: list[str],
        expires_at: int | None,
        org_id: str | None = None,  # Organization ID for v2 dynamic tools
    ) -> None:
        self.token = token
        self.client_id = client_id
        self.user_id = user_id
        self.user_email = user_email
        self.scopes = scopes
        self.expires_at = expires_at
        self.org_id = org_id


class AuthorizationCode(SDKAuthorizationCode):
    """Authorization code model extending SDK's AuthorizationCode with user info and Supabase tokens."""

    # Additional fields for user info (not in SDK)
    user_id: str
    user_email: str | None = None
    org_id: str | None = None  # Organization ID for v2 dynamic tools
    # Supabase tokens passed through from dockai-api
    supabase_access_token: str
    supabase_refresh_token: str | None = None


class DockAIOAuthProvider(OAuthProvider):
    """
    OAuth 2.1 Authorization Server for Dock AI MCP.

    Delegates all DB operations to dockai-api via internal API.
    Delegates user authentication to dockai-api /auth page.
    Token validation is delegated to dockai-api /api/oauth/validate-token.
    """

    def __init__(
        self,
        internal_api_key: str,
        api_base: str,
        base_url: str,
    ):
        """
        Initialize the OAuth provider.

        Args:
            internal_api_key: API key for authenticating with dockai-api internal endpoints
            api_base: dockai-api URL (for auth page redirect and API calls)
            base_url: This MCP server's base URL (issuer)
        """
        super().__init__(
            base_url=base_url,
            # Enable Dynamic Client Registration (DCR) - required for MCP clients
            client_registration_options=ClientRegistrationOptions(enabled=True),
            # Enable token revocation
            revocation_options=RevocationOptions(enabled=True),
        )
        self.internal_api_key = internal_api_key
        self.api_base = api_base

    def _api_headers(self) -> dict[str, str]:
        """Headers for dockai-api internal calls."""
        return {
            "x-internal-key": self.internal_api_key,
            "Content-Type": "application/json",
        }

    async def _api_request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        json_data: dict | None = None,
    ) -> dict | None:
        """Make a request to dockai-api with proper error handling."""
        url = f"{self.api_base}{endpoint}"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=self._api_headers(),
                    params=params,
                    json=json_data,
                    timeout=10.0,
                )
                if response.status_code >= 400:
                    logger.warning(
                        f"API request failed: {method} {endpoint} -> {response.status_code}"
                    )
                    return None
                if response.status_code == 204:
                    return {"success": True}
                return response.json()
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error(f"API request error: {method} {endpoint} -> {type(e).__name__}: {e}")
            return None

    # ==================== Client Management ====================

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Retrieve client from dockai-api."""
        result = await self._api_request(
            "GET",
            "/api/oauth/clients",
            params={"client_id": client_id},
        )
        if not result:
            return None

        return OAuthClientInformationFull(
            client_id=result["client_id"],
            client_secret=result.get("client_secret"),
            client_name=result.get("client_name"),
            redirect_uris=[AnyUrl(uri) for uri in result.get("redirect_uris", [])],
            grant_types=result.get("grant_types", ["authorization_code", "refresh_token"]),
            response_types=result.get("response_types", ["code"]),
            token_endpoint_auth_method=result.get(
                "token_endpoint_auth_method", "client_secret_post"
            ),
            # Include scope for authorization validation
            scope=result.get("scope"),
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register new client via dockai-api (DCR)."""
        redirect_uris = [str(uri) for uri in (client_info.redirect_uris or [])]

        result = await self._api_request(
            "POST",
            "/api/oauth/clients",
            json_data={
                "client_id": client_info.client_id,
                "client_secret": client_info.client_secret,
                "client_name": client_info.client_name or "MCP Client",
                "redirect_uris": redirect_uris,
                "grant_types": client_info.grant_types
                or ["authorization_code", "refresh_token"],
                "response_types": client_info.response_types or ["code"],
                "token_endpoint_auth_method": client_info.token_endpoint_auth_method
                or "client_secret_post",
                # Include scope from client registration (Claude sends "claudeai")
                "scope": client_info.scope,
            },
        )

        if not result:
            logger.error("Failed to register client with dockai-api")
            raise RuntimeError("Client registration failed")

        # Update client_info with generated values from API
        client_info.client_id = result.get("client_id", client_info.client_id)
        client_info.client_secret = result.get("client_secret", client_info.client_secret)
        client_info.client_id_issued_at = result.get(
            "client_id_issued_at", int(datetime.now(timezone.utc).timestamp())
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
        After user logs in, dockai-api creates auth code and redirects back.
        """
        # Validate PKCE is present (OAuth 2.1 requirement)
        if not params.code_challenge:
            logger.warning(f"Authorization request without code_challenge for client {client.client_id}")
            # Note: SDK should enforce this, but we log for debugging

        auth_params = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "code_challenge": params.code_challenge,
            "code_challenge_method": "S256",
            "mcp_callback": f"{str(self.base_url)}/oauth/callback",
        }
        if params.state:
            auth_params["state"] = params.state
        if params.scopes:
            auth_params["scope"] = " ".join(params.scopes)

        return f"{self.api_base}/auth?{urlencode(auth_params)}"

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        """Load authorization code from dockai-api."""
        result = await self._api_request(
            "GET",
            "/api/oauth/codes",
            params={"code": authorization_code},
        )
        if not result:
            return None

        # Verify client_id matches (timing-safe comparison)
        result_client_id = result.get("client_id", "")
        if not secrets.compare_digest(result_client_id, client.client_id):
            logger.warning(f"Client ID mismatch in authorization code")
            return None

        # Parse expires_at with error handling
        try:
            expires_at_dt = datetime.fromisoformat(
                result["expires_at"].replace("Z", "+00:00")
            )
            expires_at_ts = expires_at_dt.timestamp()
        except (ValueError, KeyError) as e:
            logger.error(f"Invalid expires_at in authorization code: {e}")
            return None

        # Convert scope string to scopes list
        scope_str = result.get("scope") or ""
        scopes = scope_str.split() if scope_str else []

        # Supabase tokens are required for passthrough
        supabase_access_token = result.get("supabase_access_token")
        if not supabase_access_token:
            logger.error("Authorization code missing Supabase access token")
            return None

        return AuthorizationCode(
            code=result["code"],
            client_id=result["client_id"],
            user_id=result["user_id"],
            user_email=result.get("user_email"),
            org_id=result.get("org_id"),  # v2: Organization ID for dynamic tools
            redirect_uri=AnyUrl(result["redirect_uri"]),
            scopes=scopes,
            code_challenge=result.get("code_challenge") or "",
            expires_at=expires_at_ts,
            redirect_uri_provided_explicitly=True,  # Always true for our flow
            supabase_access_token=supabase_access_token,
            supabase_refresh_token=result.get("supabase_refresh_token"),
        )

    # ==================== Token Exchange ====================

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """
        Exchange authorization code for MCP-signed tokens.

        Generates independent JWTs signed by MCP server instead of passing
        through Supabase tokens. This avoids refresh token conflicts.
        """
        # Note: PKCE verification is handled by the SDK before this method is called

        scopes = authorization_code.scopes
        scope_str = " ".join(scopes) if scopes else None
        issuer = str(self.base_url)

        # Generate MCP-signed access token
        access_result = generate_mcp_jwt(
            user_id=authorization_code.user_id,
            user_email=authorization_code.user_email,
            client_id=authorization_code.client_id,
            scopes=scopes,
            token_type="access",
            issuer=issuer,
            org_id=authorization_code.org_id,
        )
        access_token = access_result.token
        access_exp = access_result.expires_at

        # Generate MCP-signed refresh token
        refresh_result = generate_mcp_jwt(
            user_id=authorization_code.user_id,
            user_email=authorization_code.user_email,
            client_id=authorization_code.client_id,
            scopes=scopes,
            token_type="refresh",
            issuer=issuer,
            org_id=authorization_code.org_id,
        )
        refresh_token = refresh_result.token
        refresh_exp = refresh_result.expires_at

        # Store access token for tracking (which MCP client made the request)
        await self._api_request(
            "POST",
            "/api/oauth/tokens",
            json_data={
                "token": access_token,
                "token_type": "access",
                "client_id": authorization_code.client_id,
                "user_id": authorization_code.user_id,
                "user_email": authorization_code.user_email,
                "scope": scope_str,
                "expires_at": access_exp.isoformat(),
                # No supabase_refresh_token - MCP tokens are independent
            },
        )

        # Store refresh token for tracking and validation
        await self._api_request(
            "POST",
            "/api/oauth/tokens",
            json_data={
                "token": refresh_token,
                "token_type": "refresh",
                "client_id": authorization_code.client_id,
                "user_id": authorization_code.user_id,
                "user_email": authorization_code.user_email,
                "scope": scope_str,
                "expires_at": refresh_exp.isoformat(),
            },
        )

        # Delete used authorization code
        await self._api_request(
            "DELETE",
            "/api/oauth/codes",
            params={"code": authorization_code.code},
        )

        logger.info(f"Token exchange successful for user {authorization_code.user_id[:8]}...")

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=int(ACCESS_TOKEN_EXPIRY.total_seconds()),
            scope=scope_str,
            refresh_token=refresh_token,
        )

    # ==================== Token Validation ====================

    async def load_access_token(self, token: str) -> AccessToken | None:
        """
        Validate MCP-signed JWT locally using public key.

        No network calls needed - fast local validation.
        """
        expected_issuer = str(self.base_url)
        claims = validate_access_token(token, expected_issuer)

        if not claims:
            return None

        return AccessToken(
            token=token,
            client_id=claims.client_id,
            scopes=claims.scopes,
            expires_at=claims.exp,
            claims={
                "sub": claims.sub,
                "email": claims.email,
                "org_id": claims.org_id,
            },
        )

    # ==================== Refresh Token ====================

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        """
        Load and validate refresh token.

        For MCP-signed JWTs, we validate locally first, then check DB for revocation.
        """
        # Validate the JWT locally
        expected_issuer = str(self.base_url)
        claims = validate_refresh_token(
            refresh_token,
            expected_issuer,
            expected_client_id=client.client_id,
        )

        if not claims:
            return None

        # Check if token has been revoked in DB
        result = await self._api_request(
            "GET",
            "/api/oauth/tokens",
            params={"token": refresh_token},
        )

        # If token not in DB or revoked, reject it
        if not result or result.get("error") or result.get("revoked_at"):
            logger.debug("Refresh token not found in DB or revoked")
            return None

        return RefreshToken(
            token=refresh_token,
            client_id=claims.client_id,
            user_id=claims.sub,
            user_email=claims.email,
            scopes=claims.scopes,
            expires_at=claims.exp,
            org_id=claims.org_id,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """
        Exchange refresh token for new MCP-signed tokens.

        Generates new JWTs directly - no Supabase call needed!
        This is the key improvement: refresh is now independent.
        """
        final_scopes = scopes if scopes else refresh_token.scopes
        scope_str = " ".join(final_scopes) if final_scopes else None
        issuer = str(self.base_url)

        # Generate new MCP-signed access token
        access_result = generate_mcp_jwt(
            user_id=refresh_token.user_id,
            user_email=refresh_token.user_email,
            client_id=refresh_token.client_id,
            scopes=final_scopes,
            token_type="access",
            issuer=issuer,
            org_id=refresh_token.org_id,
        )
        new_access_token = access_result.token
        access_exp = access_result.expires_at

        # Generate new MCP-signed refresh token (rotation)
        refresh_result = generate_mcp_jwt(
            user_id=refresh_token.user_id,
            user_email=refresh_token.user_email,
            client_id=refresh_token.client_id,
            scopes=final_scopes,
            token_type="refresh",
            issuer=issuer,
            org_id=refresh_token.org_id,
        )
        new_refresh_token = refresh_result.token
        refresh_exp = refresh_result.expires_at

        # Store new access token
        await self._api_request(
            "POST",
            "/api/oauth/tokens",
            json_data={
                "token": new_access_token,
                "token_type": "access",
                "client_id": refresh_token.client_id,
                "user_id": refresh_token.user_id,
                "user_email": refresh_token.user_email,
                "scope": scope_str,
                "expires_at": access_exp.isoformat(),
            },
        )

        # Revoke old refresh token
        await self._api_request(
            "PATCH",
            "/api/oauth/tokens",
            json_data={"token": refresh_token.token},
        )

        # Store new refresh token
        await self._api_request(
            "POST",
            "/api/oauth/tokens",
            json_data={
                "token": new_refresh_token,
                "token_type": "refresh",
                "client_id": refresh_token.client_id,
                "user_id": refresh_token.user_id,
                "user_email": refresh_token.user_email,
                "scope": scope_str,
                "expires_at": refresh_exp.isoformat(),
            },
        )

        logger.info(f"Refresh token exchange successful for user {refresh_token.user_id[:8]}...")

        return OAuthToken(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=int(ACCESS_TOKEN_EXPIRY.total_seconds()),
            scope=scope_str,
            refresh_token=new_refresh_token,
        )

    # ==================== Token Revocation ====================

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoke a token via dockai-api."""
        await self._api_request(
            "PATCH",
            "/api/oauth/tokens",
            json_data={"token": token.token},
        )
        logger.info(f"Token revoked: {type(token).__name__}")
