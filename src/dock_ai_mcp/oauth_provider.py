"""
OAuth Provider for Dock AI MCP

Implements OAuth 2.1 Authorization Server with:
- Dynamic Client Registration (DCR)
- Authorization Code Flow with PKCE
- Supabase token passthrough (no custom JWTs)
- All DB operations delegated to dockai-api

The MCP server acts as an OAuth bridge:
- User authenticates via Supabase on dockai-api
- Supabase tokens are passed through to the MCP client
- dockai-api validates Supabase tokens on API requests
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from pydantic import AnyUrl

from fastmcp.server.auth import AccessToken, OAuthProvider
from mcp.server.auth.provider import AuthorizationCode as SDKAuthorizationCode
from mcp.server.auth.provider import AuthorizationParams
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

# Configure logging
logger = logging.getLogger(__name__)

# Token expiration settings
ACCESS_TOKEN_EXPIRY = timedelta(hours=1)
REFRESH_TOKEN_EXPIRY = timedelta(days=30)


class RefreshToken:
    """Refresh token model with Supabase refresh token for token passthrough."""

    def __init__(
        self,
        token: str,
        client_id: str,
        user_id: str,
        user_email: str | None,
        scopes: list[str],
        expires_at: int | None,
        supabase_refresh_token: str | None = None,
    ) -> None:
        self.token = token
        self.client_id = client_id
        self.user_id = user_id
        self.user_email = user_email
        self.scopes = scopes
        self.expires_at = expires_at
        self.supabase_refresh_token = supabase_refresh_token


class AuthorizationCode(SDKAuthorizationCode):
    """Authorization code model extending SDK's AuthorizationCode with user info and Supabase tokens."""

    # Additional fields for user info (not in SDK)
    user_id: str
    user_email: str | None = None
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
        Exchange authorization code for Supabase tokens.

        This is the key simplification: we pass through Supabase tokens instead
        of creating our own JWTs. dockai-api will validate Supabase tokens directly.
        """
        # Note: PKCE verification is handled by the SDK before this method is called

        scopes = authorization_code.scopes
        scope_str = " ".join(scopes) if scopes else None

        # Use Supabase access token directly (passthrough)
        access_token = authorization_code.supabase_access_token

        # Store Supabase refresh token in our DB for later refresh operations
        # We use a custom token identifier that maps to the Supabase refresh token
        refresh_token_id = secrets.token_urlsafe(32)

        now = datetime.now(timezone.utc)
        refresh_expires = now + REFRESH_TOKEN_EXPIRY

        # Store refresh token mapping (our ID -> Supabase refresh token)
        if authorization_code.supabase_refresh_token:
            await self._api_request(
                "POST",
                "/api/oauth/tokens",
                json_data={
                    "token": refresh_token_id,
                    "token_type": "refresh",
                    "client_id": authorization_code.client_id,
                    "user_id": authorization_code.user_id,
                    "user_email": authorization_code.user_email,
                    "scope": scope_str,
                    "expires_at": refresh_expires.isoformat(),
                    # Store Supabase refresh token for later use
                    "supabase_refresh_token": authorization_code.supabase_refresh_token,
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
            expires_in=int(ACCESS_TOKEN_EXPIRY.total_seconds()),  # Supabase default is 1 hour
            scope=scope_str,
            refresh_token=refresh_token_id if authorization_code.supabase_refresh_token else None,
        )

    # ==================== Token Validation ====================

    async def load_access_token(self, token: str) -> AccessToken | None:
        """
        Validate Supabase access token by delegating to dockai-api.

        Calls /api/oauth/validate-token which verifies the JWT signature
        and returns the claims if valid.
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_base}/api/oauth/validate-token",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10.0,
                )

                if response.status_code != 200:
                    logger.debug(f"Token validation failed: {response.status_code}")
                    return None

                result = response.json()

                if not result.get("valid"):
                    return None

                return AccessToken(
                    token=token,
                    client_id="",  # Supabase tokens don't have client_id
                    scopes=[],  # Supabase uses role-based access, not OAuth scopes
                    expires_at=result.get("exp"),
                    claims={
                        "sub": result.get("sub"),
                        "email": result.get("email"),
                    },
                )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            logger.error(f"Token validation request failed: {e}")
            return None
        except Exception as e:
            logger.debug(f"Failed to validate token: {e}")
            return None

    # ==================== Refresh Token ====================

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        """Load refresh token from dockai-api."""
        result = await self._api_request(
            "GET",
            "/api/oauth/tokens",
            params={"token": refresh_token},
        )

        if not result or result.get("error"):
            return None

        # Verify it's a refresh token
        if result.get("token_type") != "refresh":
            return None

        # Verify client matches (timing-safe comparison)
        result_client_id = result.get("client_id", "")
        if not secrets.compare_digest(result_client_id, client.client_id):
            logger.warning("Client ID mismatch in refresh token")
            return None

        # Parse and validate expiration
        try:
            expires_at = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
        except (ValueError, KeyError) as e:
            logger.error(f"Invalid expires_at in refresh token: {e}")
            return None

        # Check if refresh token is expired
        if datetime.now(timezone.utc) >= expires_at:
            logger.info("Refresh token expired")
            return None

        scopes = result.get("scope", "").split() if result.get("scope") else []

        return RefreshToken(
            token=result["token"],
            client_id=result["client_id"],
            user_id=result["user_id"],
            user_email=result.get("user_email"),
            scopes=scopes,
            expires_at=int(expires_at.timestamp()),
            supabase_refresh_token=result.get("supabase_refresh_token"),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """
        Exchange refresh token for new Supabase tokens.

        Delegates to dockai-api /api/oauth/refresh which handles:
        - Loading Supabase refresh token from DB
        - Calling Supabase to refresh
        - Storing new tokens
        - Revoking old refresh token
        """
        final_scopes = scopes if scopes else refresh_token.scopes

        # Single API call to dockai-api - all logic is centralized there
        result = await self._api_request(
            "POST",
            "/api/oauth/refresh",
            json_data={
                "refresh_token": refresh_token.token,
                "client_id": refresh_token.client_id,
            },
        )

        if not result or result.get("error"):
            error_msg = result.get("error", "Unknown error") if result else "API request failed"
            logger.error(f"Token refresh failed: {error_msg}")
            raise RuntimeError(f"Token refresh failed: {error_msg}")

        logger.info(f"Refresh token exchange successful for user {refresh_token.user_id[:8]}...")

        return OAuthToken(
            access_token=result["access_token"],
            token_type=result.get("token_type", "Bearer"),
            expires_in=result.get("expires_in", 3600),
            scope=" ".join(final_scopes),
            refresh_token=result.get("refresh_token"),
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
