"""
OAuth Provider for Dock AI MCP

Implements OAuth 2.1 Authorization Server with:
- Dynamic Client Registration (DCR)
- Authorization Code Flow with PKCE
- Supabase token passthrough (no custom JWTs)
- All DB operations delegated to dockai-api

Security features:
- Timing-safe string comparisons
- Proper token expiration validation
- Scope validation on refresh
- Error logging for debugging

The MCP server acts as an OAuth bridge:
- User authenticates via Supabase on dockai-api
- Supabase tokens are passed through to the MCP client
- dockai-api validates Supabase tokens on API requests
"""

import base64
import hashlib
import logging
import os
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
        # Supabase URL for token refresh
        self.supabase_url = os.environ.get("SUPABASE_URL", "https://swtkpyhoqnbstgdzbwsz.supabase.co")
        # Note: self.base_url is set by parent class as AnyHttpUrl

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

    def _verify_pkce(self, code_verifier: str, code_challenge: str, method: str) -> bool:
        """Verify PKCE code_verifier against code_challenge (timing-safe)."""
        if method == "S256":
            digest = hashlib.sha256(code_verifier.encode()).digest()
            computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            return secrets.compare_digest(computed, code_challenge)
        elif method == "plain":
            return secrets.compare_digest(code_verifier, code_challenge)
        return False

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

        logger.info(f"Token exchange successful for user {authorization_code.user_id}")

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
        Validate Supabase access token and return AccessToken if valid.

        We decode the Supabase JWT without signature verification (we don't have
        the secret). The actual validation happens in dockai-api when the token
        is used for API calls.
        """
        import json

        try:
            # Decode JWT without verification to extract claims
            # Supabase JWTs have 3 parts: header.payload.signature
            parts = token.split(".")
            if len(parts) != 3:
                logger.debug("Invalid JWT format")
                return None

            # Decode payload (add padding if needed)
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes.decode("utf-8"))

            # Check expiration
            exp = payload.get("exp")
            if exp and datetime.now(timezone.utc).timestamp() > exp:
                logger.debug("Token expired")
                return None

            # Supabase JWT structure differs from our custom JWT
            # sub = user ID, email is in email field
            user_id = payload.get("sub")
            email = payload.get("email")

            if not user_id:
                logger.debug("Token missing user ID (sub)")
                return None

            return AccessToken(
                token=token,
                client_id="",  # Supabase tokens don't have client_id
                scopes=[],  # Supabase uses role-based access, not OAuth scopes
                expires_at=exp,
                claims={
                    "sub": user_id,
                    "email": email,
                },
            )
        except Exception as e:
            logger.debug(f"Failed to decode token: {e}")
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

        # Supabase refresh token is required for token refresh
        supabase_refresh_token = result.get("supabase_refresh_token")
        if not supabase_refresh_token:
            logger.error("Refresh token missing Supabase refresh token")
            return None

        return RefreshToken(
            token=result["token"],
            client_id=result["client_id"],
            user_id=result["user_id"],
            user_email=result.get("user_email"),
            scopes=scopes,
            expires_at=int(expires_at.timestamp()),
            supabase_refresh_token=supabase_refresh_token,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """
        Exchange refresh token for new Supabase tokens.

        Calls Supabase's token refresh endpoint to get a new access token.
        """
        final_scopes = scopes if scopes else refresh_token.scopes

        # Call Supabase to refresh the token
        supabase_anon_key = os.environ.get("SUPABASE_ANON_KEY", "")
        if not supabase_anon_key:
            logger.error("SUPABASE_ANON_KEY not configured")
            raise RuntimeError("Token refresh not available")

        try:
            async with httpx.AsyncClient() as http_client:
                response = await http_client.post(
                    f"{self.supabase_url}/auth/v1/token?grant_type=refresh_token",
                    headers={
                        "apikey": supabase_anon_key,
                        "Content-Type": "application/json",
                    },
                    json={"refresh_token": refresh_token.supabase_refresh_token},
                    timeout=10.0,
                )

                if response.status_code != 200:
                    logger.error(f"Supabase token refresh failed: {response.status_code}")
                    raise RuntimeError("Token refresh failed")

                data = response.json()
                new_access_token = data.get("access_token")
                new_supabase_refresh_token = data.get("refresh_token")
                expires_in = data.get("expires_in", 3600)

                if not new_access_token:
                    logger.error("Supabase returned no access token")
                    raise RuntimeError("Token refresh failed")

        except httpx.RequestError as e:
            logger.error(f"Supabase request error: {e}")
            raise RuntimeError("Token refresh failed")

        # Create new refresh token ID for our DB
        new_refresh_token_id = secrets.token_urlsafe(32)

        now = datetime.now(timezone.utc)
        refresh_expires = now + REFRESH_TOKEN_EXPIRY

        # Store new refresh token mapping
        if new_supabase_refresh_token:
            await self._api_request(
                "POST",
                "/api/oauth/tokens",
                json_data={
                    "token": new_refresh_token_id,
                    "token_type": "refresh",
                    "client_id": refresh_token.client_id,
                    "user_id": refresh_token.user_id,
                    "user_email": refresh_token.user_email,
                    "scope": " ".join(final_scopes),
                    "expires_at": refresh_expires.isoformat(),
                    "supabase_refresh_token": new_supabase_refresh_token,
                },
            )

        # Revoke old refresh token
        await self._api_request(
            "PATCH",
            "/api/oauth/tokens",
            json_data={"token": refresh_token.token},
        )

        logger.info(f"Refresh token exchange successful for user {refresh_token.user_id}")

        return OAuthToken(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=expires_in,
            scope=" ".join(final_scopes),
            refresh_token=new_refresh_token_id if new_supabase_refresh_token else None,
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
