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
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
import jwt  # PyJWT
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
    """Refresh token model for MCP-signed tokens (independent of Supabase)."""

    def __init__(
        self,
        token: str,
        client_id: str,
        user_id: str,
        user_email: str | None,
        scopes: list[str],
        expires_at: int | None,
    ) -> None:
        self.token = token
        self.client_id = client_id
        self.user_id = user_id
        self.user_email = user_email
        self.scopes = scopes
        self.expires_at = expires_at


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

    # ==================== JWT Generation ====================

    def _generate_mcp_jwt(
        self,
        user_id: str,
        user_email: str | None,
        client_id: str,
        scopes: list[str],
        token_type: str,  # "access" or "refresh"
    ) -> tuple[str, datetime]:
        """Generate MCP-signed JWT instead of passing through Supabase token."""
        now = datetime.now(timezone.utc)

        if token_type == "access":
            exp = now + ACCESS_TOKEN_EXPIRY
        else:  # refresh
            exp = now + REFRESH_TOKEN_EXPIRY

        payload = {
            "sub": user_id,
            "email": user_email,
            "client_id": client_id,
            "scope": " ".join(scopes) if scopes else None,
            "type": token_type,
            "iss": str(self.base_url),
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
        }

        private_key = os.environ.get("MCP_JWT_PRIVATE_KEY")
        if not private_key:
            raise RuntimeError("MCP_JWT_PRIVATE_KEY not configured")

        # Handle PEM key formatting (env vars often have escaped newlines)
        if "\\n" in private_key:
            private_key = private_key.replace("\\n", "\n")

        token = jwt.encode(payload, private_key, algorithm="RS256")

        return token, exp

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
        Exchange authorization code for MCP-signed tokens.

        Generates independent JWTs signed by MCP server instead of passing
        through Supabase tokens. This avoids refresh token conflicts.
        """
        # Note: PKCE verification is handled by the SDK before this method is called

        scopes = authorization_code.scopes
        scope_str = " ".join(scopes) if scopes else None

        # Generate MCP-signed access token
        access_token, access_exp = self._generate_mcp_jwt(
            user_id=authorization_code.user_id,
            user_email=authorization_code.user_email,
            client_id=authorization_code.client_id,
            scopes=scopes,
            token_type="access",
        )

        # Generate MCP-signed refresh token
        refresh_token, refresh_exp = self._generate_mcp_jwt(
            user_id=authorization_code.user_id,
            user_email=authorization_code.user_email,
            client_id=authorization_code.client_id,
            scopes=scopes,
            token_type="refresh",
        )

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
        try:
            public_key = os.environ.get("MCP_JWT_PUBLIC_KEY")
            if not public_key:
                logger.error("MCP_JWT_PUBLIC_KEY not configured")
                return None

            # Handle PEM key formatting (env vars often have escaped newlines)
            if "\\n" in public_key:
                public_key = public_key.replace("\\n", "\n")

            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                issuer=str(self.base_url),
            )

            # Verify that it's an access token
            if claims.get("type") != "access":
                logger.debug("Token is not an access token")
                return None

            return AccessToken(
                token=token,
                client_id=claims.get("client_id", ""),
                scopes=claims.get("scope", "").split() if claims.get("scope") else [],
                expires_at=claims.get("exp"),
                claims={
                    "sub": claims.get("sub"),
                    "email": claims.get("email"),
                },
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
        # First, validate the JWT locally
        try:
            public_key = os.environ.get("MCP_JWT_PUBLIC_KEY")
            if not public_key:
                logger.error("MCP_JWT_PUBLIC_KEY not configured")
                return None

            # Handle PEM key formatting
            if "\\n" in public_key:
                public_key = public_key.replace("\\n", "\n")

            claims = jwt.decode(
                refresh_token,
                public_key,
                algorithms=["RS256"],
                issuer=str(self.base_url),
            )

            # Verify it's a refresh token
            if claims.get("type") != "refresh":
                logger.debug("Token is not a refresh token")
                return None

            # Verify client matches
            token_client_id = claims.get("client_id", "")
            if not secrets.compare_digest(token_client_id, client.client_id):
                logger.warning("Client ID mismatch in refresh token")
                return None

        except jwt.ExpiredSignatureError:
            logger.info("Refresh token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.debug(f"Refresh token JWT validation failed: {e}")
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

        scopes = claims.get("scope", "").split() if claims.get("scope") else []

        return RefreshToken(
            token=refresh_token,
            client_id=claims.get("client_id", ""),
            user_id=claims.get("sub", ""),
            user_email=claims.get("email"),
            scopes=scopes,
            expires_at=claims.get("exp"),
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

        # Generate new MCP-signed access token
        new_access_token, access_exp = self._generate_mcp_jwt(
            user_id=refresh_token.user_id,
            user_email=refresh_token.user_email,
            client_id=refresh_token.client_id,
            scopes=final_scopes,
            token_type="access",
        )

        # Generate new MCP-signed refresh token (rotation)
        new_refresh_token, refresh_exp = self._generate_mcp_jwt(
            user_id=refresh_token.user_id,
            user_email=refresh_token.user_email,
            client_id=refresh_token.client_id,
            scopes=final_scopes,
            token_type="refresh",
        )

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
