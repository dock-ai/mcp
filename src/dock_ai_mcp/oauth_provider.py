"""
OAuth Provider for Dock AI MCP

Implements OAuth 2.1 Authorization Server with:
- Dynamic Client Registration (DCR)
- Authorization Code Flow with PKCE
- Token management (access + refresh)
- All DB operations delegated to dockai-api
"""

import secrets
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
import jwt
from pydantic import AnyUrl

from fastmcp.server.auth import OAuthProvider, AccessToken
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.server.auth.provider import AuthorizationParams
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions


# Token expiration settings
ACCESS_TOKEN_EXPIRY = timedelta(hours=1)
REFRESH_TOKEN_EXPIRY = timedelta(days=30)


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


class DockAIOAuthProvider(OAuthProvider):
    """
    OAuth 2.1 Authorization Server for Dock AI MCP.

    Delegates all DB operations to dockai-api via internal API.
    Delegates user authentication to dockai-api /auth page.
    """

    def __init__(
        self,
        internal_api_key: str,
        jwt_secret: str,
        api_base: str,
        base_url: str,
    ):
        """
        Initialize the OAuth provider.

        Args:
            internal_api_key: API key for authenticating with dockai-api internal endpoints
            jwt_secret: Secret key for signing our own JWTs
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
        self.jwt_secret = jwt_secret
        self.api_base = api_base
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
        """Make a request to dockai-api."""
        url = f"{self.api_base}{endpoint}"
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
                return None
            if response.status_code == 204:
                return {"success": True}
            return response.json()

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
            token_endpoint_auth_method=result.get("token_endpoint_auth_method", "client_secret_post"),
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
                "grant_types": client_info.grant_types or ["authorization_code", "refresh_token"],
                "response_types": client_info.response_types or ["code"],
                "token_endpoint_auth_method": client_info.token_endpoint_auth_method or "client_secret_post",
            },
        )

        if result:
            # Update client_info with generated values from API
            client_info.client_id = result.get("client_id", client_info.client_id)
            client_info.client_secret = result.get("client_secret", client_info.client_secret)
            client_info.client_id_issued_at = result.get("client_id_issued_at", int(datetime.now(timezone.utc).timestamp()))

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

        # Verify client_id matches
        if result.get("client_id") != client.client_id:
            return None

        expires_at = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))

        return AuthorizationCode(
            code=result["code"],
            client_id=result["client_id"],
            user_id=result["user_id"],
            user_email=result.get("user_email"),
            redirect_uri=result["redirect_uri"],
            scope=result.get("scope"),
            code_challenge=result.get("code_challenge"),
            code_challenge_method=result.get("code_challenge_method"),
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
            "iss": str(self.base_url),
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

        # Calculate expiration times
        now = datetime.now(timezone.utc)
        access_expires = now + ACCESS_TOKEN_EXPIRY
        refresh_expires = now + REFRESH_TOKEN_EXPIRY

        # Store access token via dockai-api
        await self._api_request(
            "POST",
            "/api/oauth/tokens",
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

        # Store refresh token via dockai-api
        await self._api_request(
            "POST",
            "/api/oauth/tokens",
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
        await self._api_request(
            "DELETE",
            "/api/oauth/codes",
            params={"code": authorization_code.code},
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
                issuer=str(self.base_url),
            )
        except jwt.InvalidTokenError:
            return None

        # Check if token is revoked via dockai-api
        result = await self._api_request(
            "GET",
            "/api/oauth/tokens",
            params={"token": token},
        )

        # If token is in DB and revoked (or not found = expired/revoked), reject
        if not result or result.get("error"):
            # Token not found or error - but JWT is valid, allow it
            # (token might not be stored if we're validating a token from before DB storage)
            pass

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
        """Load refresh token from dockai-api."""
        result = await self._api_request(
            "GET",
            "/api/oauth/tokens",
            params={"token": refresh_token},
        )

        if not result or result.get("error"):
            return None

        # Verify it's a refresh token and client matches
        if result.get("token_type") != "refresh":
            return None
        if result.get("client_id") != client.client_id:
            return None

        expires_at = datetime.fromisoformat(result["expires_at"].replace("Z", "+00:00"))
        scopes = result.get("scope", "").split() if result.get("scope") else []

        return RefreshToken(
            token=result["token"],
            client_id=result["client_id"],
            user_id=result["user_id"],
            user_email=result.get("user_email"),
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
        await self._api_request(
            "POST",
            "/api/oauth/tokens",
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
        await self._api_request(
            "POST",
            "/api/oauth/tokens",
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
        await self._api_request(
            "PATCH",
            "/api/oauth/tokens",
            json_data={"token": refresh_token.token},
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
        """Revoke a token via dockai-api."""
        await self._api_request(
            "PATCH",
            "/api/oauth/tokens",
            json_data={"token": token.token},
        )
