"""
Rate limiting middleware using Upstash Redis.

Security features:
- IP spoofing protection (trusts x-real-ip from Vercel edge)
- Graceful degradation on Redis failures
- Logging for monitoring and debugging
"""

import hashlib
import logging
import os
import sys

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Configure logging
logger = logging.getLogger(__name__)

# Rate limit configuration from environment
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))

# Environment check for fail-closed behavior
IS_PRODUCTION = os.environ.get("VERCEL_ENV") == "production" or os.environ.get("NODE_ENV") == "production"

# Paths that bypass rate limiting
WHITELISTED_PATHS = {"/health", "/.well-known/mcp.json"}


def get_rate_limiter():
    """Get rate limiter instance if Redis is configured."""
    url = os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

    # Debug: log what we found
    logger.info(f"UPSTASH_REDIS_REST_URL configured: {bool(url)}")
    logger.info(f"UPSTASH_REDIS_REST_TOKEN configured: {bool(token)}")

    if not url or not token:
        logger.warning("Rate limiting disabled: UPSTASH_REDIS_* not configured")
        return None

    try:
        from upstash_ratelimit import FixedWindow, Ratelimit
        from upstash_redis import Redis

        logger.info(f"Connecting to Upstash Redis: {url[:30]}...")
        redis = Redis(url=url, token=token)
        limiter = Ratelimit(
            redis=redis,
            limiter=FixedWindow(max_requests=RATE_LIMIT_MAX, window=RATE_LIMIT_WINDOW),
            prefix="mcp_ratelimit",
        )
        logger.info(f"Rate limiting enabled: {RATE_LIMIT_MAX} req/{RATE_LIMIT_WINDOW}s")
        return limiter
    except ImportError as e:
        logger.error(f"Failed to import upstash packages: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize rate limiter: {type(e).__name__}: {e}")
        return None


def get_client_ip(request: Request) -> str:
    """
    Extract client IP from request headers securely.

    On Vercel, x-real-ip is set by the edge and cannot be spoofed.
    Falls back to x-forwarded-for only if x-vercel-id is present (trusted proxy).
    """
    # Vercel sets x-real-ip at the edge - most secure
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    # Only trust x-forwarded-for if request comes from Vercel edge
    if request.headers.get("x-vercel-id"):
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            # First IP is the original client
            return forwarded.split(",")[0].strip()

    # Direct connection (local dev)
    if request.client and request.client.host:
        return request.client.host

    # Fallback: generate fingerprint to avoid shared quota attack
    fingerprint_data = (
        f"{request.headers.get('user-agent', '')}"
        f"{request.headers.get('accept-language', '')}"
        f"{request.headers.get('accept-encoding', '')}"
    )
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
    return f"unknown-{fingerprint}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce rate limiting with proper security."""

    def __init__(self, app, limiter=None):
        super().__init__(app)
        self.limiter = limiter
        self.limit_value = RATE_LIMIT_MAX

    async def dispatch(self, request: Request, call_next):
        # Fail closed in production if rate limiting not configured
        if not self.limiter:
            if IS_PRODUCTION:
                logger.error("SECURITY: Rate limiting not configured in production!")
                return JSONResponse(
                    status_code=503,
                    content={"error": "Service temporarily unavailable"},
                )
            # In development, allow but warn
            return await call_next(request)

        # Skip OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Skip whitelisted paths
        if request.url.path in WHITELISTED_PATHS:
            return await call_next(request)

        # Get client identifier
        client_ip = get_client_ip(request)

        # Check rate limit
        try:
            result = self.limiter.limit(client_ip)

            # Add rate limit headers to all responses
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(self.limit_value)
            response.headers["X-RateLimit-Remaining"] = str(
                getattr(result, "remaining", max(0, self.limit_value - 1))
            )
            response.headers["X-RateLimit-Reset"] = str(getattr(result, "reset", 60))

            if not result.allowed:
                logger.warning(
                    f"Rate limit exceeded for {client_ip} on {request.url.path}"
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "retry_after": result.reset,
                    },
                    headers={
                        "Retry-After": str(result.reset),
                        "X-RateLimit-Limit": str(self.limit_value),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(result.reset),
                    },
                )

            return response

        except Exception as e:
            # Log the error for monitoring
            logger.error(
                f"Rate limiting failed: {type(e).__name__}: {e}",
                extra={
                    "client_ip": client_ip,
                    "path": request.url.path,
                },
            )
            # Fail closed in production, fail open in development
            if IS_PRODUCTION:
                return JSONResponse(
                    status_code=503,
                    content={"error": "Service temporarily unavailable"},
                )
            return await call_next(request)
