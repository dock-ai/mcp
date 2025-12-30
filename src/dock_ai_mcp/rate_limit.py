"""
Rate limiting middleware using Upstash Redis.
"""

import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


def get_rate_limiter():
    """Get rate limiter instance if Redis is configured."""
    url = os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

    if not url or not token:
        return None

    try:
        from upstash_ratelimit import Ratelimit, FixedWindow
        from upstash_redis import Redis

        redis = Redis(url=url, token=token)
        return Ratelimit(
            redis=redis,
            limiter=FixedWindow(max_requests=100, window=60),  # 100 req/min per IP
            prefix="mcp_ratelimit",
        )
    except Exception:
        return None


def get_client_ip(request: Request) -> str:
    """Extract client IP from request headers."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce rate limiting."""

    def __init__(self, app, limiter=None):
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting if not configured
        if not self.limiter:
            return await call_next(request)

        # Skip OPTIONS requests (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Get client identifier
        client_ip = get_client_ip(request)

        # Check rate limit
        try:
            result = self.limiter.limit(client_ip)
            if not result.allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "retry_after": result.reset,
                    },
                    headers={
                        "Retry-After": str(result.reset),
                        "X-RateLimit-Limit": "100",
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(result.reset),
                    },
                )
        except Exception:
            # If rate limiting fails, allow the request (fail open)
            pass

        return await call_next(request)
