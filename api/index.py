"""
Dock AI MCP Server - Vercel Deployment

Imports from the main server module and adds CORS + Rate Limiting middleware.
"""

import sys
from pathlib import Path

# Add src/ to Python path for Vercel
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

# Import the MCP server and rate limiter
from dock_ai_mcp.server import mcp
from dock_ai_mcp.rate_limit import RateLimitMiddleware, get_rate_limiter

# Initialize rate limiter (returns None if Redis not configured)
rate_limiter = get_rate_limiter()

# ASGI app with CORS and Rate Limiting for Vercel
middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    ),
    Middleware(RateLimitMiddleware, limiter=rate_limiter),
]

app = mcp.http_app(middleware=middleware)
