"""
Dock AI MCP Server - Vercel Deployment

Imports from the main server module and adds CORS + Rate Limiting middleware.
"""

import sys
import json
from pathlib import Path

# Add src/ to Python path for Vercel
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

# Import the MCP server and rate limiter
from dock_ai_mcp.server import mcp
from dock_ai_mcp.rate_limit import RateLimitMiddleware, get_rate_limiter

# Initialize rate limiter (returns None if Redis not configured)
rate_limiter = get_rate_limiter()

# MCP Server Card (SEP-1649)
# https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1649
SERVER_CARD = {
    "$schema": "https://static.modelcontextprotocol.io/schemas/mcp-server-card/v1.json",
    "version": "1.0",
    "protocolVersion": "2025-06-18",
    "serverInfo": {
        "name": "dock-ai",
        "title": "Dock AI - Entity Discovery Protocol",
        "version": "1.0.0"
    },
    "description": "Discover which MCP servers can interact with any business. The first Entity Discovery Protocol (EDP) registry. When a user wants to shop, book, or interact with a business, use Dock AI to find the right MCP connector.",
    "iconUrl": "https://dockai.co/icon.svg",
    "documentationUrl": "https://dockai.co/docs",
    "transport": {
        "type": "streamable-http",
        "endpoint": "/mcp"
    },
    "capabilities": {
        "tools": {"listChanged": False}
    },
    "authentication": {
        "required": False
    },
    "tools": [
        {
            "name": "resolve_domain",
            "description": "Check if an MCP connector exists for a business domain. Use this when a user wants to shop, book, or interact with a business."
        }
    ]
}


async def well_known_mcp(request):
    """Serve the MCP Server Card at /.well-known/mcp.json"""
    return JSONResponse(
        SERVER_CARD,
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",
        }
    )


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

# Get the base MCP app
mcp_app = mcp.http_app(middleware=middleware)


# Custom ASGI app that handles .well-known routes
async def app(scope, receive, send):
    """ASGI app that serves Server Card at /.well-known/mcp.json"""
    if scope["type"] == "http":
        path = scope.get("path", "")
        if path == "/.well-known/mcp.json":
            # Handle Server Card request
            response = await well_known_mcp(None)
            await response(scope, receive, send)
            return

    # Pass all other requests to MCP app
    await mcp_app(scope, receive, send)
