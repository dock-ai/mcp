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
from starlette.responses import JSONResponse
from starlette.routing import Route

# Import the MCP server and rate limiter
from dock_ai_mcp.server import mcp, IS_SERVERLESS
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
        "tools": {"listChanged": False},
        "prompts": {"listChanged": False},
        "resources": {"subscribe": False, "listChanged": False}
    },
    "authentication": {
        "required": False
    },
    "tools": [
        {
            "name": "resolve_domain",
            "description": "Check if an MCP connector exists for a business domain. Use this when a user wants to shop, book, or interact with a business."
        },
        {
            "name": "contact_business",
            "description": "Send an email to a business. Requires authentication and entity_id from resolve_domain."
        }
    ],
    "prompts": [
        {
            "name": "discover_business",
            "description": "Help discover MCP connectors for a business by name"
        },
        {
            "name": "setup_connector",
            "description": "Guide for setting up MCP connectors in AI assistants"
        }
    ],
    "resources": [
        {
            "uri": "docs://getting-started",
            "name": "Getting Started Guide",
            "description": "Getting started guide for Dock AI"
        },
        {
            "uri": "docs://supported-providers",
            "name": "Supported Providers",
            "description": "List of supported MCP providers"
        }
    ]
}


async def well_known_mcp(request):
    """Serve the MCP Server Card at /.well-known/mcp.json"""
    # Server Card is public metadata - allow any origin to read it
    # This is intentional as it's discovery metadata, not sensitive data
    return JSONResponse(
        SERVER_CARD,
        headers={
            "Cache-Control": "public, max-age=3600",
            "Access-Control-Allow-Origin": "*",  # Public discovery endpoint
        }
    )


# Allowed origins for CORS
ALLOWED_ORIGINS = [
    # Dock AI
    "https://dockai.co",
    "https://www.dockai.co",
    "https://mcp.dockai.co",
    # Claude
    "https://claude.ai",
    "https://www.claude.ai",
    # ChatGPT
    "https://chat.openai.com",
    "https://chatgpt.com",
    # Mistral
    "https://chat.mistral.ai",
    "https://mistral.ai",
    # Development
    "http://localhost:3000",
    "http://localhost:3001",
]

# ASGI app with CORS and Rate Limiting for Vercel
middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Internal-Key"],
        allow_credentials=True,
    ),
    Middleware(RateLimitMiddleware, limiter=rate_limiter),
]

# Get the base MCP app (stateless_http for serverless deployments like Vercel)
mcp_app = mcp.http_app(middleware=middleware, stateless_http=IS_SERVERLESS)


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
