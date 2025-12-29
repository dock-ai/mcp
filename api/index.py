"""
Dock AI MCP Server - Vercel Deployment

Just imports from the main server module and adds CORS middleware.
"""

import sys
from pathlib import Path

# Add src/ to Python path for Vercel
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

# Import the MCP server (tools are registered via decorators)
from dock_ai_mcp.server import mcp

# ASGI app with CORS for Vercel
middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
]

app = mcp.http_app(middleware=middleware)
