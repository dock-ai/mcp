"""
Centralized configuration for Dock AI MCP Server

All environment variables and settings are defined here.
"""

import os

# ========================================
# API CONFIGURATION
# ========================================

# Base URL for dockai-api
API_BASE = os.environ.get("DOCKAI_API_URL", "https://api.dockai.co")

# Internal API key for authenticated calls to dockai-api
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY")

# MCP server's public URL (used as OAuth issuer)
MCP_BASE_URL = os.environ.get("MCP_BASE_URL", "https://connect.dockai.co")

# ========================================
# DEPLOYMENT ENVIRONMENT
# ========================================

# Production detection
IS_PRODUCTION = (
    os.environ.get("VERCEL_ENV") == "production"
    or os.environ.get("NODE_ENV") == "production"
)

# Serverless (Vercel) vs persistent (Railway)
IS_SERVERLESS = os.environ.get("VERCEL") == "1"
IS_RAILWAY = os.environ.get("RAILWAY_ENVIRONMENT") is not None

# Server port (Railway provides PORT, default to 8080 for local dev)
PORT = int(os.environ.get("PORT", 8080))

# ========================================
# ICONS & RESOURCES
# ========================================

# Dock AI icons - hosted on api.dockai.co/public
ICON_URL_SVG = "https://api.dockai.co/icon.svg"
ICON_URL_PNG = "https://api.dockai.co/icon.png"

# ========================================
# VALIDATION
# ========================================

# Validate required environment variables in production
if IS_PRODUCTION and not INTERNAL_API_KEY:
    raise RuntimeError("SECURITY: INTERNAL_API_KEY is required in production")
