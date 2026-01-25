"""
resolve_domain tool handler

Resolves a business domain to get entity info, connectors, and capabilities.
"""

import logging
import httpx
from fastmcp.server.dependencies import get_access_token

from ..config import API_BASE
from ..validators import is_valid_domain

logger = logging.getLogger(__name__)


async def resolve_domain_handler(
    domain: str,
    include_private: bool = False,
) -> dict:
    """
    Check if an MCP connector exists for a business domain.

    Args:
        domain: Business website domain without protocol
        include_private: If True, include private capabilities (requires auth)

    Returns:
        Entity info, connectors, and available capabilities
    """
    # Validate domain format
    domain = domain.lower().strip()
    if not is_valid_domain(domain):
        return {"error": "Invalid domain format", "domain": domain}

    # Get auth token from FastMCP dependency
    auth_token = None
    access_token = get_access_token()
    if access_token:
        auth_token = access_token.token

    # Use internal endpoint for private capabilities
    endpoint = "/api/v1/resolve-internal" if include_private else "/api/v1/resolve"

    async with httpx.AsyncClient() as client:
        headers = {"X-Source": "mcp"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        response = await client.get(
            f"{API_BASE}{endpoint}",
            params={"domain": domain},
            timeout=10.0,
            headers=headers,
        )

        if response.status_code == 404:
            return {"error": "Entity not found", "domain": domain}

        if response.status_code != 200:
            return {"error": f"API error: {response.status_code}"}

        try:
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to parse API response: {e}")
            return {"error": "Invalid response from API"}

        # Handle response format from dockai-api
        entity = data.get("entity")
        connectors = data.get("connectors", [])

        if not entity:
            return {"error": "No entity found for this domain", "domain": domain}

        # Build response with entity, connectors, and capabilities
        capabilities = data.get("capabilities", [])
        result = {
            "domain": domain,
            "entity": entity,
            "connectors": connectors,
            "capabilities": capabilities,
        }

        # Find connectors with MCP endpoints
        mcps = [c for c in connectors if c.get("status") == "connected"]

        # Add hint for AI if MCP endpoints are available
        if mcps:
            endpoints = list(
                set(m.get("mcp_endpoint") for m in mcps if m.get("mcp_endpoint"))
            )
            endpoint_list = ", ".join(endpoints) if endpoints else ""

            entity_name = entity.get("name", "this business")
            result["_ai_hint"] = (
                f"MCP (Model Context Protocol) endpoint found for {entity_name}! "
                "IMPORTANT: If you (the AI assistant) don't have this MCP connector installed, "
                "guide the user to add it TO YOU (their AI assistant: Claude, ChatGPT, or Mistral Le Chat). "
                "Dock AI is just a registry - the connector must be added to the AI assistant itself. "
                f"MCP URL to add: {endpoint_list}"
            )

            # Add installation instructions for major AI assistants
            if endpoints:
                result["_install_instructions"] = _build_install_instructions(
                    endpoints[0]
                )
        elif connectors:
            # Connectors detected but none have MCP endpoints yet
            connector_names = [c.get("name", c.get("slug")) for c in connectors]
            result["_ai_hint"] = (
                f"This business uses: {', '.join(connector_names)}. "
                "However, these providers don't have MCP connectors available yet. "
                "Dock AI is tracking them for future integration."
            )

        # Add capabilities hint if available
        if capabilities:
            cap_slugs = [c.get("action") for c in capabilities]
            cap_hint = (
                f"\n\nAVAILABLE ACTIONS: This business has configured {len(capabilities)} action(s): {', '.join(cap_slugs)}. "
                "Use execute_action(entity_id, action, params) to interact with them. "
                "Check the capabilities array for each action's required parameters."
            )
            if "_ai_hint" in result:
                result["_ai_hint"] += cap_hint
            else:
                result["_ai_hint"] = cap_hint.strip()

        return result


def _build_install_instructions(endpoint: str) -> dict:
    """Build MCP connector installation instructions for AI assistants."""
    return {
        "claude": {
            "steps": [
                "Go to Settings -> Connectors",
                "Click 'Add custom connector'",
                f"Enter URL: {endpoint}",
                "Click Add",
            ],
            "requires": "Pro or Max plan",
        },
        "chatgpt": {
            "steps": [
                "Go to Settings -> Apps",
                "Enable Developer mode in Advanced settings",
                "Click Create under Connectors",
                f"Enter URL: {endpoint}",
                "Enter name and click Create",
            ],
            "requires": "Plus, Pro, or Business plan",
        },
        "mistral_le_chat": {
            "steps": [
                "Click Intelligence -> Connectors",
                "Click '+ Add Connector'",
                "Select 'Custom MCP Connector' tab",
                f"Enter URL: {endpoint}",
                "Click Connect",
            ],
            "requires": "All plans",
        },
    }
