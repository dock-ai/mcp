"""
Dock AI MCP Server - Vercel Deployment

Allows AI agents to discover MCP endpoints for real-world entities.
"""

import httpx
from fastmcp import FastMCP
from mcp.types import Icon
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

API_BASE = "https://api.dockai.co"

# Dock AI icon (teal gradient with lightning bolt)
ICON_DATA_URI = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCA0OCA0OCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjQ4IiBoZWlnaHQ9IjQ4IiByeD0iMTEiIGZpbGw9InVybCgjcGFpbnQwX2xpbmVhcl8xXzUpIi8+CjxwYXRoIGQ9Ik0xNC4yMjU5IDI2LjM5OTRDMTMuOTk0NyAyNi40MDAxIDEzLjc2OCAyNi4zMzY1IDEzLjU3MjIgMjYuMjE1OEMxMy4zNzY0IDI2LjA5NTEgMTMuMjE5NSAyNS45MjIzIDEzLjExOTcgMjUuNzE3NUMxMy4wMTk5IDI1LjUxMjggMTIuOTgxMyAyNS4yODQ0IDEzLjAwODQgMjUuMDU4OUMxMy4wMzU2IDI0LjgzMzUgMTMuMTI3MyAyNC42MjAyIDEzLjI3MyAyNC40NDM5TDI1LjM2ODQgMTIuMjA3MUMyNS40NTkxIDEyLjEwNDIgMjUuNTgyNyAxMi4wMzQ3IDI1LjcxOSAxMi4wMUMyNS44NTUyIDExLjk4NTMgMjUuOTk2IDEyLjAwNjcgMjYuMTE4MiAxMi4wNzA5QzI2LjI0MDQgMTIuMTM1MSAyNi4zMzY3IDEyLjIzODEgMjYuMzkxNCAxMi4zNjMyQzI2LjQ0NjEgMTIuNDg4MiAyNi40NTU4IDEyLjYyNzcgMjYuNDE5MSAxMi43NTg5TDI0LjA3MzMgMTkuOTgxQzI0LjAwNDEgMjAuMTYyOCAyMy45ODA5IDIwLjM1ODQgMjQuMDA1NiAyMC41NTA5QzI0LjAzMDMgMjAuNzQzNCAyNC4xMDIyIDIwLjkyNzIgMjQuMjE1MSAyMS4wODY1QzI0LjMyODEgMjEuMjQ1NyAyNC40Nzg3IDIxLjM3NTcgMjQuNjU0IDIxLjQ2NTNDMjQuODI5MyAyMS41NTQ4IDI1LjAyNDEgMjEuNjAxMyAyNS4yMjE4IDIxLjYwMDZIMzMuNzc0MUMzNC4wMDUzIDIxLjU5OTkgMzQuMjMyIDIxLjY2MzUgMzQuNDI3OCAyMS43ODQyQzM0LjYyMzYgMjEuOTA0OSAzNC43ODA1IDIyLjA3NzcgMzQuODgwMyAyMi4yODI1QzM0Ljk4MDEgMjIuNDg3MiAzNS4wMTg3IDIyLjcxNTYgMzQuOTkxNiAyMi45NDExQzM0Ljk2NDQgMjMuMTY2NSAzNC44NzI3IDIzLjM3OTggMzQuNzI3IDIzLjU1NjFMMjIuNjMxNiAzNS43OTI5QzIyLjU0MDkgMzUuODk1OCAyMi40MTczIDM1Ljk2NTMgMjIuMjgxIDM1Ljk5QzIyLjE0NDggMzYuMDE0NyAyMi4wMDQgMzUuOTkzMyAyMS44ODE4IDM1LjkyOTFDMjEuNzU5NiAzNS44NjQ5IDIxLjY2MzMgMzUuNzYxOSAyMS42MDg2IDM1LjYzNjhDMjEuNTUzOSAzNS41MTE4IDIxLjU0NDIgMzUuMzcyMyAyMS41ODA5IDM1LjI0MTFMMjMuOTI2NyAyOC4wMTlDMjMuOTk1OSAyNy44MzcyIDI0LjAxOTEgMjcuNjQxNiAyMy45OTQ0IDI3LjQ0OTFDMjMuOTY5NyAyNy4yNTY2IDIzLjg5NzggMjcuMDcyOCAyMy43ODQ5IDI2LjkxMzVDMjMuNjcxOSAyNi43NTQzIDIzLjUyMTMgMjYuNjI0MyAyMy4zNDYgMjYuNTM0N0MyMy4xNzA3IDI2LjQ0NTIgMjIuOTc1OSAyNi4zOTg3IDIyLjc3ODIgMjYuMzk5NEgxNC4yMjU5WiIgZmlsbD0id2hpdGUiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMV81IiB4MT0iNy41IiB5MT0iNy41IiB4Mj0iMzciIHkyPSI0MS41IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CjxzdG9wIHN0b3AtY29sb3I9IiMwRDk0ODgiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjMTRCOEE2Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg=="

mcp = FastMCP(
    name="Dock AI",
    stateless_http=True,  # Required for serverless
    instructions="""
    Use this server to discover MCP endpoints for real-world entities.
    Given a domain (e.g., "example-restaurant.com"), you can find which MCP
    servers can interact with that entity and what capabilities they offer.
    """,
    icons=[
        Icon(src=ICON_DATA_URI, mimeType="image/svg+xml", sizes=["48x48"]),
    ],
)


@mcp.tool
async def resolve_domain(domain: str) -> dict:
    """
    Resolve a domain to its MCP endpoints.

    Given a domain, returns the entity information and available MCP endpoints
    that can interact with this entity. A domain may have multiple entities
    (e.g., different locations of the same business).

    Args:
        domain: The domain to resolve (e.g., "example-restaurant.com")

    Returns:
        Domain information including all entities with their names, locations,
        verification levels, and list of MCP endpoints with their capabilities.
        Also includes pending_providers for providers that serve this entity
        but haven't joined Dock AI yet.

    IMPORTANT - Before calling this tool:
    1. If the user provides a business name instead of a domain, you MUST first
       use web_search to find the official website/domain of that business.
    2. Verify you have the correct domain before calling this tool.
    3. Example: User says "Book at Gloria Osteria Paris" -> First search the web
       for "Gloria Osteria Paris official website" to find the domain.

    IMPORTANT - After getting results:
    - If MCPs are found, suggest installing the MCP server(s) using the
      claude_desktop_config from the response.
    - If only pending_providers are found, inform the user that these providers
      serve this entity but haven't joined Dock AI yet, so direct MCP interaction
      is not yet available.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{API_BASE}/v1/resolve/domain/{domain}",
            timeout=10.0,
        )

        if response.status_code == 404:
            return {"error": "Entity not found", "domain": domain}

        if response.status_code != 200:
            return {"error": f"API error: {response.status_code}"}

        data = response.json()

        # Handle new multi-entity response format
        entities = data.get("entities", [])

        if not entities:
            return {"error": "No entities found for this domain", "domain": domain}

        # Collect all MCPs from all entities
        all_mcps = []
        for entity in entities:
            entity_mcps = entity.get("mcps", [])
            for mcp_info in entity_mcps:
                # Add entity context to each MCP
                mcp_with_context = mcp_info.copy()
                mcp_with_context["_entity_name"] = entity.get("name", "Unknown")
                mcp_with_context["_entity_path"] = entity.get("path", "")
                all_mcps.append(mcp_with_context)

        # Build response with entities array
        result = {
            "domain": data.get("domain", domain),
            "entities": entities,
        }

        # Add installation hints for AI based on entity count and MCPs
        if all_mcps:
            if len(entities) == 1:
                entity_name = entities[0].get("name", "this entity")
                result["_ai_hint"] = (
                    f"MCP endpoints found for {entity_name}! Suggest to the user that "
                    "they can install the MCP server(s) to interact with this entity "
                    "directly. Use the claude_desktop_config below."
                )
            else:
                entity_names = [e.get("name", "Unknown") for e in entities]
                result["_ai_hint"] = (
                    f"This domain has {len(entities)} entities/locations: "
                    f"{', '.join(entity_names)}. MCP endpoints found! "
                    "The user may want to interact with a specific location. "
                    "Suggest installing the MCP server(s) using the claude_desktop_config below."
                )

            # Generate Claude Desktop config snippet from all entities' MCPs
            mcp_configs = {}
            for mcp_info in all_mcps:
                provider = mcp_info.get("provider", "unknown")
                endpoint = mcp_info.get("endpoint", "")
                if endpoint:
                    # Use provider as key; if multiple entities have same provider,
                    # the config will be the same endpoint
                    mcp_configs[provider] = {"url": f"{endpoint}/mcp"}

            if mcp_configs:
                result["claude_desktop_config"] = {"mcpServers": mcp_configs}

        return result


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
