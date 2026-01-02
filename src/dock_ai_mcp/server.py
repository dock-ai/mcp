"""
Dock AI MCP Server

Allows AI agents to discover MCP endpoints for real-world entities.
"""

import os
import httpx
from fastmcp import FastMCP
from mcp.types import Icon

API_BASE = "https://api.dockai.co"

# Dock AI icon (teal gradient with lightning bolt)
ICON_DATA_URI = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCA0OCA0OCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjQ4IiBoZWlnaHQ9IjQ4IiByeD0iMTEiIGZpbGw9InVybCgjcGFpbnQwX2xpbmVhcl8xXzUpIi8+CjxwYXRoIGQ9Ik0xNC4yMjU5IDI2LjM5OTRDMTMuOTk0NyAyNi40MDAxIDEzLjc2OCAyNi4zMzY1IDEzLjU3MjIgMjYuMjE1OEMxMy4zNzY0IDI2LjA5NTEgMTMuMjE5NSAyNS45MjIzIDEzLjExOTcgMjUuNzE3NUMxMy4wMTk5IDI1LjUxMjggMTIuOTgxMyAyNS4yODQ0IDEzLjAwODQgMjUuMDU4OUMxMy4wMzU2IDI0LjgzMzUgMTMuMTI3MyAyNC42MjAyIDEzLjI3MyAyNC40NDM5TDI1LjM2ODQgMTIuMjA3MUMyNS40NTkxIDEyLjEwNDIgMjUuNTgyNyAxMi4wMzQ3IDI1LjcxOSAxMi4wMUMyNS44NTUyIDExLjk4NTMgMjUuOTk2IDEyLjAwNjcgMjYuMTE4MiAxMi4wNzA5QzI2LjI0MDQgMTIuMTM1MSAyNi4zMzY3IDEyLjIzODEgMjYuMzkxNCAxMi4zNjMyQzI2LjQ0NjEgMTIuNDg4MiAyNi40NTU4IDEyLjYyNzcgMjYuNDE5MSAxMi43NTg5TDI0LjA3MzMgMTkuOTgxQzI0LjAwNDEgMjAuMTYyOCAyMy45ODA5IDIwLjM1ODQgMjQuMDA1NiAyMC41NTA5QzI0LjAzMDMgMjAuNzQzNCAyNC4xMDIyIDIwLjkyNzIgMjQuMjE1MSAyMS4wODY1QzI0LjMyODEgMjEuMjQ1NyAyNC40Nzg3IDIxLjM3NTcgMjQuNjU0IDIxLjQ2NTNDMjQuODI5MyAyMS41NTQ4IDI1LjAyNDEgMjEuNjAxMyAyNS4yMjE4IDIxLjYwMDZIMzMuNzc0MUMzNC4wMDUzIDIxLjU5OTkgMzQuMjMyIDIxLjY2MzUgMzQuNDI3OCAyMS43ODQyQzM0LjYyMzYgMjEuOTA0OSAzNC43ODA1IDIyLjA3NzcgMzQuODgwMyAyMi4yODI1QzM0Ljk4MDEgMjIuNDg3MiAzNS4wMTg3IDIyLjcxNTYgMzQuOTkxNiAyMi45NDExQzM0Ljk2NDQgMjMuMTY2NSAzNC44NzI3IDIzLjM3OTggMzQuNzI3IDIzLjU1NjFMMjIuNjMxNiAzNS43OTI5QzIyLjU0MDkgMzUuODk1OCAyMi40MTczIDM1Ljk2NTMgMjIuMjgxIDM1Ljk5QzIyLjE0NDggMzYuMDE0NyAyMi4wMDQgMzUuOTkzMyAyMS44ODE4IDM1LjkyOTFDMjEuNzU5NiAzNS44NjQ5IDIxLjY2MzMgMzUuNzYxOSAyMS42MDg2IDM1LjYzNjhDMjEuNTUzOSAzNS41MTE4IDIxLjU0NDIgMzUuMzcyMyAyMS41ODA5IDM1LjI0MTFMMjMuOTI2NyAyOC4wMTlDMjMuOTk1OSAyNy44MzcyIDI0LjAxOTEgMjcuNjQxNiAyMy45OTQ0IDI3LjQ0OTFDMjMuOTY5NyAyNy4yNTY2IDIzLjg5NzggMjcuMDcyOCAyMy43ODQ5IDI2LjkxMzVDMjMuNjcxOSAyNi43NTQzIDIzLjUyMTMgMjYuNjI0MyAyMy4zNDYgMjYuNTM0N0MyMy4xNzA3IDI2LjQ0NTIgMjIuOTc1OSAyNi4zOTg3IDIyLjc3ODIgMjYuMzk5NEgxNC4yMjU5WiIgZmlsbD0id2hpdGUiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMV81IiB4MT0iNy41IiB5MT0iNy41IiB4Mj0iMzciIHkyPSI0MS41IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CjxzdG9wIHN0b3AtY29sb3I9IiMwRDk0ODgiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjMTRCOEE2Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg=="

# Check if running in serverless mode (Vercel sets VERCEL=1)
IS_SERVERLESS = os.environ.get("VERCEL") == "1"

mcp = FastMCP(
    name="Dock AI",
    stateless_http=IS_SERVERLESS,
    instructions="""
    Dock AI is a registry that maps businesses to their MCP connectors.

    WHEN TO USE: When a user mentions a business/brand by name and wants to:
    - Shop, browse products, or buy something (e-commerce)
    - Book, reserve, or order (restaurants, hotels, salons)
    - Interact with any real-world business

    ALWAYS call resolve_domain first to check if an MCP connector exists.
    If the user gives a business name, search the web for its domain first.
    """,
    icons=[
        Icon(src=ICON_DATA_URI, mimeType="image/svg+xml", sizes=["48x48"]),
    ],
)


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
async def resolve_domain(domain: str) -> dict:
    """
    Check if an MCP connector exists for a business domain.

    USE THIS when a user wants to shop, book, or interact with a business.
    Examples:
    - "Find products on Gymshark" -> resolve_domain("gymshark.com")
    - "Book a table at Carbone" -> resolve_domain("carbonenewyork.com")

    Args:
        domain: Business website domain (e.g., "gymshark.com", "allbirds.com")

    Returns:
        - mcps: Available MCP connectors with endpoints and capabilities
        - pending_providers: Providers without public MCP yet
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

        # Add hint for AI based on entity count and MCPs
        if all_mcps:
            # Get unique endpoints
            endpoints = list(set(m.get("endpoint") for m in all_mcps if m.get("endpoint")))
            endpoint_list = ", ".join(endpoints) if endpoints else ""

            if len(entities) == 1:
                entity_name = entities[0].get("name", "this entity")
                result["_ai_hint"] = (
                    f"MCP (Model Context Protocol) endpoint found for {entity_name}! "
                    "IMPORTANT: If you (the AI assistant) don't have this MCP connector installed, "
                    "guide the user to add it TO YOU (their AI assistant: Claude, ChatGPT, or Mistral Le Chat). "
                    "Dock AI is just a registry - the connector must be added to the AI assistant itself. "
                    f"MCP URL to add: {endpoint_list}"
                )
            else:
                entity_names = [e.get("name", "Unknown") for e in entities]
                result["_ai_hint"] = (
                    f"This domain has {len(entities)} entities/locations: "
                    f"{', '.join(entity_names)}. MCP (Model Context Protocol) endpoints found! "
                    "IMPORTANT: If you (the AI assistant) don't have these MCP connectors installed, "
                    "guide the user to add them TO YOU (their AI assistant: Claude, ChatGPT, or Mistral Le Chat). "
                    "Dock AI is just a registry - the connectors must be added to the AI assistant itself. "
                    f"MCP URL(s) to add: {endpoint_list}"
                )

            # Add installation instructions for major AI assistants
            result["_install_instructions"] = {
                "claude": {
                    "steps": [
                        "Go to Settings → Connectors",
                        "Click 'Add custom connector'",
                        f"Enter URL: {endpoints[0] if endpoints else ''}",
                        "Click Add"
                    ],
                    "requires": "Pro or Max plan"
                },
                "chatgpt": {
                    "steps": [
                        "Go to Settings → Apps",
                        "Enable Developer mode in Advanced settings",
                        "Click Create under Connectors",
                        f"Enter URL: {endpoints[0] if endpoints else ''}",
                        "Enter name and click Create"
                    ],
                    "requires": "Plus, Pro, or Business plan"
                },
                "mistral_le_chat": {
                    "steps": [
                        "Click Intelligence → Connectors",
                        "Click '+ Add Connector'",
                        "Select 'Custom MCP Connector' tab",
                        f"Enter URL: {endpoints[0] if endpoints else ''}",
                        "Click Connect"
                    ],
                    "requires": "All plans"
                }
            }

        return result


def main():
    """Entry point for the MCP server."""
    mcp.run(transport="http", host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
