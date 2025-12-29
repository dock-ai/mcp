"""
Dock AI MCP Server

Allows AI agents to discover MCP endpoints for real-world entities.
"""

import httpx
from fastmcp import FastMCP

API_BASE = "https://api.dockai.co"

mcp = FastMCP(
    name="Dock AI",
    instructions="""
    Use this server to discover MCP endpoints for real-world entities.
    Given a domain (e.g., "example-restaurant.com"), you can find which MCP
    servers can interact with that entity and what capabilities they offer.
    """,
)


@mcp.tool
async def resolve_domain(domain: str) -> dict:
    """
    Resolve a domain to its MCP endpoints.

    Given a domain, returns the entity information and available MCP endpoints
    that can interact with this entity.

    Args:
        domain: The domain to resolve (e.g., "example-restaurant.com")

    Returns:
        Entity information including name, category, verification level,
        and list of MCP endpoints with their capabilities.
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

        return response.json()


def main():
    """Entry point for the MCP server."""
    mcp.run(transport="http", host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
