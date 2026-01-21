"""
Dock AI MCP Gateway (v2)

FastMCP 3.0 Architecture:
- Per-session visibility: tools are enabled/disabled per session using tags
- Dynamic tool discovery: resolve_domain() activates connector/entity tools for the session
- Proxy mounting: external MCP servers (Zenchef, etc.) are mounted dynamically

Flow:
1. Agent connects -> list_tools() returns only `resolve_domain`
2. Agent calls resolve_domain("business.fr")
3. Dock AI enables connector/entity tools for THIS SESSION
4. Agent refreshes list_tools() -> sees connector tools + entity capabilities
5. Agent calls connector/capability tools directly
"""

import os
import re
import httpx
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any
from pydantic import Field
from fastmcp import FastMCP
from fastmcp.server.context import Context
from fastmcp.server.dependencies import get_access_token
from mcp.types import Icon

logger = logging.getLogger(__name__)

# Validation patterns
DOMAIN_PATTERN = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$",
    re.IGNORECASE,
)
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

from .oauth_provider import DockAIOAuthProvider

# Environment variables
API_BASE = os.environ.get("DOCKAI_API_URL", "https://api.dockai.co")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY")
MCP_BASE_URL = os.environ.get("MCP_BASE_URL", "https://mcp.dockai.co")
IS_PRODUCTION = (
    os.environ.get("VERCEL_ENV") == "production"
    or os.environ.get("NODE_ENV") == "production"
)

# Validate required environment variables in production
if IS_PRODUCTION and not INTERNAL_API_KEY:
    raise RuntimeError("SECURITY: INTERNAL_API_KEY is required in production")

# Dock AI icon (teal gradient with lightning bolt)
ICON_DATA_URI = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCA0OCA0OCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjQ4IiBoZWlnaHQ9IjQ4IiByeD0iMTEiIGZpbGw9InVybCgjcGFpbnQwX2xpbmVhcl8xXzUpIi8+CjxwYXRoIGQ9Ik0xNC4yMjU5IDI2LjM5OTRDMTMuOTk0NyAyNi40MDAxIDEzLjc2OCAyNi4zMzY1IDEzLjU3MjIgMjYuMjE1OEMxMy4zNzY0IDI2LjA5NTEgMTMuMjE5NSAyNS45MjIzIDEzLjExOTcgMjUuNzE3NUMxMy4wMTk5IDI1LjUxMjggMTIuOTgxMyAyNS4yODQ0IDEzLjAwODQgMjUuMDU4OUMxMy4wMzU2IDI0LjgzMzUgMTMuMTI3MyAyNC42MjAyIDEzLjI3MyAyNC40NDM5TDI1LjM2ODQgMTIuMjA3MUMyNS40NTkxIDEyLjEwNDIgMjUuNTgyNyAxMi4wMzQ3IDI1LjcxOSAxMi4wMUMyNS44NTUyIDExLjk4NTMgMjUuOTk2IDEyLjAwNjcgMjYuMTE4MiAxMi4wNzA5QzI2LjI0MDQgMTIuMTM1MSAyNi4zMzY3IDEyLjIzODEgMjYuMzkxNCAxMi4zNjMyQzI2LjQ0NjEgMTIuNDg4MiAyNi40NTU4IDEyLjYyNzcgMjYuNDE5MSAxMi43NTg5TDI0LjA3MzMgMTkuOTgxQzI0LjAwNDEgMjAuMTYyOCAyMy45ODA5IDIwLjM1ODQgMjQuMDA1NiAyMC41NTA5QzI0LjAzMDMgMjAuNzQzNCAyNC4xMDIyIDIwLjkyNzIgMjQuMjE1MSAyMS4wODY1QzI0LjMyODEgMjEuMjQ1NyAyNC40Nzg3IDIxLjM3NTcgMjQuNjU0IDIxLjQ2NTNDMjQuODI5MyAyMS41NTQ4IDI1LjAyNDEgMjEuNjAxMyAyNS4yMjE4IDIxLjYwMDZIMzMuNzc0MUMzNC4wMDUzIDIxLjU5OTkgMzQuMjMyIDIxLjY2MzUgMzQuNDI3OCAyMS43ODQyQzM0LjYyMzYgMjEuOTA0OSAzNC43ODA1IDIyLjA3NzcgMzQuODgwMyAyMi4yODI1QzM0Ljk4MDEgMjIuNDg3MiAzNS4wMTg3IDIyLjcxNTYgMzQuOTkxNiAyMi45NDExQzM0Ljk2NDQgMjMuMTY2NSAzNC44NzI3IDIzLjM3OTggMzQuNzI3IDIzLjU1NjFMMjIuNjMxNiAzNS43OTI5QzIyLjU0MDkgMzUuODk1OCAyMi40MTczIDM1Ljk2NTMgMjIuMjgxIDM1Ljk5QzIyLjE0NDggMzYuMDE0NyAyMi4wMDQgMzUuOTkzMyAyMS44ODE4IDM1LjkyOTFDMjEuNzU5NiAzNS44NjQ5IDIxLjY2MzMgMzUuNzYxOSAyMS42MDg2IDM1LjYzNjhDMjEuNTUzOSAzNS41MTE4IDIxLjU0NDIgMzUuMzcyMyAyMS41ODA5IDM1LjI0MTFMMjMuOTI2NyAyOC4wMTlDMjMuOTk1OSAyNy44MzcyIDI0LjAxOTEgMjcuNjQxNiAyMy45OTQ0IDI3LjQ0OTFDMjMuOTY5NyAyNy4yNTY2IDIzLjg5NzggMjcuMDcyOCAyMy43ODQ5IDI2LjkxMzVDMjMuNjcxOSAyNi43NTQzIDIzLjUyMTMgMjYuNjI0MyAyMy4zNDYgMjYuNTM0N0MyMy4xNzA3IDI2LjQ0NTIgMjIuOTc1OSAyNi4zOTg3IDIyLjc3ODIgMjYuMzk5NEgxNC4yMjU5WiIgZmlsbD0id2hpdGUiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMV81IiB4MT0iNy41IiB5MT0iNy41IiB4Mj0iMzciIHkyPSI0MS41IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CjxzdG9wIHN0b3AtY29sb3I9IiMwRDk0ODgiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjMTRCOEE2Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg=="

# Check deployment environment
IS_SERVERLESS = os.environ.get("VERCEL") == "1"
IS_RAILWAY = os.environ.get("RAILWAY_ENVIRONMENT") is not None

# Railway provides PORT, default to 8080 for local dev
PORT = int(os.environ.get("PORT", 8080))


# ============== HELPER FUNCTIONS (defined before mcp) ==============


async def _fetch_business(domain: str, auth_token: str | None = None) -> dict:
    """Fetch business info from dockai-api."""
    async with httpx.AsyncClient() as client:
        headers = {"X-Source": "mcp"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        response = await client.get(
            f"{API_BASE}/api/v1/resolve",
            params={"domain": domain},
            timeout=10.0,
            headers=headers,
        )

        if response.status_code == 404:
            return {"error": "Entity not found", "domain": domain}

        if response.status_code != 200:
            return {"error": f"API error: {response.status_code}"}

        try:
            return response.json()
        except Exception as e:
            logger.error(f"Failed to parse API response: {e}")
            return {"error": "Invalid response from API"}


async def _execute_capability(
    entity_id: str,
    action: str,
    params: dict,
    auth_token: str | None = None,
) -> dict:
    """Execute a capability via the execute-action API."""
    headers = {
        "Content-Type": "application/json",
        "X-Source": "mcp-v2",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    request_body = {
        "entityId": entity_id,
        "action": action,
        "params": params or {},
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{API_BASE}/api/v1/execute-action",
            json=request_body,
            headers=headers,
            timeout=30.0,
        )

        if response.status_code == 401:
            return {
                "error": "Authentication required for this action",
                "success": False,
            }

        if response.status_code == 404:
            return {
                "error": f"Action '{action}' not found for this business",
                "success": False,
            }

        if response.status_code == 400:
            try:
                data = response.json()
                return {
                    "error": data.get("error", "Invalid parameters"),
                    "details": data.get("details", []),
                    "success": False,
                }
            except Exception:
                return {"error": "Invalid request", "success": False}

        if response.status_code == 429:
            return {"error": "Rate limit exceeded. Try again later.", "success": False}

        if response.status_code not in (200, 201):
            return {"error": f"API error: {response.status_code}", "success": False}

        try:
            data = response.json()
            return {"success": True, "result": data.get("result", {})}
        except Exception as e:
            logger.error(f"Failed to parse API response: {e}")
            return {"error": "Invalid response from API", "success": False}


def _build_json_schema(input_schema: dict | None) -> dict:
    """
    Convert capability input_schema to JSON Schema format.

    Input format:
    {"field": {"type": "string", "required": true, "label": "..."}}

    Output format (JSON Schema):
    {"type": "object", "properties": {...}, "required": [...]}
    """
    if not input_schema:
        return {"type": "object", "properties": {}}

    properties = {}
    required = []

    for field_name, field_def in input_schema.items():
        if isinstance(field_def, dict):
            prop = {"type": field_def.get("type", "string")}

            if field_def.get("label"):
                prop["description"] = field_def["label"]
            elif field_def.get("description"):
                prop["description"] = field_def["description"]

            if field_def.get("format"):
                prop["format"] = field_def["format"]

            properties[field_name] = prop

            if field_def.get("required"):
                required.append(field_name)
        else:
            properties[field_name] = {"type": str(field_def)}

    schema = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required

    return schema


def _register_capability_tool(
    server: FastMCP,
    entity_id: str,
    entity_slug: str,
    entity_name: str,
    cap_slug: str,
    cap_name: str,
    ai_description: str | None,
    input_schema: dict | None,
) -> None:
    """
    Dynamically register a capability tool on the server.

    Tool naming: {cap_slug}_{entity_slug} (e.g., book_lepetitbistro)
    Tags: entity:{entity_id}, capability:{cap_slug}
    """
    tool_name = f"{cap_slug}_{entity_slug}"
    tags = {f"entity:{entity_id}", f"capability:{cap_slug}"}

    description = ai_description or cap_name
    if entity_name:
        description = f"[{entity_name}] {description}"

    # Build JSON Schema from input_schema
    _build_json_schema(input_schema)

    # Create the tool function dynamically
    # Capture entity_id and cap_slug in closure
    _entity_id = entity_id
    _cap_slug = cap_slug

    async def cap_tool_fn(ctx: Context, **params: Any) -> dict:
        """Execute capability."""
        access_token = get_access_token()
        auth_token = access_token.token if access_token else None
        return await _execute_capability(_entity_id, _cap_slug, params, auth_token)

    # Set function metadata
    cap_tool_fn.__name__ = tool_name
    cap_tool_fn.__doc__ = description

    # Register the tool with tags
    server.tool(name=tool_name, tags=tags)(cap_tool_fn)

    # Disable by default (enabled per-session after resolve_domain)
    server.disable(tags={f"entity:{entity_id}"})

    logger.info(f"Registered capability tool: {tool_name} (tags: {tags})")


async def _register_capabilities_at_startup(server: FastMCP) -> None:
    """
    Fetch and register all capabilities at startup.

    All tools are disabled by default. They are enabled per-session
    after resolve_domain() is called for a matching entity.
    """
    if not INTERNAL_API_KEY:
        logger.warning("No INTERNAL_API_KEY - skipping capability registration")
        return

    try:
        async with httpx.AsyncClient() as client:
            headers = {"x-internal-key": INTERNAL_API_KEY}
            response = await client.get(
                f"{API_BASE}/api/v1/mcp-tools",
                headers=headers,
                timeout=30.0,
            )

            if response.status_code != 200:
                logger.error(f"Failed to fetch capabilities: {response.status_code}")
                return

            data = response.json()
            capabilities = data.get("capabilities", [])

            for cap in capabilities:
                _register_capability_tool(
                    server=server,
                    entity_id=cap["entity_id"],
                    entity_slug=cap["entity_slug"],
                    entity_name=cap.get("entity_name", ""),
                    cap_slug=cap["slug"],
                    cap_name=cap.get("name", ""),
                    ai_description=cap.get("ai_description"),
                    input_schema=cap.get("input_schema"),
                )

            logger.info(f"Registered {len(capabilities)} capability tools")

    except Exception as e:
        logger.error(f"Failed to register capabilities: {e}")


# ============== SERVER LIFESPAN ==============


@asynccontextmanager
async def gateway_lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """
    Manage gateway lifecycle.

    - Startup: Register all capabilities as disabled tools
    - Shutdown: Cleanup
    """
    logger.info("Dock AI Gateway v2 starting...")
    await _register_capabilities_at_startup(server)
    logger.info("Dock AI Gateway v2 ready")
    try:
        yield {}
    finally:
        logger.info("Dock AI Gateway v2 shutting down...")


# ============== SERVER CREATION ==============


# OAuth 2.1 Authorization Server with DCR
# All DB operations delegated to dockai-api
oauth_provider = (
    DockAIOAuthProvider(
        internal_api_key=INTERNAL_API_KEY,
        api_base=API_BASE,
        base_url=MCP_BASE_URL,
    )
    if INTERNAL_API_KEY
    else None
)

mcp = FastMCP(
    name="Dock AI Gateway",
    auth=oauth_provider,
    lifespan=gateway_lifespan,
    instructions="""
    Dock AI Gateway - Dynamic MCP connector discovery for businesses.

    AUTHENTICATION REQUIRED: You must authenticate to use this MCP.
    Go to https://api.dockai.co/auth to get started.

    ═══════════════════════════════════════════════════════════════════════
    HOW IT WORKS - Dynamic Tool Discovery
    ═══════════════════════════════════════════════════════════════════════

    1. Initially, you only see `resolve_domain` tool
    2. Call resolve_domain("business-domain.com") to discover capabilities
    3. After resolve_domain, new tools appear based on:
       - Connected providers (Zenchef, etc.) -> zenchef:book, zenchef:cancel
       - Business capabilities -> book_lepetitbistro, send_message_restaurant
    4. Refresh your tool list to see the new tools
    5. Call the discovered tools directly (no execute_action wrapper needed)

    EXAMPLE FLOW:
    - User: "Book a table at Septime Paris"
    - You: call resolve_domain("septime-charonne.fr")
    - You: refresh tools -> see zenchef:book (if Septime uses Zenchef)
    - You: call zenchef:book(restaurant_id="xxx", date="2024-02-15", guests=4)

    ⚠️ ALWAYS CONFIRM BEFORE EXECUTING ACTIONS:
    Before calling any action tool, you MUST:
    1. Show the user what action will be executed
    2. List all parameters that will be sent
    3. Ask for explicit confirmation
    4. Only proceed after the user confirms
    """,
    icons=[
        Icon(src=ICON_DATA_URI, mimeType="image/svg+xml", sizes=["48x48"]),
    ],
)


# ============== PROMPTS ==============


@mcp.prompt()
def discover_business(
    business_name: Annotated[str, Field(description="Name of the business to discover")]
) -> str:
    """Help discover MCP connectors for a business by name."""
    return f"""I want to interact with {business_name}.

Please:
1. Search for their website domain
2. Use resolve_domain to check if an MCP connector exists
3. After resolve_domain, refresh your tool list to see new tools
4. Tell me what actions are available (use the new tools directly)"""


@mcp.prompt()
def setup_connector() -> str:
    """Guide for setting up MCP connectors in AI assistants."""
    return """Please help me set up an MCP connector in my AI assistant.

I need step-by-step instructions for:
- Claude (Anthropic)
- ChatGPT (OpenAI)
- Le Chat (Mistral)

The MCP server URL is: https://mcp.dockai.co"""


# ============== RESOURCES ==============


@mcp.resource("docs://getting-started")
def getting_started_guide() -> str:
    """Getting started guide for Dock AI Gateway."""
    return """# Getting Started with Dock AI Gateway

Dock AI Gateway helps AI agents discover and interact with business capabilities.

## How it works (v2 - Dynamic Tools)

1. **Call resolve_domain**: Discover a business's capabilities
   ```
   resolve_domain("septime-charonne.fr")
   ```

2. **Refresh tools**: After resolve_domain, new tools become available
   - Provider tools: zenchef:book, zenchef:cancel (if business uses Zenchef)
   - Capability tools: book_septime, send_message_septime

3. **Call tools directly**: No wrapper needed
   ```
   zenchef:book(restaurant_id="xxx", date="2024-02-15", guests=4)
   ```

## Key Benefits

- **Dynamic discovery**: Tools appear based on what the business supports
- **Direct execution**: Call provider APIs directly, no intermediary
- **Per-session**: Different sessions can have different tools

## Documentation

Visit https://dockai.co/docs for full documentation.
"""


@mcp.resource("docs://supported-providers")
def supported_providers() -> str:
    """List of supported MCP providers."""
    return """# Supported MCP Providers

Dock AI Gateway indexes businesses served by these providers:

## Booking & Reservations
- ZenChef (restaurants) - MCP available
- TheFork (restaurants) - Coming soon
- Resy (restaurants) - Coming soon

## E-commerce
- Shopify Storefront MCP

## How providers work

When you call resolve_domain, Dock AI detects which providers the business uses.
If the provider has an MCP server, their tools become available for your session.

## Add your provider

If you're an MCP provider, register at https://provider.dockai.co
"""


# ============== CORE TOOL - Always Visible ==============


@mcp.tool(annotations={"readOnlyHint": True, "openWorldHint": True})
async def resolve_domain(
    ctx: Context,
    domain: Annotated[
        str,
        Field(
            description="Business website domain without protocol (e.g., 'gymshark.com', 'septime-charonne.fr')",
            min_length=3,
            max_length=255,
        ),
    ],
) -> dict:
    """
    Discover capabilities for a business domain.

    After calling this tool:
    1. Refresh your tool list (list_tools)
    2. New tools will appear based on the business's connected providers and capabilities
    3. Call those tools directly to interact with the business

    USE THIS when a user wants to shop, book, or interact with a business.
    Examples:
    - "Find products on Gymshark" -> resolve_domain("gymshark.com")
    - "Book a table at Carbone" -> resolve_domain("carbonenewyork.com")

    Returns:
        - entity: Business information (name, category, location)
        - connectors: Detected providers (Zenchef, Shopify, etc.)
        - capabilities: Available actions (book, send_message, etc.)
        - _tools_unlocked: List of tools now available for your session
    """
    # Validate domain format
    domain = domain.lower().strip()
    if not DOMAIN_PATTERN.match(domain):
        return {"error": "Invalid domain format", "domain": domain}

    # Get auth token from FastMCP dependency
    access_token = get_access_token()
    auth_token = access_token.token if access_token else None

    # Fetch business info from dockai-api
    data = await _fetch_business(domain, auth_token)

    if data.get("error"):
        return data

    entity = data.get("entity")
    connectors = data.get("connectors", [])
    capabilities = data.get("capabilities", [])

    if not entity:
        return {"error": "No entity found for this domain", "domain": domain}

    entity_id = entity.get("id")
    entity_slug = entity.get("slug", "")
    entity_name = entity.get("name", "")

    unlocked_tools = []

    # Enable connector tools for THIS SESSION
    for connector in connectors:
        connector_slug = connector.get("slug")
        mcp_endpoint = connector.get("mcp_endpoint")

        if connector_slug and connector.get("status") == "connected":
            tag = f"connector:{connector_slug}"
            try:
                await ctx.enable_components(tags={tag})
                logger.info(f"Enabled connector {connector_slug} for session")

                # If connector has MCP endpoint, note it
                if mcp_endpoint:
                    unlocked_tools.append(
                        {
                            "type": "connector",
                            "connector": connector_slug,
                            "mcp_endpoint": mcp_endpoint,
                        }
                    )
            except Exception as e:
                logger.warning(f"Failed to enable connector {connector_slug}: {e}")

    # Enable entity capability tools for THIS SESSION
    if entity_id:
        tag = f"entity:{entity_id}"
        try:
            await ctx.enable_components(tags={tag})
            logger.info(f"Enabled entity {entity_id} tools for session")

            # List capability tools that were unlocked
            for cap in capabilities:
                tool_name = f"{cap.get('action', cap.get('slug'))}_{entity_slug}"
                unlocked_tools.append(
                    {
                        "type": "capability",
                        "tool": tool_name,
                        "action": cap.get("action", cap.get("slug")),
                        "entity": entity_name,
                    }
                )
        except Exception as e:
            logger.warning(f"Failed to enable entity {entity_id} tools: {e}")

    # Build response
    result = {
        "domain": domain,
        "entity": entity,
        "connectors": connectors,
        "capabilities": capabilities,
    }

    # Add AI hints
    if unlocked_tools:
        result["_tools_unlocked"] = unlocked_tools
        result["_ai_hint"] = (
            f"Tools have been unlocked for {entity_name}! "
            "IMPORTANT: Refresh your tool list (list_tools) to see the new tools. "
            f"Unlocked: {len(unlocked_tools)} tool(s). "
            "Call these tools directly to interact with the business."
        )
    elif connectors:
        connector_names = [c.get("name", c.get("slug")) for c in connectors]
        result["_ai_hint"] = (
            f"This business uses: {', '.join(connector_names)}. "
            "However, these providers don't have MCP connectors available yet."
        )
    else:
        result["_ai_hint"] = (
            "No connectors or capabilities found for this business. "
            "They may not have registered with Dock AI yet."
        )

    # Add installation instructions if MCP endpoints are available
    mcp_endpoints = [c.get("mcp_endpoint") for c in connectors if c.get("mcp_endpoint")]
    if mcp_endpoints:
        result["_install_instructions"] = {
            "claude": {
                "steps": [
                    "Go to Settings -> Connectors",
                    "Click 'Add custom connector'",
                    f"Enter URL: {mcp_endpoints[0]}",
                    "Click Add",
                ],
                "requires": "Pro or Max plan",
            },
            "chatgpt": {
                "steps": [
                    "Go to Settings -> Apps",
                    "Enable Developer mode in Advanced settings",
                    "Click Create under Connectors",
                    f"Enter URL: {mcp_endpoints[0]}",
                    "Enter name and click Create",
                ],
                "requires": "Plus, Pro, or Business plan",
            },
            "mistral_le_chat": {
                "steps": [
                    "Click Intelligence -> Connectors",
                    "Click '+ Add Connector'",
                    "Select 'Custom MCP Connector' tab",
                    f"Enter URL: {mcp_endpoints[0]}",
                    "Click Connect",
                ],
                "requires": "All plans",
            },
        }

    return result


# ============== HEALTH CHECK ==============


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    """Health check endpoint for Railway."""
    from starlette.responses import JSONResponse

    return JSONResponse({"status": "ok", "version": "2.0.0"})


# ============== ENTRY POINT ==============


def main():
    """Entry point for the MCP server."""
    # Railway/persistent: stateless_http=False (maintains sessions)
    # Vercel/serverless: stateless_http=True (no session state)
    stateless = IS_SERVERLESS and not IS_RAILWAY

    logger.info(f"Starting Dock AI Gateway on port {PORT} (stateless={stateless})")
    mcp.run(transport="http", host="0.0.0.0", port=PORT, stateless_http=stateless)


if __name__ == "__main__":
    main()
