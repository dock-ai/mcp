"""
Dynamic Tools Middleware for Dock AI MCP v2.

This middleware intercepts list_tools and call_tool requests to provide
dynamic tools based on user context:
- PUBLIC capabilities: visible to all connected users
- PRIVATE capabilities: visible only to organization members
- Connector proxies: tools proxied from external MCP servers (e.g., Zenchef)

Tool naming convention:
- Capabilities: {slug}_{entity_slug} (e.g., book_lepetitbistro)
- Connector proxies: {connector_slug}_{tool_name} (e.g., zenchef_create_reservation)
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Sequence

import httpx
from mcp.types import Tool

from fastmcp.server.middleware import Middleware, MiddlewareContext, CallNext
from fastmcp.server.dependencies import get_access_token
from fastmcp.tools.tool import ToolResult

logger = logging.getLogger(__name__)


class DynamicToolsMiddleware(Middleware):
    """
    Middleware that adds dynamic tools (capabilities + connector proxies) to the tool list.

    Tools are fetched from dockai-api based on the authenticated user's context:
    - Public capabilities are visible to all authenticated users
    - Private capabilities are only visible to organization members
    - Connector proxies are available for org members with connected providers
    """

    # Cache TTL for dynamic tools (5 minutes)
    CACHE_TTL = timedelta(minutes=5)

    def __init__(
        self,
        api_base: str,
        internal_api_key: str | None = None,
    ):
        """
        Initialize the middleware.

        Args:
            api_base: Base URL for dockai-api (e.g., https://api.dockai.co)
            internal_api_key: API key for internal endpoints (optional)
        """
        self.api_base = api_base.rstrip("/")
        self.internal_api_key = internal_api_key

        # In-memory cache: {cache_key: (tools_data, cached_at)}
        self._cache: dict[str, tuple[dict, datetime]] = {}

        # Track dynamic tool names for routing call_tool
        self._dynamic_tool_names: set[str] = set()

    async def on_list_tools(
        self,
        context: MiddlewareContext,
        call_next: CallNext,
    ) -> Sequence[Tool]:
        """
        Intercept list_tools to add dynamic tools based on user context.

        1. Get static/core tools from next handler
        2. If user is authenticated, fetch and add dynamic tools
        3. Return combined list
        """
        # 1. Get static tools
        static_tools = await call_next(context)

        # 2. Check if user is authenticated
        access_token = get_access_token()
        if not access_token:
            # Not authenticated - return only static tools
            return static_tools

        # Extract user context from token claims
        user_id = access_token.claims.get("sub")
        org_id = access_token.claims.get("org_id")

        if not user_id:
            logger.warning("Access token missing 'sub' claim")
            return static_tools

        # 3. Check cache
        cache_key = f"{user_id}:{org_id or 'none'}"
        if cache_key in self._cache:
            cached_data, cached_at = self._cache[cache_key]
            if datetime.now() - cached_at < self.CACHE_TTL:
                dynamic_tools = self._build_tools_from_cache(cached_data)
                return list(static_tools) + dynamic_tools

        # 4. Fetch from dockai-api
        try:
            tools_data = await self._fetch_dynamic_tools(access_token.token)
            self._cache[cache_key] = (tools_data, datetime.now())
            dynamic_tools = self._build_tools_from_cache(tools_data)
            return list(static_tools) + dynamic_tools
        except Exception as e:
            logger.error(f"Failed to fetch dynamic tools: {e}")
            # Return static tools on error
            return static_tools

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: CallNext,
    ) -> ToolResult:
        """
        Intercept call_tool to handle dynamic tools.

        If the tool is a dynamic capability, execute it via the API.
        If the tool is a connector proxy, forward to the connector MCP.
        Otherwise, delegate to the next handler (static tools).
        """
        # Extract tool name and arguments from context
        params = context.request.params
        tool_name = params.name if params else None
        arguments = params.arguments if params else {}

        if not tool_name:
            return await call_next(context)

        # Check if this is a dynamic tool
        if tool_name not in self._dynamic_tool_names:
            # Not a dynamic tool - delegate to static handler
            return await call_next(context)

        # Get auth token
        access_token = get_access_token()
        if not access_token:
            return ToolResult(
                success=False,
                error="Authentication required for dynamic tools",
            )

        # Parse tool name to determine type
        # Format: {capability_slug}_{entity_slug} or {connector_slug}_{tool_name}
        parts = tool_name.split("_", 1)
        if len(parts) < 2:
            return await call_next(context)

        # Check cache for tool metadata
        user_id = access_token.claims.get("sub")
        org_id = access_token.claims.get("org_id")
        cache_key = f"{user_id}:{org_id or 'none'}"

        if cache_key not in self._cache:
            # Cache miss - try to fetch
            try:
                tools_data = await self._fetch_dynamic_tools(access_token.token)
                self._cache[cache_key] = (tools_data, datetime.now())
            except Exception as e:
                return ToolResult(
                    success=False,
                    error=f"Failed to fetch tool metadata: {e}",
                )

        cached_data, _ = self._cache[cache_key]

        # Find the tool in cached data
        tool_meta = self._find_tool_metadata(tool_name, cached_data)

        if not tool_meta:
            return ToolResult(
                success=False,
                error=f"Dynamic tool '{tool_name}' not found",
            )

        # Execute based on tool type
        if tool_meta.get("type") == "capability":
            return await self._execute_capability(
                access_token.token,
                tool_meta["entity_id"],
                tool_meta["capability_slug"],
                arguments,
            )
        elif tool_meta.get("type") == "connector_proxy":
            return await self._proxy_connector_tool(
                tool_meta["mcp_endpoint"],
                tool_meta["original_tool_name"],
                arguments,
            )
        else:
            return await call_next(context)

    async def _fetch_dynamic_tools(self, auth_token: str) -> dict:
        """
        Fetch capabilities and connectors from dockai-api.

        Returns:
            dict with 'capabilities' and 'connectors' lists
        """
        headers = {
            "Authorization": f"Bearer {auth_token}",
        }
        if self.internal_api_key:
            headers["x-internal-key"] = self.internal_api_key

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.api_base}/api/v1/mcp-tools",
                headers=headers,
                timeout=10.0,
            )

            if response.status_code != 200:
                logger.warning(f"mcp-tools API returned {response.status_code}")
                return {"capabilities": [], "connectors": []}

            return response.json()

    def _build_tools_from_cache(self, data: dict) -> list[Tool]:
        """
        Build Tool objects from cached API response.

        Creates a Tool for each:
        - Capability: {slug}_{entity_slug}
        - Connector proxy: {connector_slug}_{tool_name} (if MCP available)
        """
        tools = []

        # Build capability tools
        for cap in data.get("capabilities", []):
            tool_name = f"{cap['slug']}_{cap['entity_slug']}"
            self._dynamic_tool_names.add(tool_name)

            # Build input schema from capability schema
            input_schema = self._build_input_schema(cap.get("input_schema"))

            description = cap.get("ai_description") or cap.get("name", "")
            entity_name = cap.get("entity_name", "")
            if entity_name:
                description = f"[{entity_name}] {description}"

            tools.append(
                Tool(
                    name=tool_name,
                    description=description,
                    inputSchema=input_schema,
                    annotations={
                        "readOnlyHint": False,
                        "openWorldHint": False,
                    },
                )
            )

        # Note: Connector proxy tools would be added here
        # For now, we don't implement full MCP-to-MCP proxying
        # as it requires establishing connections to external MCPs

        return tools

    def _build_input_schema(self, cap_schema: dict | None) -> dict[str, Any]:
        """
        Convert capability input_schema to JSON Schema format.

        Capability schemas are stored as:
        {
            "field_name": {"type": "string", "required": true, ...}
        }

        Convert to JSON Schema:
        {
            "type": "object",
            "properties": {...},
            "required": [...]
        }
        """
        if not cap_schema:
            return {"type": "object", "properties": {}}

        properties = {}
        required = []

        for field_name, field_def in cap_schema.items():
            if isinstance(field_def, dict):
                prop = {"type": field_def.get("type", "string")}

                # Add description from label
                if field_def.get("label"):
                    prop["description"] = field_def["label"]
                elif field_def.get("description"):
                    prop["description"] = field_def["description"]

                # Add format if specified
                if field_def.get("format"):
                    prop["format"] = field_def["format"]

                properties[field_name] = prop

                # Track required fields
                if field_def.get("required"):
                    required.append(field_name)
            else:
                # Simple type definition
                properties[field_name] = {"type": str(field_def)}

        schema = {
            "type": "object",
            "properties": properties,
        }
        if required:
            schema["required"] = required

        return schema

    def _find_tool_metadata(self, tool_name: str, data: dict) -> dict | None:
        """
        Find metadata for a dynamic tool by name.

        Returns metadata dict with tool type and execution info.
        """
        for cap in data.get("capabilities", []):
            expected_name = f"{cap['slug']}_{cap['entity_slug']}"
            if expected_name == tool_name:
                return {
                    "type": "capability",
                    "entity_id": cap["entity_id"],
                    "capability_slug": cap["slug"],
                    "entity_slug": cap["entity_slug"],
                }

        # Check connectors (not implemented yet)
        for conn in data.get("connectors", []):
            prefix = f"{conn['slug']}_"
            if tool_name.startswith(prefix):
                original_name = tool_name[len(prefix) :]
                return {
                    "type": "connector_proxy",
                    "mcp_endpoint": conn["mcp_endpoint"],
                    "original_tool_name": original_name,
                    "connector_slug": conn["slug"],
                }

        return None

    async def _execute_capability(
        self,
        auth_token: str,
        entity_id: str,
        action: str,
        params: dict,
    ) -> ToolResult:
        """
        Execute a capability via the execute-action API.
        """
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
            "X-Source": "mcp-v2",
        }

        request_body = {
            "entityId": entity_id,
            "action": action,
            "params": params or {},
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.api_base}/api/v1/execute-action",
                    json=request_body,
                    headers=headers,
                    timeout=30.0,
                )

                if response.status_code == 401:
                    return ToolResult(
                        success=False,
                        error="Authentication required for this action",
                    )

                if response.status_code == 404:
                    return ToolResult(
                        success=False,
                        error=f"Action '{action}' not found for this business",
                    )

                if response.status_code == 400:
                    try:
                        data = response.json()
                        return ToolResult(
                            success=False,
                            error=data.get("error", "Invalid parameters"),
                            output=data.get("details", []),
                        )
                    except Exception:
                        return ToolResult(success=False, error="Invalid request")

                if response.status_code == 429:
                    return ToolResult(
                        success=False,
                        error="Rate limit exceeded. Try again later.",
                    )

                if response.status_code not in (200, 201):
                    return ToolResult(
                        success=False,
                        error=f"API error: {response.status_code}",
                    )

                data = response.json()
                return ToolResult(
                    success=True,
                    output=data,
                )

        except httpx.TimeoutException:
            return ToolResult(
                success=False,
                error="Request timed out. The business service may be slow.",
            )
        except Exception as e:
            logger.error(f"Failed to execute capability: {e}")
            return ToolResult(
                success=False,
                error=f"Failed to execute action: {str(e)}",
            )

    async def _proxy_connector_tool(
        self,
        mcp_endpoint: str,
        tool_name: str,
        arguments: dict,
    ) -> ToolResult:
        """
        Proxy a tool call to an external MCP server.

        Note: This is a placeholder implementation. Full MCP-to-MCP proxying
        requires establishing a proper MCP client connection to the external server.
        """
        # For now, return an error indicating this feature is not yet implemented
        return ToolResult(
            success=False,
            error=f"Connector proxy to {mcp_endpoint} is not yet implemented. "
            f"Tool: {tool_name}",
        )
