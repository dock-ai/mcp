"""
prepare_action tool handler

Returns entity and capability info for displaying an interactive form.
Does NOT execute the action - that's done via execute_action from the UI.
"""

import logging
import httpx
from fastmcp.server.dependencies import get_access_token

from ..config import API_BASE
from ..validators import is_valid_uuid, is_valid_action_slug

logger = logging.getLogger(__name__)


async def prepare_action_handler(
    entity_id: str,
    action: str,
) -> dict:
    """
    Prepare an action form by returning entity and capability info.

    Args:
        entity_id: The entity ID (UUID)
        action: The action slug (e.g., 'send_message', 'book')

    Returns:
        Entity info and input_schema for the form
    """
    # Validate entity_id format (UUID)
    if not is_valid_uuid(entity_id):
        return {"error": "Invalid entity_id format (must be UUID)", "success": False}

    # Validate action slug format
    action = action.strip().lower()
    if not action:
        return {"error": "Action cannot be empty", "success": False}
    if not is_valid_action_slug(action):
        return {
            "error": "Invalid action format",
            "success": False,
        }

    # Get auth token
    access_token = get_access_token()
    auth_token = access_token.token if access_token else None

    headers = {"X-Source": "mcp"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    # Fetch entity and capability info
    async with httpx.AsyncClient() as client:
        # Get entity info
        response = await client.get(
            f"{API_BASE}/api/v1/entity/{entity_id}",
            headers=headers,
            timeout=10.0,
        )

        if response.status_code == 404:
            return {"error": "Entity not found", "success": False}

        if response.status_code != 200:
            return {"error": f"API error: {response.status_code}", "success": False}

        try:
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to parse API response: {e}")
            return {"error": "Invalid response from API", "success": False}

        entity = data.get("entity", data)
        capabilities = data.get("capabilities", [])

        # Find the specific capability
        capability = next(
            (c for c in capabilities if c.get("action") == action or c.get("slug") == action),
            None
        )

        if not capability:
            return {
                "error": f"Action '{action}' not found for this entity",
                "success": False,
                "available_actions": [c.get("action", c.get("slug")) for c in capabilities],
            }

        # Return the form data
        return {
            "success": True,
            "mode": "form",
            "entity_id": entity_id,
            "entity": {
                "id": entity.get("id"),
                "name": entity.get("name"),
                "domain": entity.get("domain"),
                "category": entity.get("category"),
            },
            "action": action,
            "capability": {
                "name": capability.get("name"),
                "description": capability.get("description", capability.get("ai_description")),
                "input_schema": capability.get("input_schema", {}),
            },
            "_ai_hint": f"Display the interactive form for '{action}'. The user can fill in the fields and submit.",
        }
