"""
execute_action tool handler

Executes a business capability action via the dockai-api.
Supports builtin, webhook, and API call handlers.
"""

import logging
import httpx
from fastmcp.server.dependencies import get_access_token

from ..config import API_BASE
from ..validators import is_valid_uuid, is_valid_action_slug, contains_sensitive_field
from ..responses import sensitive_data_blocked

logger = logging.getLogger(__name__)


async def execute_action_handler(
    entity_id: str,
    action: str,
    params: dict | None = None,
) -> dict:
    """
    Execute a business action like booking, sending a message, or searching.

    Args:
        entity_id: The entity ID (UUID) from resolve_domain response
        action: The action slug to execute
        params: Parameters for the action (varies by action type)

    Returns:
        Execution result with success status and any returned data
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
            "message": "Action must start with a letter and contain only lowercase letters, numbers, and underscores (max 50 chars)",
            "success": False,
        }

    # SECURITY: Check for sensitive fields in params (prevent data phishing)
    if params:
        sensitive_found = contains_sensitive_field(params)
        if sensitive_found:
            logger.warning(
                f"SECURITY: Blocked sensitive fields in params: {sensitive_found}"
            )
            result = sensitive_data_blocked(sensitive_found)
            result["blocked_fields"] = sensitive_found
            return result

    # Get auth token (optional for some actions)
    access_token = get_access_token()
    auth_token = access_token.token if access_token else None

    # Prepare request
    request_body = {
        "entityId": entity_id,
        "action": action,
        "params": params or {},
    }

    headers = {
        "Content-Type": "application/json",
        "X-Source": "mcp",
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{API_BASE}/api/v1/execute-action",
            json=request_body,
            headers=headers,
            timeout=30.0,
        )

        # Handle different response codes
        return _handle_response(response, action)


def _handle_response(response: httpx.Response, action: str) -> dict:
    """Handle the API response and return appropriate result."""
    if response.status_code == 401:
        return {
            "error": "Authentication required for this action",
            "success": False,
            "_ai_hint": "This action requires the user to be logged in. Ask them to authenticate first.",
        }

    if response.status_code == 404:
        return {
            "error": f"Action '{action}' not found for this business",
            "success": False,
            "_ai_hint": "This business doesn't have this action configured. Use resolve_domain to see available capabilities.",
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
        return {
            "error": "Rate limit exceeded. Try again later.",
            "success": False,
        }

    if response.status_code == 402:
        try:
            data = response.json()
            return {
                "error": data.get("error", "Usage limit exceeded"),
                "message": data.get(
                    "message",
                    "Monthly execution limit reached. Please upgrade your plan.",
                ),
                "usage": data.get("usage"),
                "upgrade_url": data.get("upgrade_url", "https://business.dockai.co"),
                "success": False,
                "_ai_hint": data.get(
                    "_ai_hint",
                    "The business has reached their monthly execution limit. They need to upgrade their Dock AI plan to continue.",
                ),
            }
        except Exception:
            return {
                "error": "Usage limit exceeded",
                "message": "The business has reached their monthly limit. They need to upgrade at https://business.dockai.co",
                "success": False,
            }

    if response.status_code == 502:
        try:
            data = response.json()
            return {
                "error": data.get("error", "Business webhook unavailable"),
                "message": data.get(
                    "message", "The business service is temporarily unavailable"
                ),
                "success": False,
            }
        except Exception:
            return {"error": "Business webhook unavailable", "success": False}

    if response.status_code not in (200, 201):
        return {"error": f"API error: {response.status_code}", "success": False}

    try:
        data = response.json()
    except Exception as e:
        logger.error(f"Failed to parse API response: {e}")
        return {"error": "Invalid response from API", "success": False}

    # Check if action requires confirmation (email verification)
    if data.get("status") == "pending_confirmation":
        return {
            "success": True,
            "status": "pending_confirmation",
            "action": action,
            "message": data.get("message", "This action requires confirmation."),
            "expires_in": data.get("expires_in"),
            "_ai_hint": data.get(
                "_ai_hint",
                "A confirmation email has been sent to the user. They must confirm before the action executes.",
            ),
        }

    # Check if the response indicates success with result
    if data.get("success") is True:
        return {
            "success": True,
            "action": action,
            "result": data.get("result", {}),
            "_ai_hint": data.get(
                "_ai_hint",
                f"Action '{action}' executed successfully. Present the result to the user.",
            ),
        }

    # Fallback for other success responses
    return {
        "success": True,
        "action": action,
        "result": data.get("result", {}),
        "_ai_hint": f"Action '{action}' executed successfully. Present the result to the user.",
    }
