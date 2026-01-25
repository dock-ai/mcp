"""
my_organization tool handler (exposed as my_capabilities)

Discovers the user's private capabilities from their organization.
Used when users want to use their own business tools (CRM sync, email, workflows).
"""

import logging
import httpx
from fastmcp.server.dependencies import get_access_token

from ..config import API_BASE
from ..responses import auth_required, auth_expired, not_found, api_error

logger = logging.getLogger(__name__)


async def my_organization_handler() -> dict:
    """
    Discover user's private capabilities (CRM sync, email, workflows).

    Returns available actions that can be executed with execute_action().
    Requires authentication via OAuth.

    Returns:
        Available entities, capabilities, and helpful hints
    """
    # Get auth token - required for this endpoint
    access_token = get_access_token()
    if not access_token:
        return auth_required()

    auth_token = access_token.token

    async with httpx.AsyncClient() as client:
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "X-Source": "mcp",
        }

        response = await client.get(
            f"{API_BASE}/api/v1/my-organization",
            headers=headers,
            timeout=10.0,
        )

        if response.status_code == 401:
            return auth_expired()

        if response.status_code == 404:
            result = not_found("Organization")
            result["message"] = "You are not a member of any organization. Register or claim a business first at https://dockai.co"
            result["_ai_hint"] = "The user doesn't have an organization yet. Guide them to register their business at dockai.co"
            return result

        if response.status_code != 200:
            return api_error(response.status_code)

        try:
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to parse API response: {e}")
            return {"error": "Invalid response from API"}

        # Enhance response with helpful hints
        entities = data.get("entities", [])
        total_caps = sum(len(e.get("capabilities", [])) for e in entities)

        if total_caps > 0:
            # Build a summary of available actions
            all_caps = []
            for entity in entities:
                for cap in entity.get("capabilities", []):
                    all_caps.append(f"{cap['action']} ({entity['name']})")

            data["_ai_hint"] = (
                f"You have access to {total_caps} capability(ies) across {len(entities)} entity(ies): {', '.join(all_caps)}. "
                "BEFORE executing any action: 1) Identify the right capability, 2) Collect missing parameters from user, "
                "3) Show EXACTLY what will be sent and ask for confirmation, 4) Execute ONLY after user approves. "
                "Some actions trigger real business processes (emails, payments)!"
            )
        else:
            data["_ai_hint"] = (
                "No capabilities configured yet. "
                "Go to the Dock AI dashboard at https://business.dockai.co to add capabilities to your entities."
            )

        return data
