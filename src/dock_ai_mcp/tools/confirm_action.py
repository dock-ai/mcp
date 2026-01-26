"""
confirm_action tool handler

Confirms or rejects a pending action using the 6-digit code from email.
"""

import logging
import httpx
from fastmcp.server.dependencies import get_access_token

from ..config import API_BASE

logger = logging.getLogger(__name__)


async def confirm_action_handler(
    code: str,
    action: str = "confirm",
    rejection_reason: str | None = None,
) -> dict:
    """
    Confirm or reject a pending action with the 6-digit code from email.

    Args:
        code: The 6-digit confirmation code from the email
        action: "confirm" to execute, "reject" to cancel
        rejection_reason: Optional reason for rejection

    Returns:
        Result with success status and execution details
    """
    # Validate code format
    if not code or not code.isdigit() or len(code) != 6:
        return {
            "error": "Invalid code format",
            "message": "Code must be exactly 6 digits",
            "success": False,
        }

    # Validate action
    if action not in ("confirm", "reject"):
        return {
            "error": "Invalid action",
            "message": "Action must be 'confirm' or 'reject'",
            "success": False,
        }

    # Get auth token (required)
    access_token = get_access_token()
    if not access_token or not access_token.token:
        return {
            "error": "Authentication required",
            "message": "You must be logged in to confirm actions",
            "success": False,
            "_ai_hint": "The user needs to authenticate first.",
        }

    # Prepare request
    request_body = {
        "code": code,
        "action": action,
    }
    if rejection_reason and action == "reject":
        request_body["rejectionReason"] = rejection_reason

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token.token}",
        "X-Source": "mcp",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{API_BASE}/api/v1/confirm-action",
            json=request_body,
            headers=headers,
            timeout=30.0,
        )

        return _handle_response(response, action)


def _handle_response(response: httpx.Response, action: str) -> dict:
    """Handle the API response."""

    if response.status_code == 401:
        return {
            "error": "Authentication required",
            "success": False,
            "_ai_hint": "The user needs to log in to confirm this action.",
        }

    if response.status_code == 404:
        return {
            "error": "Confirmation code not found",
            "message": "This code is invalid or has already been used.",
            "success": False,
        }

    if response.status_code == 410:
        return {
            "error": "Action expired",
            "message": "This confirmation code has expired. The user needs to trigger the action again.",
            "success": False,
        }

    if response.status_code == 403:
        return {
            "error": "Permission denied",
            "message": "Only the user who triggered the action can confirm it.",
            "success": False,
        }

    if response.status_code == 502:
        try:
            data = response.json()
            return {
                "success": False,
                "status": "confirmed_but_failed",
                "message": data.get("message", "Action confirmed but webhook failed"),
                "result": data.get("result"),
            }
        except Exception:
            return {"error": "Webhook execution failed", "success": False}

    if response.status_code not in (200, 201):
        return {"error": f"API error: {response.status_code}", "success": False}

    try:
        data = response.json()
    except Exception:
        return {"error": "Invalid response from API", "success": False}

    # Success cases
    if action == "reject":
        return {
            "success": True,
            "status": "rejected",
            "message": data.get("message", "Action has been rejected."),
            "_ai_hint": "The action was rejected. No webhook was executed.",
        }

    return {
        "success": data.get("success", True),
        "status": data.get("status", "confirmed"),
        "action": data.get("action"),
        "business": data.get("business"),
        "message": data.get("message", "Action confirmed and executed."),
        "result": data.get("result"),
        "_ai_hint": data.get("_ai_hint", "Action was confirmed and executed successfully."),
    }
