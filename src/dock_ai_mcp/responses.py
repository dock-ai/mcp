"""
Standardized response builders for MCP tool handlers.

Provides consistent response formats across all tools with
helpful hints for AI agents.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResponse:
    """
    Standard response structure for MCP tool handlers.

    Attributes:
        success: Whether the operation succeeded
        result: The result data (if successful)
        error: Error message (if failed)
        message: Human-readable status message
        _ai_hint: Instructions for the AI agent on how to present/handle the response
    """

    success: bool
    result: dict[str, Any] | None = None
    error: str | None = None
    message: str | None = None
    _ai_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON response."""
        data: dict[str, Any] = {"success": self.success}

        if self.result is not None:
            data["result"] = self.result
        if self.error is not None:
            data["error"] = self.error
        if self.message is not None:
            data["message"] = self.message
        if self._ai_hint is not None:
            data["_ai_hint"] = self._ai_hint

        return data


# ========================================
# PRE-CONFIGURED ERROR RESPONSES
# ========================================


def auth_required() -> dict[str, Any]:
    """Authentication required error."""
    return ToolResponse(
        success=False,
        error="Authentication required",
        message="You must be logged in to perform this action. Connect your MCP client with OAuth to authenticate.",
        _ai_hint="The user needs to authenticate first. Guide them to connect their AI assistant with Dock AI OAuth.",
    ).to_dict()


def auth_expired() -> dict[str, Any]:
    """Authentication expired error."""
    return ToolResponse(
        success=False,
        error="Authentication expired or invalid",
        message="Please re-authenticate with Dock AI.",
        _ai_hint="The user's authentication has expired. They need to reconnect.",
    ).to_dict()


def not_found(resource: str = "Resource") -> dict[str, Any]:
    """Resource not found error."""
    return ToolResponse(
        success=False,
        error=f"{resource} not found",
        message=f"The requested {resource.lower()} could not be found.",
        _ai_hint=f"The {resource.lower()} doesn't exist or the user doesn't have access.",
    ).to_dict()


def invalid_format(field: str, expected: str) -> dict[str, Any]:
    """Invalid format error."""
    return ToolResponse(
        success=False,
        error=f"Invalid {field} format",
        message=f"Expected {expected}.",
        _ai_hint=f"The {field} parameter has an invalid format. Expected: {expected}",
    ).to_dict()


def api_error(status_code: int) -> dict[str, Any]:
    """Generic API error."""
    return ToolResponse(
        success=False,
        error=f"API error: {status_code}",
        _ai_hint="An error occurred while communicating with the Dock AI API. The user may want to try again.",
    ).to_dict()


def rate_limited() -> dict[str, Any]:
    """Rate limit exceeded error."""
    return ToolResponse(
        success=False,
        error="Rate limit exceeded",
        message="Too many requests. Please try again later.",
        _ai_hint="The user has made too many requests. Ask them to wait a moment before trying again.",
    ).to_dict()


def sensitive_data_blocked(fields: list[str]) -> dict[str, Any]:
    """Sensitive data detected in parameters."""
    return ToolResponse(
        success=False,
        error="Sensitive data detected",
        message=f"Parameters contain sensitive field names that are not allowed: {', '.join(fields)}. "
        "For security, Dock AI blocks transmission of passwords, credit cards, SSN, API keys, etc.",
        _ai_hint="SECURITY: The parameters contained sensitive field names. Never ask users for or transmit passwords, credit cards, SSN, or API keys through Dock AI.",
    ).to_dict()


def action_success(action: str, result: dict[str, Any], business_name: str | None = None) -> dict[str, Any]:
    """Successful action execution."""
    hint = f"Action '{action}' executed successfully."
    if business_name:
        hint = f"Action '{action}' executed successfully for {business_name}."
    hint += " Present the result to the user."

    return ToolResponse(
        success=True,
        result=result,
        _ai_hint=hint,
    ).to_dict()


def pending_confirmation(email: str | None = None) -> dict[str, Any]:
    """Action requires confirmation."""
    return {
        "success": True,
        "status": "pending_confirmation",
        "message": "This action requires your confirmation. A confirmation email has been sent.",
        "_ai_hint": "IMPORTANT: A confirmation email has been sent to the user. "
        "They must click the link in the email to confirm this action before it executes. "
        "Ask them to check their email (including spam folder) and click the confirmation link. "
        "The action will NOT execute until they confirm via email.",
    }
