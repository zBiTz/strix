"""Parameter validation utilities for Strix tools.

This module provides helper functions for validating tool parameters,
detecting unknown/invented parameters, and generating helpful error messages
with usage examples to prevent agents from getting stuck.
"""

from typing import Any


def validate_unknown_params(
    kwargs: dict[str, Any],
    valid_params: set[str],
    tool_name: str,
) -> dict[str, Any] | None:
    """Check for unknown parameters and return error with valid parameters list.

    Args:
        kwargs: Dictionary of unknown parameters captured by **kwargs
        valid_params: Set of valid parameter names for this tool
        tool_name: Name of the tool being validated

    Returns:
        Error dict with hint if unknown params found, None otherwise
    """
    if not kwargs:
        return None

    unknown = list(kwargs.keys())
    return {
        "error": f"Unknown parameter(s): {unknown}. Valid parameters are: {sorted(valid_params)}",
        "hint": "Did you mean one of the valid parameters listed above?",
        "tool_name": tool_name,
    }


def validate_action_param(
    action: str,
    valid_actions: list[str],
    tool_name: str,
) -> dict[str, Any] | None:
    """Validate action parameter against allowed values.

    Args:
        action: The action parameter value to validate
        valid_actions: List of valid action values
        tool_name: Name of the tool being validated

    Returns:
        Error dict with valid actions if invalid, None otherwise
    """
    if action not in valid_actions:
        return {
            "error": f"Invalid action: '{action}'. Must be one of: {valid_actions}",
            "tool_name": tool_name,
        }
    return None


def validate_required_param(
    param_value: Any,
    param_name: str,
    action: str,
    tool_name: str,
) -> dict[str, Any] | None:
    """Check if a required parameter is present.

    Args:
        param_value: The parameter value to check
        param_name: Name of the required parameter
        action: Current action being performed
        tool_name: Name of the tool being validated

    Returns:
        Error dict if parameter is missing, None otherwise
    """
    if param_value is None or (isinstance(param_value, str) and not param_value):
        return {
            "error": f"Missing required parameter: '{param_name}' for action '{action}'",
            "tool_name": tool_name,
        }
    return None


def generate_usage_hint(
    tool_name: str,
    action: str,
    example_params: dict[str, Any],
) -> dict[str, Any]:
    """Generate a usage example for the tool.

    Args:
        tool_name: Name of the tool
        action: The action being demonstrated
        example_params: Example parameters for this action

    Returns:
        Dict with usage example
    """
    return {
        "usage_example": {
            "action": action,
            **example_params,
        },
    }


def generate_workflow_hint(
    tool_name: str,
    workflow_steps: list[str],
    example_usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate workflow guidance for tools requiring pre-fetched data.

    Args:
        tool_name: Name of the tool
        workflow_steps: List of workflow steps to perform
        example_usage: Optional example usage dict

    Returns:
        Dict with workflow guidance
    """
    result: dict[str, Any] = {
        "workflow_hint": f"This tool requires pre-fetched data. Follow the correct workflow:",
        "correct_workflow": workflow_steps,
        "tool_name": tool_name,
    }
    if example_usage:
        result["usage_example"] = example_usage
    return result


def detect_url_in_unknown_params(unknown_params: list[str]) -> bool:
    """Detect if unknown parameters contain URL-like parameter names.

    Args:
        unknown_params: List of unknown parameter names

    Returns:
        True if URL-like parameters detected, False otherwise
    """
    url_keywords = {"url", "target_url", "target", "uri", "endpoint"}
    return any(param.lower() in url_keywords for param in unknown_params)


def add_workflow_hint_for_url_params(
    error_dict: dict[str, Any],
    workflow_steps: list[str],
) -> dict[str, Any]:
    """Add workflow hint to error when URL parameters are detected.

    Args:
        error_dict: The error dictionary to enhance
        workflow_steps: Steps for the correct workflow

    Returns:
        Enhanced error dictionary with workflow hint
    """
    error_dict["workflow_hint"] = (
        "This tool analyzes pre-fetched data, not URLs directly. "
        "First fetch the URL data, then pass it to this tool."
    )
    error_dict["correct_workflow"] = workflow_steps
    return error_dict
