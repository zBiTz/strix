"""Tests for tool parameter validation functionality."""

from __future__ import annotations

import pytest

from strix.tools.validation import (
    add_workflow_hint_for_url_params,
    detect_url_in_unknown_params,
    generate_usage_hint,
    generate_workflow_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


class TestValidateUnknownParams:
    """Test cases for validate_unknown_params function."""

    def test_no_unknown_params_returns_none(self) -> None:
        """Test that no unknown params returns None."""
        result = validate_unknown_params({}, {"action", "domain"}, "test_tool")
        assert result is None

    def test_unknown_params_returns_error(self) -> None:
        """Test that unknown params returns error dict."""
        kwargs = {"target_url": "example.com", "query": "test"}
        result = validate_unknown_params(kwargs, {"action", "domain"}, "test_tool")

        assert result is not None
        assert "error" in result
        assert "Unknown parameter(s)" in result["error"]
        assert "target_url" in result["error"]
        assert "query" in result["error"]
        assert "hint" in result
        assert result["tool_name"] == "test_tool"

    def test_lists_valid_parameters(self) -> None:
        """Test that error message lists valid parameters."""
        kwargs = {"bad_param": "value"}
        valid_params = {"action", "domain", "subdomain"}
        result = validate_unknown_params(kwargs, valid_params, "test_tool")

        assert result is not None
        assert "Valid parameters are:" in result["error"]
        # Check that sorted valid params are in the error
        assert "'action'" in result["error"]
        assert "'domain'" in result["error"]
        assert "'subdomain'" in result["error"]


class TestValidateActionParam:
    """Test cases for validate_action_param function."""

    def test_valid_action_returns_none(self) -> None:
        """Test that valid action returns None."""
        result = validate_action_param("enumerate", ["enumerate", "check"], "test_tool")
        assert result is None

    def test_invalid_action_returns_error(self) -> None:
        """Test that invalid action returns error dict."""
        result = validate_action_param("invalid", ["enumerate", "check"], "test_tool")

        assert result is not None
        assert "error" in result
        assert "Invalid action: 'invalid'" in result["error"]
        assert "['enumerate', 'check']" in result["error"]
        assert result["tool_name"] == "test_tool"


class TestValidateRequiredParam:
    """Test cases for validate_required_param function."""

    def test_present_param_returns_none(self) -> None:
        """Test that present param returns None."""
        result = validate_required_param("example.com", "domain", "enumerate", "test_tool")
        assert result is None

    def test_none_param_returns_error(self) -> None:
        """Test that None param returns error."""
        result = validate_required_param(None, "domain", "enumerate", "test_tool")

        assert result is not None
        assert "error" in result
        assert "Missing required parameter: 'domain'" in result["error"]
        assert "enumerate" in result["error"]

    def test_empty_string_returns_error(self) -> None:
        """Test that empty string param returns error."""
        result = validate_required_param("", "domain", "enumerate", "test_tool")

        assert result is not None
        assert "error" in result
        assert "Missing required parameter: 'domain'" in result["error"]


class TestGenerateUsageHint:
    """Test cases for generate_usage_hint function."""

    def test_generates_usage_example(self) -> None:
        """Test that usage hint is generated correctly."""
        result = generate_usage_hint("test_tool", "enumerate", {"domain": "example.com"})

        assert "usage_example" in result
        assert result["usage_example"]["action"] == "enumerate"
        assert result["usage_example"]["domain"] == "example.com"


class TestGenerateWorkflowHint:
    """Test cases for generate_workflow_hint function."""

    def test_generates_workflow_with_steps(self) -> None:
        """Test that workflow hint includes steps."""
        steps = [
            "1. Fetch the URL first",
            "2. Extract the data",
            "3. Call the tool with data",
        ]
        result = generate_workflow_hint("test_tool", steps)

        assert "workflow_hint" in result
        assert "correct_workflow" in result
        assert result["correct_workflow"] == steps
        assert result["tool_name"] == "test_tool"

    def test_generates_workflow_with_example(self) -> None:
        """Test that workflow hint can include usage example."""
        steps = ["1. Step one"]
        example = {"action": "test", "param": "value"}
        result = generate_workflow_hint("test_tool", steps, example)

        assert "usage_example" in result
        assert result["usage_example"] == example


class TestDetectUrlInUnknownParams:
    """Test cases for detect_url_in_unknown_params function."""

    def test_detects_url_keyword(self) -> None:
        """Test detection of 'url' in unknown params."""
        assert detect_url_in_unknown_params(["url"]) is True

    def test_detects_target_url_keyword(self) -> None:
        """Test detection of 'target_url' in unknown params."""
        assert detect_url_in_unknown_params(["target_url"]) is True

    def test_detects_target_keyword(self) -> None:
        """Test detection of 'target' in unknown params."""
        assert detect_url_in_unknown_params(["target"]) is True

    def test_detects_uri_keyword(self) -> None:
        """Test detection of 'uri' in unknown params."""
        assert detect_url_in_unknown_params(["uri"]) is True

    def test_detects_endpoint_keyword(self) -> None:
        """Test detection of 'endpoint' in unknown params."""
        assert detect_url_in_unknown_params(["endpoint"]) is True

    def test_case_insensitive_detection(self) -> None:
        """Test that detection is case-insensitive."""
        assert detect_url_in_unknown_params(["URL"]) is True
        assert detect_url_in_unknown_params(["Target_URL"]) is True

    def test_no_url_keywords_returns_false(self) -> None:
        """Test that non-URL params return False."""
        assert detect_url_in_unknown_params(["domain", "action"]) is False

    def test_empty_list_returns_false(self) -> None:
        """Test that empty list returns False."""
        assert detect_url_in_unknown_params([]) is False


class TestAddWorkflowHintForUrlParams:
    """Test cases for add_workflow_hint_for_url_params function."""

    def test_adds_workflow_hint_to_error(self) -> None:
        """Test that workflow hint is added to error dict."""
        error_dict = {"error": "Unknown parameter"}
        steps = ["1. Fetch first", "2. Analyze second"]
        result = add_workflow_hint_for_url_params(error_dict, steps)

        assert "workflow_hint" in result
        assert "This tool analyzes pre-fetched data" in result["workflow_hint"]
        assert "correct_workflow" in result
        assert result["correct_workflow"] == steps

    def test_preserves_original_error(self) -> None:
        """Test that original error is preserved."""
        error_dict = {"error": "Unknown parameter", "hint": "Try this"}
        steps = ["1. Step"]
        result = add_workflow_hint_for_url_params(error_dict, steps)

        assert result["error"] == "Unknown parameter"
        assert result["hint"] == "Try this"


# Integration tests with actual tools
class TestToolIntegration:
    """Integration tests with actual tool functions."""

    def test_subdomain_enum_unknown_param(self) -> None:
        """Test subdomain_enum rejects unknown parameters."""
        from strix.tools.subdomain_enum.subdomain_enum import subdomain_enum

        result = subdomain_enum(
            action="enumerate",
            domain="example.com",
            target_url="https://example.com",  # type: ignore[call-arg]
        )

        assert "error" in result
        assert "Unknown parameter(s)" in result["error"]
        assert "target_url" in result["error"]
        assert "hint" in result or "usage_example" in result

    def test_subdomain_enum_invalid_action(self) -> None:
        """Test subdomain_enum rejects invalid action."""
        from strix.tools.subdomain_enum.subdomain_enum import subdomain_enum

        result = subdomain_enum(
            action="invalid_action",  # type: ignore[arg-type]
            domain="example.com",
        )

        assert "error" in result
        assert "Invalid action" in result["error"]
        assert "invalid_action" in result["error"]

    def test_subdomain_enum_missing_domain(self) -> None:
        """Test subdomain_enum requires domain parameter."""
        from strix.tools.subdomain_enum.subdomain_enum import subdomain_enum

        result = subdomain_enum(
            action="enumerate",
            domain="",
        )

        assert "error" in result
        assert "Missing required parameter: 'domain'" in result["error"]

    def test_header_analyzer_url_param_workflow_hint(self) -> None:
        """Test header_analyzer provides workflow hint for URL param."""
        from strix.tools.header_analyzer.header_analyzer import header_analyzer

        result = header_analyzer(
            action="analyze",
            target_url="https://example.com",  # type: ignore[call-arg]
        )

        assert "error" in result
        assert "Unknown parameter(s)" in result["error"]
        assert "workflow_hint" in result
        assert "pre-fetched data" in result["workflow_hint"]
        assert "correct_workflow" in result
        assert any("send_request" in step for step in result["correct_workflow"])

    def test_wayback_fetcher_query_param_hint(self) -> None:
        """Test wayback_fetcher detects 'query' parameter mistake."""
        from strix.tools.wayback_fetcher.wayback_fetcher import wayback_fetcher

        result = wayback_fetcher(
            action="fetch",
            query="example.com",  # type: ignore[call-arg]
        )

        assert "error" in result
        assert "Unknown parameter(s)" in result["error"]
        assert "query" in result["error"]
        assert "hint" in result
        assert "domain" in result["hint"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
