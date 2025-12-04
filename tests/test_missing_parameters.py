"""Tests for missing required parameter handling."""

from __future__ import annotations

import pytest

from strix.tools.argument_parser import validate_required_args
from strix.tools.validation import generate_missing_param_error


class TestGenerateMissingParamError:
    """Test cases for generate_missing_param_error function."""

    def test_generates_error_for_single_missing_param(self) -> None:
        """Test generating error for a single missing parameter."""
        result = generate_missing_param_error("test_tool", ["action"])

        assert "error" in result
        assert "Missing required parameter(s): ['action']" in result["error"]
        assert "hint" in result
        assert "test_tool" in result["hint"]
        assert result["tool_name"] == "test_tool"

    def test_generates_error_for_multiple_missing_params(self) -> None:
        """Test generating error for multiple missing parameters."""
        result = generate_missing_param_error("test_tool", ["action", "domain"])

        assert "error" in result
        assert "action" in result["error"]
        assert "domain" in result["error"]

    def test_includes_provided_params_when_given(self) -> None:
        """Test that provided parameters are included in error."""
        result = generate_missing_param_error(
            "test_tool",
            ["action"],
            {"domain": "example.com", "timeout": 5}
        )

        assert "provided_params" in result
        assert "domain" in result["provided_params"]
        assert "timeout" in result["provided_params"]


class TestValidateRequiredArgs:
    """Test cases for validate_required_args function."""

    def test_validates_function_with_no_missing_args(self) -> None:
        """Test function with all required args provided."""
        def test_func(action: str, domain: str) -> None:
            pass

        is_valid, missing = validate_required_args(
            test_func,
            {"action": "enumerate", "domain": "example.com"}
        )

        assert is_valid is True
        assert missing == []

    def test_detects_missing_required_arg(self) -> None:
        """Test detection of missing required argument."""
        def test_func(action: str, domain: str) -> None:
            pass

        is_valid, missing = validate_required_args(
            test_func,
            {"domain": "example.com"}
        )

        assert is_valid is False
        assert "action" in missing

    def test_ignores_optional_args(self) -> None:
        """Test that optional args with defaults are not considered missing."""
        def test_func(action: str, domain: str, timeout: int = 5) -> None:
            pass

        is_valid, missing = validate_required_args(
            test_func,
            {"action": "enumerate", "domain": "example.com"}
        )

        assert is_valid is True
        assert missing == []

    def test_ignores_kwargs_parameter(self) -> None:
        """Test that **kwargs parameter is ignored."""
        def test_func(action: str, **kwargs: str) -> None:
            pass

        is_valid, missing = validate_required_args(
            test_func,
            {"action": "enumerate"}
        )

        assert is_valid is True
        assert missing == []

    def test_ignores_agent_state_parameter(self) -> None:
        """Test that agent_state parameter is ignored."""
        def test_func(action: str, agent_state: object | None = None) -> None:
            pass

        is_valid, missing = validate_required_args(
            test_func,
            {"action": "enumerate"}
        )

        assert is_valid is True
        assert missing == []

    def test_detects_multiple_missing_args(self) -> None:
        """Test detection of multiple missing arguments."""
        def test_func(action: str, domain: str, endpoint: str) -> None:
            pass

        is_valid, missing = validate_required_args(
            test_func,
            {"domain": "example.com"}
        )

        assert is_valid is False
        assert "action" in missing
        assert "endpoint" in missing
        assert len(missing) == 2


class TestToolExecutorMissingParams:
    """Integration tests with tool executor."""

    @pytest.mark.asyncio
    async def test_executor_returns_error_for_missing_action(self) -> None:
        """Test that executor returns helpful error for missing action parameter."""
        from strix.tools.executor import _execute_tool_locally

        result = await _execute_tool_locally("subdomain_enum", None, domain="example.com")

        assert isinstance(result, dict)
        assert "error" in result
        assert "action" in result["error"]
        assert "hint" in result
        assert result["tool_name"] == "subdomain_enum"

    @pytest.mark.asyncio
    async def test_executor_returns_error_for_missing_domain(self) -> None:
        """Test that executor returns helpful error for missing domain parameter."""
        from strix.tools.executor import _execute_tool_locally

        result = await _execute_tool_locally("subdomain_enum", None, action="enumerate")

        assert isinstance(result, dict)
        assert "error" in result
        assert "domain" in result["error"]

    @pytest.mark.asyncio
    async def test_executor_works_with_all_params_provided(self) -> None:
        """Test that executor works normally when all params are provided."""
        from strix.tools.executor import _execute_tool_locally

        result = await _execute_tool_locally(
            "subdomain_enum",
            None,
            action="enumerate",
            domain="example.com"
        )

        # Should not be an error dict with "error" key from missing params
        # (it may still have errors from execution, but those are different)
        if isinstance(result, dict) and "error" in result:
            # If there's an error, it shouldn't be about missing params
            assert "Missing required parameter" not in result.get("error", "")

    @pytest.mark.asyncio
    async def test_execute_tool_with_validation_catches_missing_params(self) -> None:
        """Test that execute_tool_with_validation also handles missing params."""
        from unittest.mock import patch

        from strix.tools.executor import execute_tool_with_validation

        # Mock execute_tool to return our test result directly
        async def mock_execute_tool(tool_name, agent_state, **kwargs):
            from strix.tools.executor import _execute_tool_locally
            return await _execute_tool_locally(tool_name, agent_state, **kwargs)

        with patch("strix.tools.executor.execute_tool", side_effect=mock_execute_tool):
            result = await execute_tool_with_validation(
                "subdomain_enum",
                None,
                domain="example.com"
            )

            # Should return an error dict, not raise an exception
            assert isinstance(result, dict)
            assert "error" in result
            assert "action" in str(result["error"]).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
