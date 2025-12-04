"""Tests for HTTP client timeout in sandbox tool execution."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


class TestExecutorHTTPTimeout:
    """Test cases for HTTP timeout configuration and handling in executor."""

    def test_sandbox_http_timeout_default_value(self) -> None:
        """Test that SANDBOX_HTTP_TIMEOUT has the correct default value."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("STRIX_TOOL_TIMEOUT", None)
            # Reimport to get fresh value
            import importlib

            from strix.tools import executor

            importlib.reload(executor)
            # Default should be 300 + 30 = 330 seconds
            assert executor.SANDBOX_HTTP_TIMEOUT == 330

    def test_sandbox_http_timeout_custom_value(self) -> None:
        """Test that SANDBOX_HTTP_TIMEOUT respects STRIX_TOOL_TIMEOUT environment variable."""
        with patch.dict(os.environ, {"STRIX_TOOL_TIMEOUT": "600"}, clear=False):
            # Reimport to get fresh value
            import importlib

            from strix.tools import executor

            importlib.reload(executor)
            # Should be 600 + 30 = 630 seconds
            assert executor.SANDBOX_HTTP_TIMEOUT == 630

    @pytest.mark.asyncio
    async def test_timeout_exception_is_caught_and_converted(self) -> None:
        """Test that httpx.TimeoutException is caught and converted to RuntimeError."""
        import strix.tools.executor as executor_module

        # Create mock agent state
        mock_agent_state = MagicMock()
        mock_agent_state.sandbox_id = "test-sandbox-id"
        mock_agent_state.sandbox_token = "test-token"  # noqa: S105
        mock_agent_state.sandbox_info = {"tool_server_port": 8000}
        mock_agent_state.agent_id = "test-agent"

        # Mock the runtime
        mock_runtime = MagicMock()
        mock_runtime.get_sandbox_url = AsyncMock(return_value="http://localhost:8000")

        # Patch get_runtime in the executor module's namespace
        with (
            patch.object(executor_module, "get_runtime", return_value=mock_runtime, create=True),
            patch("httpx.AsyncClient") as mock_client_class,
        ):
            # Setup mock to raise TimeoutException
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("Request timeout"))
            mock_client_class.return_value = mock_client

            # Execute and expect RuntimeError with timeout message
            with pytest.raises(RuntimeError) as exc_info:
                await executor_module._execute_tool_in_sandbox(
                    "test_tool", mock_agent_state, param1="value1"
                )

            # Verify the error message
            error_msg = str(exc_info.value)
            assert "timed out" in error_msg.lower()
            assert "seconds" in error_msg.lower()
            assert "tool server may be overloaded or unresponsive" in error_msg.lower()

    @pytest.mark.asyncio
    async def test_timeout_value_is_passed_to_httpx_client(self) -> None:
        """Test that the timeout value is correctly passed to httpx client."""
        import strix.tools.executor as executor_module

        # Create mock agent state
        mock_agent_state = MagicMock()
        mock_agent_state.sandbox_id = "test-sandbox-id"
        mock_agent_state.sandbox_token = "test-token"  # noqa: S105
        mock_agent_state.sandbox_info = {"tool_server_port": 8000}
        mock_agent_state.agent_id = "test-agent"

        # Mock the runtime
        mock_runtime = MagicMock()
        mock_runtime.get_sandbox_url = AsyncMock(return_value="http://localhost:8000")

        # Patch get_runtime in the executor module's namespace
        with (
            patch.object(executor_module, "get_runtime", return_value=mock_runtime, create=True),
            patch("httpx.AsyncClient") as mock_client_class,
        ):
            # Setup successful response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"result": "success"}

            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client

            # Execute tool
            await executor_module._execute_tool_in_sandbox(
                "test_tool", mock_agent_state, param1="value1"
            )

            # Verify that timeout was passed to post call
            mock_client.post.assert_called_once()
            call_kwargs = mock_client.post.call_args.kwargs
            assert "timeout" in call_kwargs
            assert call_kwargs["timeout"] == executor_module.SANDBOX_HTTP_TIMEOUT
            # Verify timeout is not None
            assert call_kwargs["timeout"] is not None

    @pytest.mark.asyncio
    async def test_timeout_exception_includes_timeout_value_in_message(self) -> None:
        """Test that the timeout error message includes the actual timeout value."""
        import strix.tools.executor as executor_module

        # Create mock agent state
        mock_agent_state = MagicMock()
        mock_agent_state.sandbox_id = "test-sandbox-id"
        mock_agent_state.sandbox_token = "test-token"  # noqa: S105
        mock_agent_state.sandbox_info = {"tool_server_port": 8000}
        mock_agent_state.agent_id = "test-agent"

        # Mock the runtime
        mock_runtime = MagicMock()
        mock_runtime.get_sandbox_url = AsyncMock(return_value="http://localhost:8000")

        # Patch get_runtime in the executor module's namespace
        with (
            patch.object(executor_module, "get_runtime", return_value=mock_runtime, create=True),
            patch("httpx.AsyncClient") as mock_client_class,
        ):
            # Setup mock to raise TimeoutException
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("Request timeout"))
            mock_client_class.return_value = mock_client

            # Execute and expect RuntimeError
            with pytest.raises(RuntimeError) as exc_info:
                await executor_module._execute_tool_in_sandbox(
                    "test_tool", mock_agent_state, param1="value1"
                )

            # Verify the error message includes the timeout value
            error_msg = str(exc_info.value)
            assert str(executor_module.SANDBOX_HTTP_TIMEOUT) in error_msg

    @pytest.mark.asyncio
    async def test_other_exceptions_are_not_affected(self) -> None:
        """Test that other HTTP exceptions are still handled correctly."""
        import strix.tools.executor as executor_module

        # Create mock agent state
        mock_agent_state = MagicMock()
        mock_agent_state.sandbox_id = "test-sandbox-id"
        mock_agent_state.sandbox_token = "test-token"  # noqa: S105
        mock_agent_state.sandbox_info = {"tool_server_port": 8000}
        mock_agent_state.agent_id = "test-agent"

        # Mock the runtime
        mock_runtime = MagicMock()
        mock_runtime.get_sandbox_url = AsyncMock(return_value="http://localhost:8000")

        # Patch get_runtime in the executor module's namespace
        with (
            patch.object(executor_module, "get_runtime", return_value=mock_runtime, create=True),
            patch("httpx.AsyncClient") as mock_client_class,
        ):
            # Setup mock to raise HTTPStatusError (401)
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_http_error = httpx.HTTPStatusError(
                "Auth failed", request=MagicMock(), response=mock_response
            )

            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.post = AsyncMock(side_effect=mock_http_error)
            mock_client_class.return_value = mock_client

            # Execute and expect RuntimeError with auth message
            with pytest.raises(RuntimeError) as exc_info:
                await executor_module._execute_tool_in_sandbox(
                    "test_tool", mock_agent_state, param1="value1"
                )

            # Verify it's the auth error, not timeout error
            error_msg = str(exc_info.value)
            assert "authentication" in error_msg.lower()
            assert "invalid or missing sandbox token" in error_msg.lower()
            # Should NOT contain timeout message
            assert "timed out" not in error_msg.lower()


class TestTimeoutIntegration:
    """Integration tests for timeout behavior."""

    def test_timeout_calculation_with_various_environment_values(self) -> None:
        """Test that timeout calculation works correctly with various env values."""
        test_cases = [
            ("100", 130),  # 100 + 30
            ("300", 330),  # 300 + 30 (default)
            ("600", 630),  # 600 + 30
            ("3600", 3630),  # 3600 + 30 (1 hour)
        ]

        for env_value, expected_timeout in test_cases:
            with patch.dict(os.environ, {"STRIX_TOOL_TIMEOUT": env_value}, clear=False):
                import importlib

                from strix.tools import executor

                importlib.reload(executor)
                assert expected_timeout == executor.SANDBOX_HTTP_TIMEOUT

    def test_timeout_buffer_is_30_seconds(self) -> None:
        """Test that the timeout buffer is exactly 30 seconds."""
        with patch.dict(os.environ, {"STRIX_TOOL_TIMEOUT": "500"}, clear=False):
            import importlib

            from strix.tools import executor

            importlib.reload(executor)
            # Verify buffer is 30 seconds (530 - 500 = 30)
            assert executor.SANDBOX_HTTP_TIMEOUT == 530
            buffer = executor.SANDBOX_HTTP_TIMEOUT - 500
            assert buffer == 30
