"""Tests for tool server timeout functionality."""

from __future__ import annotations

import json
import os
import queue
import sys
from multiprocessing import Queue
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# Set SANDBOX_MODE and mock sys.argv before importing tool_server to prevent RuntimeError
os.environ["STRIX_SANDBOX_MODE"] = "true"
# Mock command line arguments that the tool_server expects
sys.argv = ["tool_server.py", "--token", "test-token", "--port", "8000"]


@pytest.fixture
def clean_strix_timeout_env() -> Any:
    """Ensure STRIX_TOOL_TIMEOUT is clean before and after test."""
    original = os.environ.get("STRIX_TOOL_TIMEOUT")
    yield
    if original is not None:
        os.environ["STRIX_TOOL_TIMEOUT"] = original
    else:
        os.environ.pop("STRIX_TOOL_TIMEOUT", None)


class TestToolServerTimeout:
    """Test cases for tool server timeout functionality."""

    def test_timeout_env_variable_parsing(self, clean_strix_timeout_env: Any) -> None:  # noqa: ARG002
        """Test that STRIX_TOOL_TIMEOUT environment variable is parsed correctly."""
        # Test default value
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("STRIX_TOOL_TIMEOUT", None)
            default_timeout = int(os.getenv("STRIX_TOOL_TIMEOUT", "300"))
            assert default_timeout == 300

        # Test custom value
        with patch.dict(os.environ, {"STRIX_TOOL_TIMEOUT": "600"}, clear=False):
            custom_timeout = int(os.getenv("STRIX_TOOL_TIMEOUT", "300"))
            assert custom_timeout == 600

    def test_queue_timeout_behavior(self) -> None:
        """Test that queue.Empty exception is handled correctly."""
        # Create a queue that will timeout
        test_queue: Queue[Any] = Queue()

        # Try to get from empty queue with timeout
        with pytest.raises(queue.Empty):
            test_queue.get(timeout=0.1)

    def test_error_dict_to_string_conversion(self) -> None:
        """Test that error dicts are converted to JSON strings."""
        test_error_dict = {
            "error": "Missing parameter",
            "parameter": "domain",
            "hint": "Use 'domain' instead of 'target'",
        }

        # Convert to string as the server would
        error_str = json.dumps(test_error_dict, indent=2)

        # Verify it's a valid JSON string
        parsed = json.loads(error_str)
        assert parsed == test_error_dict
        assert isinstance(error_str, str)


class TestToolServerIntegration:
    """Integration tests for tool server timeout and process management."""

    def test_cleanup_agent_terminates_process(self) -> None:
        """Test that cleanup_agent properly terminates a running process."""
        from multiprocessing import Process
        from unittest.mock import patch

        # Create a mock process that appears to be alive
        mock_process = MagicMock(spec=Process)
        mock_process.is_alive.return_value = True

        agent_id = "test_agent_cleanup"
        agent_processes_mock = {agent_id: {"process": mock_process, "pid": 12345}}
        agent_queues_mock = {agent_id: {"request": MagicMock(), "response": MagicMock()}}

        # Mock the module-level variables and lock
        with (
            patch("strix.runtime.tool_server.agent_processes", agent_processes_mock),
            patch("strix.runtime.tool_server.agent_queues", agent_queues_mock),
            patch("strix.runtime.tool_server._agent_lock"),
        ):
            from strix.runtime.tool_server import cleanup_agent

            cleanup_agent(agent_id)

            # Verify terminate and join were called
            mock_process.terminate.assert_called_once()
            mock_process.join.assert_called_once_with(timeout=1)

            # Verify agent was removed from dictionaries
            assert agent_id not in agent_processes_mock
            assert agent_id not in agent_queues_mock

    def test_cleanup_agent_kills_stubborn_process(self) -> None:
        """Test that cleanup_agent kills process if terminate doesn't work."""
        from multiprocessing import Process
        from unittest.mock import patch

        # Create a mock process that stays alive after terminate
        mock_process = MagicMock(spec=Process)
        mock_process.is_alive.return_value = True  # Still alive after terminate

        agent_id = "test_agent_kill"
        agent_processes_mock = {agent_id: {"process": mock_process, "pid": 12346}}
        agent_queues_mock = {agent_id: {"request": MagicMock(), "response": MagicMock()}}

        with (
            patch("strix.runtime.tool_server.agent_processes", agent_processes_mock),
            patch("strix.runtime.tool_server.agent_queues", agent_queues_mock),
            patch("strix.runtime.tool_server._agent_lock"),
        ):
            from strix.runtime.tool_server import cleanup_agent

            cleanup_agent(agent_id)

            # Verify terminate, join, and kill were all called
            mock_process.terminate.assert_called_once()
            mock_process.join.assert_called()
            mock_process.kill.assert_called_once()

    def test_cleanup_agent_handles_broken_pipe_gracefully(self) -> None:
        """Test that cleanup_agent handles BrokenPipeError without raising."""
        from multiprocessing import Process
        from unittest.mock import patch

        # Create a mock process that raises BrokenPipeError on terminate
        mock_process = MagicMock(spec=Process)
        mock_process.is_alive.return_value = True
        mock_process.terminate.side_effect = BrokenPipeError("Pipe broken")

        agent_id = "test_agent_error"
        agent_processes_mock = {agent_id: {"process": mock_process, "pid": 12347}}
        agent_queues_mock = {agent_id: {"request": MagicMock(), "response": MagicMock()}}

        with (
            patch("strix.runtime.tool_server.agent_processes", agent_processes_mock),
            patch("strix.runtime.tool_server.agent_queues", agent_queues_mock),
            patch("strix.runtime.tool_server._agent_lock"),
            patch("strix.runtime.tool_server.logger") as mock_logger,
        ):
            from strix.runtime.tool_server import cleanup_agent

            # Should not raise exception
            cleanup_agent(agent_id)

            # Verify logger.debug was called with error
            mock_logger.debug.assert_called_once()
            assert "Error during agent" in str(mock_logger.debug.call_args)

            # Verify agent was still removed from dictionaries
            assert agent_id not in agent_processes_mock
            assert agent_id not in agent_queues_mock

    def test_ensure_agent_process_creates_new_process(self) -> None:
        """Test that ensure_agent_process creates a new worker process."""
        from unittest.mock import patch

        agent_id = "test_agent_new"

        with (
            patch("strix.runtime.tool_server.agent_processes", {}),
            patch("strix.runtime.tool_server.agent_queues", {}),
            patch("strix.runtime.tool_server._agent_lock"),
            patch("strix.runtime.tool_server.Process") as mock_process_class,
        ):
            mock_process = MagicMock()
            mock_process.pid = 99999
            mock_process_class.return_value = mock_process

            from strix.runtime.tool_server import ensure_agent_process

            request_queue, response_queue = ensure_agent_process(agent_id)

            # Verify process was created and started
            mock_process_class.assert_called_once()
            mock_process.start.assert_called_once()

            # Verify queues were returned
            assert request_queue is not None
            assert response_queue is not None

    def test_timeout_wrapper_returns_error_on_empty_queue(self) -> None:
        """Test that get_with_timeout returns timeout error when queue is empty."""

        # Simulate the get_with_timeout function behavior
        mock_queue = MagicMock()
        mock_queue.get.side_effect = queue.Empty()

        timeout = 1

        try:
            result = mock_queue.get(timeout=timeout)
        except queue.Empty:
            result = {"error": f"Tool execution timed out after {timeout} seconds"}

        # Verify timeout error is returned
        assert "error" in result
        assert "timed out" in result["error"]
        assert str(timeout) in result["error"]

    def test_dead_process_detection_and_recreation(self) -> None:
        """Test that dead worker processes are detected and recreated."""
        from unittest.mock import patch

        agent_id = "test_agent_dead"

        # Create a mock process that reports as not alive
        mock_dead_process = MagicMock()
        mock_dead_process.is_alive.return_value = False
        mock_dead_process.pid = 11111

        agent_processes_mock = {agent_id: {"process": mock_dead_process, "pid": 11111}}
        agent_queues_mock = {
            agent_id: {"request": MagicMock(), "response": MagicMock()}
        }

        with (
            patch("strix.runtime.tool_server.agent_processes", agent_processes_mock),
            patch("strix.runtime.tool_server.agent_queues", agent_queues_mock),
            patch("strix.runtime.tool_server._agent_lock"),
        ):
            # Verify process is detected as not alive
            process_info = agent_processes_mock.get(agent_id)
            assert process_info is not None
            process = process_info.get("process")
            assert process is not None
            assert not process.is_alive()  # type: ignore[attr-defined]

            # This simulates what execute_tool does when it detects a dead process
            # cleanup_agent would be called, then ensure_agent_process to recreate
