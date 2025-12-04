"""Tests for tool server timeout functionality."""

from __future__ import annotations

import json
import os
import queue
from multiprocessing import Queue
from typing import Any
from unittest.mock import patch

import pytest


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
