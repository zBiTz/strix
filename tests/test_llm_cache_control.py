"""Tests for LLM cache control functionality."""

from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.llm.config import LLMConfig
from strix.llm.llm import LLM


@pytest.fixture
def llm_config() -> LLMConfig:
    """Create a mock LLM config."""
    config = MagicMock(spec=LLMConfig)
    config.model_name = "anthropic/claude-3-sonnet"
    config.enable_prompt_caching = True
    config.timeout = 60
    config.prompt_modules = []
    return config


@pytest.fixture
def llm(llm_config: LLMConfig) -> LLM:
    """Create an LLM instance without loading prompts."""
    return LLM(config=llm_config, agent_name=None, agent_id=None)


class TestAddCacheControlToContent:
    """Tests for the _add_cache_control_to_content method."""

    def test_string_content_converts_to_text_block_with_cache_control(self, llm: LLM) -> None:
        """Test that string content is converted to a text block with cache_control."""
        content = "Hello, world!"
        result = llm._add_cache_control_to_content(content)

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["type"] == "text"
        assert result[0]["text"] == "Hello, world!"
        assert result[0]["cache_control"] == {"type": "ephemeral"}

    def test_list_with_single_text_block_adds_cache_control(self, llm: LLM) -> None:
        """Test that cache_control is added to a single text block."""
        content = [{"type": "text", "text": "Hello, world!"}]
        result = llm._add_cache_control_to_content(content)

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["type"] == "text"
        assert result[0]["text"] == "Hello, world!"
        assert result[0]["cache_control"] == {"type": "ephemeral"}

    def test_list_with_text_block_at_end_adds_cache_control(self, llm: LLM) -> None:
        """Test that cache_control is added to the last text block when it's at the end."""
        content = [
            {"type": "image", "source": {"type": "base64", "data": "..."}},
            {"type": "text", "text": "Describe this image."},
        ]
        result = llm._add_cache_control_to_content(content)

        assert len(result) == 2
        # First item (image) should not have cache_control
        assert "cache_control" not in result[0]
        # Second item (text) should have cache_control
        assert result[1]["cache_control"] == {"type": "ephemeral"}

    def test_list_with_thinking_block_at_end_caches_last_text_block(self, llm: LLM) -> None:
        """Test that cache_control is added to the last text block, not thinking block.

        This is the key fix for extended thinking support.
        When extended thinking is enabled, content may look like:
        [{"type": "thinking", "thinking": "..."}, {"type": "text", "text": "..."}]

        Or with the thinking block at the end:
        [{"type": "text", "text": "..."}, {"type": "thinking", "thinking": "..."}]

        We must cache the text block, never the thinking block.
        """
        # Case 1: Thinking block at the end
        content = [
            {"type": "text", "text": "My response"},
            {"type": "thinking", "thinking": "Let me think about this..."},
        ]
        result = llm._add_cache_control_to_content(content)

        assert len(result) == 2
        # First item (text) should have cache_control since it's the last text block
        assert result[0]["cache_control"] == {"type": "ephemeral"}
        assert result[0]["type"] == "text"
        # Second item (thinking) should NOT have cache_control
        assert "cache_control" not in result[1]

    def test_list_with_thinking_block_first_caches_text_block(self, llm: LLM) -> None:
        """Test that cache_control is added to text block when thinking is first."""
        content = [
            {"type": "thinking", "thinking": "Let me think about this..."},
            {"type": "text", "text": "My response"},
        ]
        result = llm._add_cache_control_to_content(content)

        assert len(result) == 2
        # First item (thinking) should NOT have cache_control
        assert "cache_control" not in result[0]
        # Second item (text) should have cache_control
        assert result[1]["cache_control"] == {"type": "ephemeral"}
        assert result[1]["type"] == "text"

    def test_list_with_multiple_text_blocks_caches_last_one(self, llm: LLM) -> None:
        """Test that only the last text block gets cache_control."""
        content = [
            {"type": "text", "text": "First text"},
            {"type": "image", "source": {"type": "base64", "data": "..."}},
            {"type": "text", "text": "Second text"},
        ]
        result = llm._add_cache_control_to_content(content)

        assert len(result) == 3
        # First text block should NOT have cache_control
        assert "cache_control" not in result[0]
        # Image should NOT have cache_control
        assert "cache_control" not in result[1]
        # Last text block should have cache_control
        assert result[2]["cache_control"] == {"type": "ephemeral"}

    def test_list_with_no_text_blocks_returns_unchanged(self, llm: LLM) -> None:
        """Test that content without text blocks is returned unchanged."""
        content = [
            {"type": "image", "source": {"type": "base64", "data": "..."}},
            {"type": "thinking", "thinking": "Let me think..."},
        ]
        # Store original for comparison
        original_copy = [item.copy() for item in content]
        result = llm._add_cache_control_to_content(content)

        assert result == content
        assert content == original_copy  # Verify original wasn't mutated
        # Verify no cache_control was added
        for item in result:
            assert "cache_control" not in item

    def test_empty_list_returns_unchanged(self, llm: LLM) -> None:
        """Test that an empty list is returned unchanged."""
        content: list[dict[str, Any]] = []
        result = llm._add_cache_control_to_content(content)

        assert result == []

    def test_original_content_not_mutated(self, llm: LLM) -> None:
        """Test that the original content list is not mutated."""
        original_content = [
            {"type": "thinking", "thinking": "Let me think..."},
            {"type": "text", "text": "My response"},
        ]
        # Make a copy to compare later
        original_copy = [item.copy() for item in original_content]

        llm._add_cache_control_to_content(original_content)

        # Original content should not be mutated
        assert original_content == original_copy
        for item in original_content:
            assert "cache_control" not in item

    def test_complex_extended_thinking_content(self, llm: LLM) -> None:
        """Test a realistic extended thinking scenario with multiple blocks."""
        content = [
            {"type": "thinking", "thinking": "I need to analyze this carefully..."},
            {"type": "thinking", "thinking": "Let me consider multiple approaches..."},
            {"type": "text", "text": "Based on my analysis, here's my recommendation:"},
            {"type": "thinking", "thinking": "I should verify this is correct..."},
        ]
        result = llm._add_cache_control_to_content(content)

        assert len(result) == 4
        # Only the text block (index 2) should have cache_control
        assert "cache_control" not in result[0]  # thinking
        assert "cache_control" not in result[1]  # thinking
        assert result[2]["cache_control"] == {"type": "ephemeral"}  # text
        assert "cache_control" not in result[3]  # thinking
