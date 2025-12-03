"""Tests for LLM environment variable configuration."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import litellm
import pytest

from strix.llm.config import LLMConfig
from strix.llm.llm import LLM, configure_litellm


class TestConfigureLitellm:
    """Tests for the configure_litellm function."""

    def teardown_method(self) -> None:
        """Reset litellm settings after each test."""
        litellm.api_key = None
        litellm.api_base = None

    def test_configure_litellm_sets_api_key_from_env(self) -> None:
        """Test that LLM_API_KEY environment variable is properly set."""
        with patch.dict(os.environ, {"LLM_API_KEY": "test-api-key"}, clear=False):
            configure_litellm()
            assert litellm.api_key == "test-api-key"

    def test_configure_litellm_sets_api_base_from_llm_api_base(self) -> None:
        """Test that LLM_API_BASE takes highest priority."""
        with patch.dict(
            os.environ,
            {
                "LLM_API_BASE": "http://llm-api-base",
                "OPENAI_API_BASE": "http://openai-base",
                "LITELLM_BASE_URL": "http://litellm-base",
                "OLLAMA_API_BASE": "http://ollama-base",
            },
            clear=False,
        ):
            configure_litellm()
            assert litellm.api_base == "http://llm-api-base"

    def test_configure_litellm_fallback_to_openai_api_base(self) -> None:
        """Test that OPENAI_API_BASE is used when LLM_API_BASE is not set."""
        env_vars = {
            "OPENAI_API_BASE": "http://openai-base",
            "LITELLM_BASE_URL": "http://litellm-base",
            "OLLAMA_API_BASE": "http://ollama-base",
        }
        # Remove LLM_API_BASE if it exists in current environment
        with patch.dict(os.environ, env_vars, clear=False):
            if "LLM_API_BASE" in os.environ:
                del os.environ["LLM_API_BASE"]
            configure_litellm()
            assert litellm.api_base == "http://openai-base"

    def test_configure_litellm_fallback_to_litellm_base_url(self) -> None:
        """Test that LITELLM_BASE_URL is used as second fallback."""
        env_vars = {
            "LITELLM_BASE_URL": "http://litellm-base",
            "OLLAMA_API_BASE": "http://ollama-base",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            # Remove higher priority vars
            for var in ["LLM_API_BASE", "OPENAI_API_BASE"]:
                if var in os.environ:
                    del os.environ[var]
            configure_litellm()
            assert litellm.api_base == "http://litellm-base"

    def test_configure_litellm_fallback_to_ollama_api_base(self) -> None:
        """Test that OLLAMA_API_BASE is used as last fallback."""
        env_vars = {
            "OLLAMA_API_BASE": "http://ollama-base",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            # Remove higher priority vars
            for var in ["LLM_API_BASE", "OPENAI_API_BASE", "LITELLM_BASE_URL"]:
                if var in os.environ:
                    del os.environ[var]
            configure_litellm()
            assert litellm.api_base == "http://ollama-base"

    def test_configure_litellm_no_api_key_when_not_set(self) -> None:
        """Test that api_key is not set when env var is not present."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove LLM_API_KEY if it exists
            if "LLM_API_KEY" in os.environ:
                del os.environ["LLM_API_KEY"]
            configure_litellm()
            assert litellm.api_key is None

    def test_configure_litellm_no_api_base_when_not_set(self) -> None:
        """Test that api_base is not set when no env vars are present."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove all API base vars
            for var in ["LLM_API_BASE", "OPENAI_API_BASE", "LITELLM_BASE_URL", "OLLAMA_API_BASE"]:
                if var in os.environ:
                    del os.environ[var]
            configure_litellm()
            assert litellm.api_base is None

    def test_configure_litellm_called_at_runtime_not_import(self) -> None:
        """Test that env vars are read at runtime, not import time.

        This verifies the fix for the issue where env vars were read at module import.
        """
        # First, clear any existing settings
        litellm.api_key = None
        litellm.api_base = None

        # Set new env vars
        with patch.dict(
            os.environ,
            {
                "LLM_API_KEY": "runtime-key",
                "LLM_API_BASE": "http://runtime-base",
            },
            clear=False,
        ):
            # Call configure_litellm and verify it picks up the new values
            configure_litellm()
            assert litellm.api_key == "runtime-key"
            assert litellm.api_base == "http://runtime-base"

    def test_configure_litellm_can_be_called_multiple_times(self) -> None:
        """Test that configure_litellm can be called multiple times with different values."""
        # First configuration
        with patch.dict(
            os.environ,
            {"LLM_API_KEY": "first-key", "LLM_API_BASE": "http://first-base"},
            clear=False,
        ):
            configure_litellm()
            assert litellm.api_key == "first-key"
            assert litellm.api_base == "http://first-base"

        # Second configuration with different values
        with patch.dict(
            os.environ,
            {"LLM_API_KEY": "second-key", "LLM_API_BASE": "http://second-base"},
            clear=False,
        ):
            configure_litellm()
            assert litellm.api_key == "second-key"
            assert litellm.api_base == "http://second-base"


class TestLLMTemperature:
    """Tests for LLM temperature configuration."""

    @pytest.fixture
    def llm_config(self) -> LLMConfig:
        """Create a mock LLM config."""
        config = MagicMock(spec=LLMConfig)
        config.model_name = "openai/gpt-4"
        config.enable_prompt_caching = False
        config.timeout = 60
        config.prompt_modules = []
        return config

    @pytest.fixture
    def llm(self, llm_config: LLMConfig) -> LLM:
        """Create an LLM instance without loading prompts."""
        return LLM(config=llm_config, agent_name=None, agent_id=None)

    @pytest.mark.asyncio
    async def test_temperature_defaults_to_zero(self, llm: LLM) -> None:
        """Test that temperature defaults to 0.5 when not set."""
        with patch.dict(os.environ, {}, clear=False):
            if "LLM_TEMPERATURE" in os.environ:
                del os.environ["LLM_TEMPERATURE"]

            # Mock the queue's make_request method
            with patch("strix.llm.llm.get_global_queue") as mock_queue:
                mock_response = MagicMock()
                mock_response.choices = []
                mock_queue.return_value.make_request = AsyncMock(return_value=mock_response)

                messages = [{"role": "user", "content": "test"}]
                await llm._make_request(messages)

                # Verify temperature was set to 0.5
                call_args = mock_queue.return_value.make_request.call_args
                assert call_args[0][0]["temperature"] == 0.5

    @pytest.mark.asyncio
    async def test_temperature_respects_env_var(self, llm: LLM) -> None:
        """Test that LLM_TEMPERATURE environment variable is respected."""
        with (
            patch.dict(os.environ, {"LLM_TEMPERATURE": "0.7"}, clear=False),
            patch("strix.llm.llm.get_global_queue") as mock_queue,
        ):
            mock_response = MagicMock()
            mock_response.choices = []
            mock_queue.return_value.make_request = AsyncMock(return_value=mock_response)

            messages = [{"role": "user", "content": "test"}]
            await llm._make_request(messages)

            # Verify temperature was set to 0.7
            call_args = mock_queue.return_value.make_request.call_args
            assert call_args[0][0]["temperature"] == 0.7

    @pytest.mark.asyncio
    async def test_temperature_accepts_float_values(self, llm: LLM) -> None:
        """Test that temperature accepts various float values."""
        test_values = ["0.0", "0.5", "1.0", "1.5", "2.0"]

        for temp_str in test_values:
            with (
                patch.dict(os.environ, {"LLM_TEMPERATURE": temp_str}, clear=False),
                patch("strix.llm.llm.get_global_queue") as mock_queue,
            ):
                mock_response = MagicMock()
                mock_response.choices = []
                mock_queue.return_value.make_request = AsyncMock(return_value=mock_response)

                messages = [{"role": "user", "content": "test"}]
                await llm._make_request(messages)

                # Verify temperature was set correctly
                call_args = mock_queue.return_value.make_request.call_args
                assert call_args[0][0]["temperature"] == float(temp_str)

    @pytest.mark.asyncio
    async def test_temperature_handles_invalid_values(self, llm: LLM) -> None:
        """Test that invalid temperature values default to 0.5."""
        invalid_values = ["invalid", "not-a-number", ""]

        for invalid_str in invalid_values:
            with (
                patch.dict(os.environ, {"LLM_TEMPERATURE": invalid_str}, clear=False),
                patch("strix.llm.llm.get_global_queue") as mock_queue,
            ):
                mock_response = MagicMock()
                mock_response.choices = []
                mock_queue.return_value.make_request = AsyncMock(return_value=mock_response)

                messages = [{"role": "user", "content": "test"}]
                await llm._make_request(messages)

                # Verify temperature defaulted to 0.5
                call_args = mock_queue.return_value.make_request.call_args
                assert call_args[0][0]["temperature"] == 0.5

    @pytest.mark.asyncio
    async def test_temperature_clamps_out_of_range_values(self, llm: LLM) -> None:
        """Test that out-of-range temperature values are clamped to valid range."""
        # Test negative value clamped to 0.0
        with (
            patch.dict(os.environ, {"LLM_TEMPERATURE": "-1.0"}, clear=False),
            patch("strix.llm.llm.get_global_queue") as mock_queue,
        ):
            mock_response = MagicMock()
            mock_response.choices = []
            mock_queue.return_value.make_request = AsyncMock(return_value=mock_response)

            messages = [{"role": "user", "content": "test"}]
            await llm._make_request(messages)

            call_args = mock_queue.return_value.make_request.call_args
            assert call_args[0][0]["temperature"] == 0.0

        # Test value > 2.0 clamped to 2.0
        with (
            patch.dict(os.environ, {"LLM_TEMPERATURE": "3.5"}, clear=False),
            patch("strix.llm.llm.get_global_queue") as mock_queue,
        ):
            mock_response = MagicMock()
            mock_response.choices = []
            mock_queue.return_value.make_request = AsyncMock(return_value=mock_response)

            messages = [{"role": "user", "content": "test"}]
            await llm._make_request(messages)

            call_args = mock_queue.return_value.make_request.call_args
            assert call_args[0][0]["temperature"] == 2.0
