"""Tests for LLM environment variable configuration."""

import os
from unittest.mock import patch

import litellm

from strix.llm.llm import configure_litellm


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
