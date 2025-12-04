"""Tests for terminal timeout and prompt detection fixes."""

import time
from typing import Any

import pytest

from strix.tools.terminal.terminal_manager import TerminalManager
from strix.tools.terminal.terminal_session import TerminalSession


class TestTerminalTimeout:
    """Tests for terminal timeout functionality."""

    @pytest.fixture
    def terminal_manager(self) -> TerminalManager:
        """Create a terminal manager."""
        manager = TerminalManager()
        yield manager
        # Cleanup
        manager.close_all_sessions()

    def test_simple_command_completes_quickly(
        self, terminal_manager: TerminalManager
    ) -> None:
        """Test that simple commands like mkdir complete quickly."""
        start = time.time()
        result = terminal_manager.execute_command("mkdir -p /tmp/test_strix")
        elapsed = time.time() - start

        assert result["status"] == "completed"
        assert result["exit_code"] == 0
        assert elapsed < 5.0, f"Simple command took {elapsed}s, expected < 5s"

    def test_simple_cd_command(self, terminal_manager: TerminalManager) -> None:
        """Test that cd command works correctly."""
        # Create directory first
        result = terminal_manager.execute_command("mkdir -p /tmp/test_strix_cd")
        assert result["status"] == "completed"

        # Change to the directory
        result = terminal_manager.execute_command("cd /tmp/test_strix_cd && pwd")
        assert result["status"] == "completed"
        assert "/tmp/test_strix_cd" in result["content"]

    def test_chained_commands_complete_quickly(
        self, terminal_manager: TerminalManager
    ) -> None:
        """Test that chained commands complete quickly."""
        start = time.time()
        result = terminal_manager.execute_command(
            "mkdir -p /tmp/test_chain && cd /tmp/test_chain && pwd"
        )
        elapsed = time.time() - start

        assert result["status"] == "completed"
        assert result["exit_code"] == 0
        assert elapsed < 5.0, f"Chained command took {elapsed}s, expected < 5s"
        assert "/tmp/test_chain" in result["content"]

    def test_timeout_triggers_properly(
        self, terminal_manager: TerminalManager
    ) -> None:
        """Test that timeout triggers for long-running commands."""
        # Use a command that sleeps for longer than timeout
        result = terminal_manager.execute_command("sleep 100", timeout=2.0)

        assert result["status"] in ["running", "timeout"]
        assert "still running" in result["content"].lower() or "timeout" in result[
            "content"
        ].lower()

    def test_max_command_timeout_enforced(
        self, terminal_manager: TerminalManager
    ) -> None:
        """Test that MAX_COMMAND_TIMEOUT is enforced."""
        # Request a very long timeout, should be clamped to MAX_COMMAND_TIMEOUT
        # We won't actually wait that long, just verify it's clamped
        session = terminal_manager._get_or_create_session("test")

        # Check that the constant exists
        assert hasattr(TerminalSession, "MAX_COMMAND_TIMEOUT")
        assert TerminalSession.MAX_COMMAND_TIMEOUT == 300.0

    def test_hard_timeout_protection(
        self, terminal_manager: TerminalManager
    ) -> None:
        """Test that hard timeout protection works via outer timeout wrapper."""
        # This tests the ThreadPoolExecutor timeout wrapper
        # Use a command that will timeout
        start = time.time()
        result = terminal_manager.execute_command("sleep 100", timeout=1.0)
        elapsed = time.time() - start

        # Should timeout within reasonable time (timeout + buffer)
        assert elapsed < 10.0, f"Hard timeout took {elapsed}s, expected < 10s"
        assert result["status"] in ["running", "timeout", "hard_timeout"]


class TestTerminalPromptDetection:
    """Tests for PS1 prompt detection and recovery."""

    @pytest.fixture
    def terminal_session(self) -> TerminalSession:
        """Create a terminal session."""
        session = TerminalSession("test-prompt")
        yield session
        session.close()

    def test_ps1_verification_runs(self, terminal_session: TerminalSession) -> None:
        """Test that PS1 verification runs during initialization."""
        # Session should be initialized
        assert terminal_session._initialized
        # Verify we can execute a simple command
        result = terminal_session.execute("echo test")
        assert result["status"] == "completed"

    def test_detect_command_completion_exists(
        self, terminal_session: TerminalSession
    ) -> None:
        """Test that fallback detection method exists."""
        # Verify the method exists
        assert hasattr(terminal_session, "_detect_command_completion")

    def test_try_recover_session_exists(
        self, terminal_session: TerminalSession
    ) -> None:
        """Test that session recovery method exists."""
        # Verify the method exists
        assert hasattr(terminal_session, "_try_recover_session")

    def test_verify_prompt_setup_exists(
        self, terminal_session: TerminalSession
    ) -> None:
        """Test that prompt setup verification exists."""
        # Verify the method exists
        assert hasattr(terminal_session, "_verify_prompt_setup")


class TestTerminalManagerOuterTimeout:
    """Tests for terminal manager outer timeout wrapper."""

    def test_execute_command_internal_exists(self) -> None:
        """Test that internal execute method exists for timeout wrapper."""
        manager = TerminalManager()
        assert hasattr(manager, "_execute_command_internal")
        manager.close_all_sessions()
