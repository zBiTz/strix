"""Tests for agent stop functionality."""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strix.agents.base_agent import BaseAgent
from strix.agents.state import AgentState


class TestAgentStop:
    """Tests for the agent stop functionality to ensure the agent exits properly."""

    @pytest.fixture
    def mock_llm_config(self) -> dict[str, Any]:
        """Create a mock LLM config."""
        return {
            "api_key": "test_key",
            "model": "test_model",
        }

    @pytest.fixture
    def agent_config(self, mock_llm_config: dict[str, Any]) -> dict[str, Any]:
        """Create a basic agent config."""
        return {
            "llm_config": mock_llm_config,
            "non_interactive": True,
            "max_iterations": 10,
        }

    @pytest.fixture
    def mock_agent_state(self) -> AgentState:
        """Create a mock agent state."""
        return AgentState(
            agent_name="TestAgent",
            max_iterations=10,
        )

    @pytest.mark.asyncio
    async def test_stop_requested_exits_loop_non_interactive(
        self, agent_config: dict[str, Any], mock_agent_state: AgentState
    ) -> None:
        """Test stop_requested exits the loop in non-interactive mode."""
        # Add state to the config
        agent_config["state"] = mock_agent_state

        with (
            patch("strix.agents.base_agent.LLM"),
            patch("strix.telemetry.tracer.get_global_tracer", return_value=None),
            patch.object(
                BaseAgent, "_initialize_sandbox_and_state", new_callable=AsyncMock
            ),
        ):
            # Create agent
            agent = BaseAgent(agent_config)

            # Simulate stop_requested being set
            agent.state.request_stop()

            # Run agent_loop
            result = await agent.agent_loop("test task")

            # Assert that the agent exited properly
            assert result is not None
            # The agent should not iterate since stop was requested immediately
            assert agent.state.iteration == 0

    @pytest.mark.asyncio
    async def test_stop_requested_exits_loop_interactive_mode(
        self, agent_config: dict[str, Any], mock_agent_state: AgentState
    ) -> None:
        """Test that when stop_requested is True in interactive mode, the agent exits the loop."""
        # Set interactive mode
        agent_config["state"] = mock_agent_state
        agent_config["non_interactive"] = False

        with (
            patch("strix.agents.base_agent.LLM"),
            patch("strix.telemetry.tracer.get_global_tracer", return_value=None),
            patch.object(BaseAgent, "_initialize_sandbox_and_state", new_callable=AsyncMock),
        ):
            # Create agent in interactive mode
            agent = BaseAgent(agent_config)

            # Simulate stop_requested being set
            agent.state.request_stop()

            # Run agent_loop
            result = await agent.agent_loop("test task")

            # Assert that the agent exited properly and didn't loop forever
            assert result is not None
            # Verify the result indicates stopped by user
            assert result.get("stopped_by_user") is True
            assert result.get("success") is False
            # The agent should not iterate since stop was requested immediately
            assert agent.state.iteration == 0
            # Verify state is marked as completed
            assert agent.state.completed is True

    @pytest.mark.asyncio
    async def test_stop_requested_after_iteration_exits_loop(
        self, agent_config: dict[str, Any], mock_agent_state: AgentState
    ) -> None:
        """Test that stop_requested exits the loop after some iterations."""
        agent_config["state"] = mock_agent_state

        with (
            patch("strix.agents.base_agent.LLM") as mock_llm_class,
            patch("strix.telemetry.tracer.get_global_tracer", return_value=None),
            patch.object(BaseAgent, "_initialize_sandbox_and_state", new_callable=AsyncMock),
        ):
            # Setup mock LLM
            mock_llm = MagicMock()
            mock_response = MagicMock()
            mock_response.content = "test content"
            mock_response.tool_invocations = []
            mock_llm.generate = AsyncMock(return_value=mock_response)
            mock_llm_class.return_value = mock_llm

            # Create agent
            agent = BaseAgent(agent_config)

            # Create a flag to track if _process_iteration was called
            original_process = agent._process_iteration
            call_count = 0

            async def mock_process(*args: Any, **kwargs: Any) -> bool:
                nonlocal call_count
                call_count += 1
                # Request stop after first iteration
                if call_count == 1:
                    agent.state.request_stop()
                return await original_process(*args, **kwargs)

            with patch.object(agent, "_process_iteration", side_effect=mock_process):
                # Run agent_loop
                result = await agent.agent_loop("test task")

                # Assert that the agent exited after processing one iteration
                assert result is not None
                assert call_count == 1
                assert agent.state.iteration == 1

    @pytest.mark.asyncio
    async def test_completed_state_exits_loop(
        self, agent_config: dict[str, Any], mock_agent_state: AgentState
    ) -> None:
        """Test that completed state also exits the loop properly."""
        agent_config["state"] = mock_agent_state

        with (
            patch("strix.agents.base_agent.LLM"),
            patch("strix.telemetry.tracer.get_global_tracer", return_value=None),
            patch.object(BaseAgent, "_initialize_sandbox_and_state", new_callable=AsyncMock),
        ):
            # Create agent
            agent = BaseAgent(agent_config)

            # Set agent as completed
            agent.state.set_completed({"success": True, "result": "test"})

            # Run agent_loop
            result = await agent.agent_loop("test task")

            # Assert that the agent exited properly
            assert result is not None
            assert result == {"success": True, "result": "test"}

    @pytest.mark.asyncio
    async def test_max_iterations_exits_loop(
        self, agent_config: dict[str, Any], mock_agent_state: AgentState
    ) -> None:
        """Test that reaching max iterations exits the loop."""
        agent_config["state"] = mock_agent_state
        agent_config["max_iterations"] = 1

        with (
            patch("strix.agents.base_agent.LLM") as mock_llm_class,
            patch("strix.telemetry.tracer.get_global_tracer", return_value=None),
            patch.object(BaseAgent, "_initialize_sandbox_and_state", new_callable=AsyncMock),
        ):
            # Setup mock LLM
            mock_llm = MagicMock()
            mock_response = MagicMock()
            mock_response.content = "test content"
            mock_response.tool_invocations = []
            mock_llm.generate = AsyncMock(return_value=mock_response)
            mock_llm_class.return_value = mock_llm

            # Create agent with max_iterations = 1
            agent = BaseAgent(agent_config)

            # Run agent_loop
            result = await agent.agent_loop("test task")

            # Assert that the agent exited after hitting max iterations
            assert result is not None
            assert agent.state.iteration >= 1

    def test_should_stop_returns_true_when_stop_requested(
        self, mock_agent_state: AgentState
    ) -> None:
        """Test that should_stop returns True when stop_requested is set."""
        mock_agent_state.request_stop()
        assert mock_agent_state.should_stop() is True

    def test_should_stop_returns_true_when_completed(self, mock_agent_state: AgentState) -> None:
        """Test that should_stop returns True when completed is set."""
        mock_agent_state.set_completed({"success": True})
        assert mock_agent_state.should_stop() is True

    def test_should_stop_returns_true_when_max_iterations(
        self, mock_agent_state: AgentState
    ) -> None:
        """Test that should_stop returns True when max iterations reached."""
        mock_agent_state.iteration = mock_agent_state.max_iterations
        assert mock_agent_state.should_stop() is True

    def test_should_stop_returns_false_by_default(self, mock_agent_state: AgentState) -> None:
        """Test that should_stop returns False by default."""
        assert mock_agent_state.should_stop() is False
