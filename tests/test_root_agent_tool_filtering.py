"""Tests for root agent tool filtering."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strix.agents.base_agent import BaseAgent
from strix.agents.state import AgentState
from strix.llm.config import LLMConfig


class TestRootAgentToolFiltering:
    """Tests for root agent tool filtering functionality."""

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
    def root_agent_state(self) -> AgentState:
        """Create a mock root agent state (parent_id is None)."""
        return AgentState(
            agent_name="RootAgent",
            parent_id=None,
            task="Test root agent task",
        )

    @pytest.fixture
    def sub_agent_state(self) -> AgentState:
        """Create a mock sub-agent state (parent_id is set)."""
        return AgentState(
            agent_name="SubAgent",
            parent_id="agent_parent123",
            task="Test sub-agent task",
        )

    @pytest.fixture
    def base_agent_config(self, llm_config: LLMConfig) -> dict:
        """Create a base agent config."""
        return {
            "llm_config": llm_config,
            "non_interactive": True,
            "max_iterations": 2000,
        }

    @pytest.mark.asyncio
    async def test_root_agent_blocks_non_coordination_tools(
        self, base_agent_config: dict, root_agent_state: AgentState
    ) -> None:
        """Test that root agent blocks non-coordination tools."""
        base_agent_config["state"] = root_agent_state

        with patch("strix.agents.base_agent.LLM"):
            agent = BaseAgent(base_agent_config)

        # Mock process_tool_invocations to prevent actual tool execution
        with patch(
            "strix.agents.base_agent.process_tool_invocations", new_callable=AsyncMock
        ) as mock_process:
            mock_process.return_value = False

            # Create actions with both coordination and non-coordination tools
            actions = [
                {"toolName": "create_agent", "args": {"agent_type": "test"}},
                {"toolName": "terminal_execute", "args": {"command": "ls"}},
                {"toolName": "sqli_tester", "args": {"url": "http://example.com"}},
            ]

            await agent._execute_actions(actions, None)

            # Verify that only coordination tool was passed to process_tool_invocations
            assert mock_process.called
            filtered_actions = mock_process.call_args[0][0]
            assert len(filtered_actions) == 1
            assert filtered_actions[0]["toolName"] == "create_agent"

            # Verify blocking message was added
            messages = agent.state.get_conversation_history()
            blocking_messages = [
                msg for msg in messages if "tool_execution_blocked" in str(msg.get("content", ""))
            ]
            assert len(blocking_messages) == 1
            assert "terminal_execute" in blocking_messages[0]["content"]
            assert "sqli_tester" in blocking_messages[0]["content"]

    @pytest.mark.asyncio
    async def test_root_agent_allows_coordination_tools(
        self, base_agent_config: dict, root_agent_state: AgentState
    ) -> None:
        """Test that root agent allows all coordination tools."""
        base_agent_config["state"] = root_agent_state

        with patch("strix.agents.base_agent.LLM"):
            agent = BaseAgent(base_agent_config)

        with patch(
            "strix.agents.base_agent.process_tool_invocations", new_callable=AsyncMock
        ) as mock_process:
            mock_process.return_value = False

            # Create actions with only coordination tools
            coordination_tools = [
                {"toolName": "create_agent", "args": {}},
                {"toolName": "view_agent_graph", "args": {}},
                {"toolName": "send_message_to_agent", "args": {}},
                {"toolName": "wait_for_message", "args": {}},
                {"toolName": "finish_scan", "args": {}},
            ]

            await agent._execute_actions(coordination_tools, None)

            # Verify all coordination tools were passed through
            assert mock_process.called
            filtered_actions = mock_process.call_args[0][0]
            assert len(filtered_actions) == len(coordination_tools)

            # Verify no blocking message was added
            messages = agent.state.get_conversation_history()
            blocking_messages = [
                msg for msg in messages if "tool_execution_blocked" in str(msg.get("content", ""))
            ]
            assert len(blocking_messages) == 0

    @pytest.mark.asyncio
    async def test_sub_agent_not_affected_by_filtering(
        self, base_agent_config: dict, sub_agent_state: AgentState
    ) -> None:
        """Test that sub-agents can use all tools without filtering."""
        base_agent_config["state"] = sub_agent_state

        with patch("strix.agents.base_agent.LLM"):
            agent = BaseAgent(base_agent_config)

        with patch(
            "strix.agents.base_agent.process_tool_invocations", new_callable=AsyncMock
        ) as mock_process:
            mock_process.return_value = False

            # Create actions with non-coordination tools
            actions = [
                {"toolName": "terminal_execute", "args": {"command": "ls"}},
                {"toolName": "sqli_tester", "args": {"url": "http://example.com"}},
                {"toolName": "subdomain_enum", "args": {"domain": "example.com"}},
            ]

            await agent._execute_actions(actions, None)

            # Verify all actions were passed through (no filtering for sub-agents)
            assert mock_process.called
            filtered_actions = mock_process.call_args[0][0]
            assert len(filtered_actions) == len(actions)

            # Verify no blocking message was added
            messages = agent.state.get_conversation_history()
            blocking_messages = [
                msg for msg in messages if "tool_execution_blocked" in str(msg.get("content", ""))
            ]
            assert len(blocking_messages) == 0

    @pytest.mark.asyncio
    async def test_blocking_message_content(
        self, base_agent_config: dict, root_agent_state: AgentState
    ) -> None:
        """Test that blocking message contains helpful guidance."""
        base_agent_config["state"] = root_agent_state

        with patch("strix.agents.base_agent.LLM"):
            agent = BaseAgent(base_agent_config)

        with patch(
            "strix.agents.base_agent.process_tool_invocations", new_callable=AsyncMock
        ) as mock_process:
            mock_process.return_value = False

            actions = [
                {"toolName": "nmap_scan", "args": {}},
            ]

            await agent._execute_actions(actions, None)

            # Verify blocking message content
            messages = agent.state.get_conversation_history()
            blocking_messages = [
                msg for msg in messages if "tool_execution_blocked" in str(msg.get("content", ""))
            ]
            assert len(blocking_messages) == 1

            content = blocking_messages[0]["content"]
            # Check for key elements in the blocking message
            assert "nmap_scan" in content
            assert "root coordination agent" in content
            assert "create_agent" in content
            assert "coordination tools" in content
            assert "specialized sub-agent" in content

    @pytest.mark.asyncio
    async def test_all_tools_blocked_returns_early(
        self, base_agent_config: dict, root_agent_state: AgentState
    ) -> None:
        """Test that when all tools are blocked, execution returns early."""
        base_agent_config["state"] = root_agent_state

        with patch("strix.agents.base_agent.LLM"):
            agent = BaseAgent(base_agent_config)

        with patch(
            "strix.agents.base_agent.process_tool_invocations", new_callable=AsyncMock
        ) as mock_process:
            mock_process.return_value = False

            # Create actions with only non-coordination tools
            actions = [
                {"toolName": "terminal_execute", "args": {}},
                {"toolName": "sqli_tester", "args": {}},
            ]

            result = await agent._execute_actions(actions, None)

            # Verify process_tool_invocations was NOT called
            assert not mock_process.called

            # Verify blocking message was added
            messages = agent.state.get_conversation_history()
            blocking_messages = [
                msg for msg in messages if "tool_execution_blocked" in str(msg.get("content", ""))
            ]
            assert len(blocking_messages) == 1

            # Verify return value is False (agent should not finish)
            assert result is False
