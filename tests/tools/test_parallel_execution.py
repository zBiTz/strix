"""Tests for parallel tool execution."""

import asyncio
from typing import Any
from unittest.mock import patch

import pytest


class TestToolGrouping:
    """Tests for _group_tool_invocations function."""

    def test_groups_parallelizable_tools(self) -> None:
        """Test that parallelizable tools are grouped correctly."""
        from strix.tools.executor import _group_tool_invocations

        with patch("strix.tools.executor.is_parallelizable") as mock_parallel:
            mock_parallel.side_effect = lambda name: name in ["list_requests", "web_search"]

            invocations = [
                {"toolName": "list_requests", "args": {}},
                {"toolName": "terminal_execute", "args": {"command": "ls"}},
                {"toolName": "web_search", "args": {"query": "test"}},
            ]

            parallel, sequential, finish = _group_tool_invocations(invocations)

            assert len(parallel) == 2
            assert len(sequential) == 1
            assert len(finish) == 0

    def test_finish_tools_grouped_separately(self) -> None:
        """Test that finish tools are always grouped last."""
        from strix.tools.executor import _group_tool_invocations

        with patch("strix.tools.executor.is_parallelizable", return_value=False):
            invocations = [
                {"toolName": "terminal_execute", "args": {}},
                {"toolName": "finish_scan", "args": {"summary": "done"}},
                {"toolName": "agent_finish", "args": {"result_summary": "done"}},
            ]

            parallel, sequential, finish = _group_tool_invocations(invocations)

            assert len(parallel) == 0
            assert len(sequential) == 1
            assert len(finish) == 2

    def test_preserves_original_indices(self) -> None:
        """Test that original indices are preserved for result ordering."""
        from strix.tools.executor import _group_tool_invocations

        with patch("strix.tools.executor.is_parallelizable") as mock_parallel:
            mock_parallel.side_effect = lambda name: name == "web_search"

            invocations = [
                {"toolName": "terminal_execute", "args": {}},
                {"toolName": "web_search", "args": {}},
                {"toolName": "finish_scan", "args": {}},
            ]

            parallel, sequential, finish = _group_tool_invocations(invocations)

            assert parallel[0][0] == 1  # original index
            assert sequential[0][0] == 0  # original index
            assert finish[0][0] == 2  # original index

    def test_empty_invocations(self) -> None:
        """Test handling of empty invocation list."""
        from strix.tools.executor import _group_tool_invocations

        parallel, sequential, finish = _group_tool_invocations([])

        assert len(parallel) == 0
        assert len(sequential) == 0
        assert len(finish) == 0

    def test_all_parallel_tools(self) -> None:
        """Test when all tools are parallelizable."""
        from strix.tools.executor import _group_tool_invocations

        with patch("strix.tools.executor.is_parallelizable", return_value=True):
            invocations = [
                {"toolName": "list_requests", "args": {}},
                {"toolName": "view_request", "args": {}},
                {"toolName": "web_search", "args": {}},
            ]

            parallel, sequential, finish = _group_tool_invocations(invocations)

            assert len(parallel) == 3
            assert len(sequential) == 0
            assert len(finish) == 0


class TestParallelExecution:
    """Tests for parallel tool execution behavior."""

    @pytest.mark.asyncio
    async def test_parallel_tools_run_concurrently(self) -> None:
        """Test that parallelizable tools actually run in parallel."""
        from strix.tools.executor import _execute_parallel_tools

        execution_times: list[float] = []

        async def mock_execute_single_tool(
            tool_inv: dict[str, Any],
            agent_state: Any,
            tracer: Any,
            agent_id: str,
        ) -> tuple[str, list[dict[str, Any]], bool]:
            tool_name = tool_inv.get("toolName")
            start = asyncio.get_event_loop().time()
            await asyncio.sleep(0.05)  # Simulate I/O
            end = asyncio.get_event_loop().time()
            execution_times.append(end - start)
            return (f"<result>{tool_name}</result>", [], False)

        with patch(
            "strix.tools.executor._execute_single_tool",
            side_effect=mock_execute_single_tool,
        ):
            invocations = [
                (0, {"toolName": "tool_a", "args": {}}),
                (1, {"toolName": "tool_b", "args": {}}),
            ]

            start_time = asyncio.get_event_loop().time()
            results = await _execute_parallel_tools(invocations, None, None, "test")
            elapsed = asyncio.get_event_loop().time() - start_time

            # If sequential, would take ~0.1s. Parallel should be ~0.05s
            assert elapsed < 0.08
            assert len(results) == 2

    @pytest.mark.asyncio
    async def test_parallel_error_isolation(self) -> None:
        """Test that one parallel tool error doesn't crash others."""
        from strix.tools.executor import _execute_parallel_tools

        async def mock_execute_single_tool(
            tool_inv: dict[str, Any],
            agent_state: Any,
            tracer: Any,
            agent_id: str,
        ) -> tuple[str, list[dict[str, Any]], bool]:
            tool_name = tool_inv.get("toolName")
            if tool_name == "failing_tool":
                raise RuntimeError("Simulated failure")
            return (f"<result>{tool_name}</result>", [], False)

        with patch(
            "strix.tools.executor._execute_single_tool",
            side_effect=mock_execute_single_tool,
        ):
            invocations = [
                (0, {"toolName": "good_tool", "args": {}}),
                (1, {"toolName": "failing_tool", "args": {}}),
            ]

            results = await _execute_parallel_tools(invocations, None, None, "test")

            assert len(results) == 2
            # Good tool succeeded
            assert "good_tool" in results[0][1]
            # Failing tool has error message
            assert "Error:" in results[1][1]


class TestProcessToolInvocations:
    """Tests for the main process_tool_invocations function."""

    @pytest.mark.asyncio
    async def test_empty_invocations_returns_false(self) -> None:
        """Test that empty invocations return False."""
        from strix.tools.executor import process_tool_invocations

        conversation_history: list[dict[str, Any]] = []
        result = await process_tool_invocations([], conversation_history, None)

        assert result is False
        assert len(conversation_history) == 0

    @pytest.mark.asyncio
    async def test_results_ordered_by_original_position(self) -> None:
        """Test that results maintain original invocation order."""
        from strix.tools.executor import process_tool_invocations

        call_order: list[str] = []

        async def mock_execute_single_tool(
            tool_inv: dict[str, Any],
            agent_state: Any,
            tracer: Any,
            agent_id: str,
        ) -> tuple[str, list[dict[str, Any]], bool]:
            tool_name = tool_inv.get("toolName")
            call_order.append(str(tool_name))
            return (f"<result>{tool_name}</result>", [], False)

        with (
            patch(
                "strix.tools.executor._execute_single_tool",
                side_effect=mock_execute_single_tool,
            ),
            patch("strix.tools.executor.is_parallelizable") as mock_parallel,
        ):
            mock_parallel.side_effect = lambda name: name in ["tool_b", "tool_d"]

            invocations = [
                {"toolName": "tool_a"},
                {"toolName": "tool_b"},
                {"toolName": "tool_c"},
                {"toolName": "tool_d"},
            ]

            conversation_history: list[dict[str, Any]] = []
            await process_tool_invocations(invocations, conversation_history, None)

            result_content = conversation_history[0]["content"]
            # Results should be in original order regardless of execution order
            assert result_content.index("tool_a") < result_content.index("tool_b")
            assert result_content.index("tool_b") < result_content.index("tool_c")
            assert result_content.index("tool_c") < result_content.index("tool_d")

    @pytest.mark.asyncio
    async def test_finish_tools_execute_last(self) -> None:
        """Test that finish tools always execute after all other tools."""
        from strix.tools.executor import process_tool_invocations

        execution_order: list[str] = []

        async def mock_execute_single_tool(
            tool_inv: dict[str, Any],
            agent_state: Any,
            tracer: Any,
            agent_id: str,
        ) -> tuple[str, list[dict[str, Any]], bool]:
            tool_name = tool_inv.get("toolName")
            execution_order.append(str(tool_name))
            return (f"<result>{tool_name}</result>", [], tool_name == "finish_scan")

        with (
            patch(
                "strix.tools.executor._execute_single_tool",
                side_effect=mock_execute_single_tool,
            ),
            patch("strix.tools.executor.is_parallelizable", return_value=False),
        ):
            invocations = [
                {"toolName": "finish_scan"},
                {"toolName": "terminal_execute"},
                {"toolName": "list_requests"},
            ]

            conversation_history: list[dict[str, Any]] = []
            result = await process_tool_invocations(
                invocations, conversation_history, None
            )

            # finish_scan should be last in execution order
            assert execution_order[-1] == "finish_scan"
            assert result is True  # should_agent_finish

    @pytest.mark.asyncio
    async def test_images_included_in_history(self) -> None:
        """Test that images are properly included in conversation history."""
        from strix.tools.executor import process_tool_invocations

        async def mock_execute_single_tool(
            tool_inv: dict[str, Any],
            agent_state: Any,
            tracer: Any,
            agent_id: str,
        ) -> tuple[str, list[dict[str, Any]], bool]:
            images = [{"type": "image_url", "image_url": {"url": "data:image/png;base64,abc"}}]
            return ("<result>test</result>", images, False)

        with (
            patch(
                "strix.tools.executor._execute_single_tool",
                side_effect=mock_execute_single_tool,
            ),
            patch("strix.tools.executor.is_parallelizable", return_value=False),
        ):
            invocations = [{"toolName": "browser_action"}]

            conversation_history: list[dict[str, Any]] = []
            await process_tool_invocations(invocations, conversation_history, None)

            # Content should be a list when images are present
            content = conversation_history[0]["content"]
            assert isinstance(content, list)
            assert any(item.get("type") == "image_url" for item in content)


class TestRegistryIntegration:
    """Tests for registry integration with parallel execution."""

    def test_is_parallelizable_returns_false_by_default(self) -> None:
        """Test that is_parallelizable returns False for unknown tools."""
        from strix.tools.registry import is_parallelizable

        result = is_parallelizable("nonexistent_tool")
        assert result is False

    def test_parallelizable_tool_registration(self) -> None:
        """Test that tools can be registered with parallelizable=True."""
        from strix.tools.registry import (
            _tools_by_name,
            clear_registry,
            is_parallelizable,
            register_tool,
            tools,
        )

        # Clear registry for isolated test
        original_tools = tools.copy()
        original_by_name = _tools_by_name.copy()

        try:
            clear_registry()

            @register_tool(parallelizable=True)
            def test_parallel_tool() -> str:
                return "test"

            assert is_parallelizable("test_parallel_tool") is True

            @register_tool(parallelizable=False)
            def test_sequential_tool() -> str:
                return "test"

            assert is_parallelizable("test_sequential_tool") is False

            @register_tool  # Default should be False
            def test_default_tool() -> str:
                return "test"

            assert is_parallelizable("test_default_tool") is False

        finally:
            # Restore registry
            clear_registry()
            tools.extend(original_tools)
            _tools_by_name.update(original_by_name)
