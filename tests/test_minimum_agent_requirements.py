"""Tests for minimum agent requirements validation in finish_scan."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from strix.tools.finish.finish_actions import (
    MIN_RECOMMENDED_AGENTS,
    _check_minimum_agent_requirements,
    finish_scan,
)


class TestMinimumAgentRequirements:
    """Tests for the _check_minimum_agent_requirements function."""

    @pytest.fixture
    def mock_agent_state(self) -> MagicMock:
        """Create a mock agent state."""
        state = MagicMock()
        state.agent_id = "root_agent_123"
        state.parent_id = None
        return state

    @pytest.fixture
    def agent_graph_with_no_subagents(self) -> dict[str, Any]:
        """Create an agent graph with only the root agent (no sub-agents)."""
        return {
            "nodes": {
                "root_agent_123": {
                    "name": "RootAgent",
                    "parent_id": None,
                    "status": "running",
                },
            }
        }

    @pytest.fixture
    def agent_graph_with_few_subagents(self) -> dict[str, Any]:
        """Create an agent graph with 3 sub-agents (below threshold)."""
        return {
            "nodes": {
                "root_agent_123": {
                    "name": "RootAgent",
                    "parent_id": None,
                    "status": "running",
                },
                "agent_001": {
                    "name": "Reconnaissance Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_002": {
                    "name": "SQLi Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_003": {
                    "name": "XSS Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
            }
        }

    @pytest.fixture
    def agent_graph_with_sufficient_subagents(self) -> dict[str, Any]:
        """Create an agent graph with 6 sub-agents (meets threshold)."""
        return {
            "nodes": {
                "root_agent_123": {
                    "name": "RootAgent",
                    "parent_id": None,
                    "status": "running",
                },
                "agent_001": {
                    "name": "Reconnaissance Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_002": {
                    "name": "Auth Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_003": {
                    "name": "Input Validation Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_004": {
                    "name": "Business Logic Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_005": {
                    "name": "API Security Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_006": {
                    "name": "Client-side Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
            }
        }

    @pytest.fixture
    def agent_graph_with_more_than_sufficient_subagents(self) -> dict[str, Any]:
        """Create an agent graph with 8 sub-agents (exceeds threshold)."""
        return {
            "nodes": {
                "root_agent_123": {
                    "name": "RootAgent",
                    "parent_id": None,
                    "status": "running",
                },
                "agent_001": {
                    "name": "Reconnaissance Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_002": {
                    "name": "Auth Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_003": {
                    "name": "Input Validation Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_004": {
                    "name": "Business Logic Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_005": {
                    "name": "API Security Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_006": {
                    "name": "Client-side Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_007": {
                    "name": "SSRF Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_008": {
                    "name": "XXE Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
            }
        }

    @pytest.fixture
    def agent_graph_with_agents_without_parent_id(self) -> dict[str, Any]:
        """Create an agent graph with some agents without parent_id (should not be counted)."""
        return {
            "nodes": {
                "root_agent_123": {
                    "name": "RootAgent",
                    "parent_id": None,
                    "status": "running",
                },
                "agent_001": {
                    "name": "Reconnaissance Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_002": {
                    "name": "SQLi Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                # These agents have no parent_id and should not be counted
                "orphan_agent_001": {
                    "name": "Orphan Agent 1",
                    "status": "finished",
                },
                "orphan_agent_002": {
                    "name": "Orphan Agent 2",
                    "status": "finished",
                },
            }
        }

    def test_no_subagents_returns_warning(
        self, mock_agent_state: MagicMock, agent_graph_with_no_subagents: dict[str, Any]
    ) -> None:
        """Test that warning is generated when no sub-agents are created."""
        with patch(
            "strix.tools.agents_graph.agents_graph_actions._agent_graph",
            agent_graph_with_no_subagents,
        ):
            result = _check_minimum_agent_requirements(mock_agent_state)

        assert result is not None
        assert result["success"] is True
        assert "warning" in result
        assert "0 sub-agent(s)" in result["warning"]
        assert f"at least {MIN_RECOMMENDED_AGENTS}" in result["warning"]
        assert result["agents_created"] == 0
        assert result["recommended_minimum"] == MIN_RECOMMENDED_AGENTS

    def test_few_subagents_returns_warning(
        self, mock_agent_state: MagicMock, agent_graph_with_few_subagents: dict[str, Any]
    ) -> None:
        """Test that warning is generated when below threshold (3 < 6)."""
        with patch(
            "strix.tools.agents_graph.agents_graph_actions._agent_graph",
            agent_graph_with_few_subagents,
        ):
            result = _check_minimum_agent_requirements(mock_agent_state)

        assert result is not None
        assert result["success"] is True
        assert "warning" in result
        assert "3 sub-agent(s)" in result["warning"]
        assert f"at least {MIN_RECOMMENDED_AGENTS}" in result["warning"]
        assert result["agents_created"] == 3
        assert result["recommended_minimum"] == MIN_RECOMMENDED_AGENTS

    def test_sufficient_subagents_no_warning(
        self,
        mock_agent_state: MagicMock,
        agent_graph_with_sufficient_subagents: dict[str, Any],
    ) -> None:
        """Test that no warning is generated when threshold is met (6 == 6)."""
        with patch(
            "strix.tools.agents_graph.agents_graph_actions._agent_graph",
            agent_graph_with_sufficient_subagents,
        ):
            result = _check_minimum_agent_requirements(mock_agent_state)

        assert result is None

    def test_more_than_sufficient_subagents_no_warning(
        self,
        mock_agent_state: MagicMock,
        agent_graph_with_more_than_sufficient_subagents: dict[str, Any],
    ) -> None:
        """Test that no warning is generated when threshold is exceeded (8 > 6)."""
        with patch(
            "strix.tools.agents_graph.agents_graph_actions._agent_graph",
            agent_graph_with_more_than_sufficient_subagents,
        ):
            result = _check_minimum_agent_requirements(mock_agent_state)

        assert result is None

    def test_counts_only_agents_with_parent_id(
        self,
        mock_agent_state: MagicMock,
        agent_graph_with_agents_without_parent_id: dict[str, Any],
    ) -> None:
        """Test that only agents with parent_id are counted as sub-agents."""
        with patch(
            "strix.tools.agents_graph.agents_graph_actions._agent_graph",
            agent_graph_with_agents_without_parent_id,
        ):
            result = _check_minimum_agent_requirements(mock_agent_state)

        # Should count only 2 agents (agent_001 and agent_002), not orphan agents
        assert result is not None
        assert result["success"] is True
        assert "warning" in result
        assert "2 sub-agent(s)" in result["warning"]
        assert result["agents_created"] == 2
        assert result["recommended_minimum"] == MIN_RECOMMENDED_AGENTS

    def test_import_error_returns_none(self, mock_agent_state: MagicMock) -> None:
        """Test that ImportError is handled gracefully and returns None."""
        # Simulate ImportError by making the import statement fail
        import sys

        with patch.dict(sys.modules, {"strix.tools.agents_graph.agents_graph_actions": None}):
            result = _check_minimum_agent_requirements(mock_agent_state)

        assert result is None

    def test_no_agent_state_still_works(
        self, agent_graph_with_few_subagents: dict[str, Any]
    ) -> None:
        """Test that function works even when agent_state is None."""
        with patch(
            "strix.tools.agents_graph.agents_graph_actions._agent_graph",
            agent_graph_with_few_subagents,
        ):
            result = _check_minimum_agent_requirements(None)

        # When agent_state is None, current_agent_id is None, so all 4 agents are counted
        # (root + 3 sub-agents, but root has no parent_id so only 3 counted)
        assert result is not None
        assert result["success"] is True
        assert result["agents_created"] == 3


class TestFinishScanIntegration:
    """Tests for integration of minimum agent requirements with finish_scan."""

    @pytest.fixture
    def mock_agent_state(self) -> MagicMock:
        """Create a mock agent state."""
        state = MagicMock()
        state.agent_id = "root_agent_123"
        state.parent_id = None
        return state

    @pytest.fixture
    def agent_graph_with_few_subagents(self) -> dict[str, Any]:
        """Create an agent graph with 3 sub-agents (below threshold)."""
        return {
            "nodes": {
                "root_agent_123": {
                    "name": "RootAgent",
                    "parent_id": None,
                    "status": "running",
                },
                "agent_001": {
                    "name": "Reconnaissance Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_002": {
                    "name": "SQLi Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_003": {
                    "name": "XSS Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
            }
        }

    @pytest.fixture
    def agent_graph_with_sufficient_subagents(self) -> dict[str, Any]:
        """Create an agent graph with 6 sub-agents (meets threshold)."""
        return {
            "nodes": {
                "root_agent_123": {
                    "name": "RootAgent",
                    "parent_id": None,
                    "status": "running",
                },
                "agent_001": {
                    "name": "Reconnaissance Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_002": {
                    "name": "Auth Testing Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_003": {
                    "name": "Input Validation Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_004": {
                    "name": "Business Logic Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_005": {
                    "name": "API Security Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
                "agent_006": {
                    "name": "Client-side Agent",
                    "parent_id": "root_agent_123",
                    "status": "finished",
                },
            }
        }

    def test_finish_scan_includes_warning_when_below_threshold(
        self, mock_agent_state: MagicMock, agent_graph_with_few_subagents: dict[str, Any]
    ) -> None:
        """Test that finish_scan includes warning in result when below threshold."""
        with patch(
            "strix.tools.agents_graph.agents_graph_actions._agent_graph",
            agent_graph_with_few_subagents,
        ), patch(
            "strix.telemetry.tracer.get_global_tracer", return_value=None
        ):
            result = finish_scan(
                content="Scan completed successfully",
                success=True,
                agent_state=mock_agent_state,
            )

        assert result["success"] is True
        assert result["scan_completed"] is True
        assert "agent_coverage_warning" in result
        assert "3 sub-agent(s)" in result["agent_coverage_warning"]
        assert result["agents_created"] == 3
        assert result["recommended_minimum"] == MIN_RECOMMENDED_AGENTS

    def test_finish_scan_no_warning_when_sufficient(
        self,
        mock_agent_state: MagicMock,
        agent_graph_with_sufficient_subagents: dict[str, Any],
    ) -> None:
        """Test that finish_scan does not include warning when threshold is met."""
        with patch(
            "strix.tools.agents_graph.agents_graph_actions._agent_graph",
            agent_graph_with_sufficient_subagents,
        ), patch(
            "strix.telemetry.tracer.get_global_tracer", return_value=None
        ):
            result = finish_scan(
                content="Scan completed successfully",
                success=True,
                agent_state=mock_agent_state,
            )

        assert result["success"] is True
        assert result["scan_completed"] is True
        assert "agent_coverage_warning" not in result
        assert "agents_created" not in result
        assert "recommended_minimum" not in result

    def test_finish_scan_with_tracer(
        self, mock_agent_state: MagicMock, agent_graph_with_few_subagents: dict[str, Any]
    ) -> None:
        """Test that finish_scan works correctly with tracer available."""
        mock_tracer = MagicMock()
        mock_tracer.vulnerability_reports = []

        with patch(
            "strix.tools.agents_graph.agents_graph_actions._agent_graph",
            agent_graph_with_few_subagents,
        ), patch(
            "strix.telemetry.tracer.get_global_tracer", return_value=mock_tracer
        ):
            result = finish_scan(
                content="Scan completed successfully",
                success=True,
                agent_state=mock_agent_state,
            )

        assert result["success"] is True
        assert result["scan_completed"] is True
        assert "vulnerabilities_found" in result
        assert result["vulnerabilities_found"] == 0
        assert "agent_coverage_warning" in result
        assert result["agents_created"] == 3
        assert result["recommended_minimum"] == MIN_RECOMMENDED_AGENTS

        # Verify tracer was called
        mock_tracer.set_final_scan_result.assert_called_once_with(
            content="Scan completed successfully",
            success=True,
        )

    def test_min_recommended_agents_constant_value(self) -> None:
        """Test that MIN_RECOMMENDED_AGENTS constant has the expected value."""
        assert MIN_RECOMMENDED_AGENTS == 6
