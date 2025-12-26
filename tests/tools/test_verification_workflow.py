"""Tests for vulnerability verification workflow."""

from datetime import UTC, datetime
from unittest.mock import MagicMock


class TestReportEntersPendingQueue:
    """Tests that new reports go to pending queue, not finalized."""

    def test_report_enters_pending_queue(self) -> None:
        """Test that new vulnerability reports go to pending queue."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Create a report with evidence
        report_id = tracer.add_pending_vulnerability_report(
            title="Test Vulnerability",
            content="This is a test vulnerability description.",
            severity="high",
            evidence={
                "primary_evidence": [{"method": "GET", "url": "test", "response_status": 200}],
                "reproduction_steps": [{"step_number": 1, "description": "test"}],
                "poc_payload": "test",
                "target_url": "https://example.com",
            },
        )

        # Check the report is in pending queue
        pending = tracer.get_pending_reports()
        assert len(pending) == 1
        assert pending[0]["id"] == report_id
        assert pending[0]["status"] == "pending_verification"

        # Check it's not in finalized reports
        assert len(tracer.vulnerability_reports) == 0

    def test_multiple_reports_in_pending_queue(self) -> None:
        """Test that multiple reports can be in pending queue."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Create multiple reports
        report_id_1 = tracer.add_pending_vulnerability_report(
            title="Vulnerability 1",
            content="Description 1",
            severity="high",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url1"},
        )
        report_id_2 = tracer.add_pending_vulnerability_report(
            title="Vulnerability 2",
            content="Description 2",
            severity="medium",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url2"},
        )

        pending = tracer.get_pending_reports()
        assert len(pending) == 2
        pending_ids = [r["id"] for r in pending]
        assert report_id_1 in pending_ids
        assert report_id_2 in pending_ids


class TestVerificationFinalizesReport:
    """Tests that verified reports move to vulnerability_reports."""

    def test_verification_finalizes_report(self) -> None:
        """Test that verified reports are moved to finalized reports."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Add a pending report
        report_id = tracer.add_pending_vulnerability_report(
            title="Verified Vulnerability",
            content="This vulnerability was verified.",
            severity="critical",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url"},
        )

        # Verify that it's pending
        assert len(tracer.get_pending_reports()) == 1
        assert len(tracer.vulnerability_reports) == 0

        # Finalize the report
        verification_evidence = {
            "verified_by": "test-verifier",
            "verification_timestamp": datetime.now(UTC).isoformat(),
        }
        success = tracer.finalize_vulnerability_report(report_id, verification_evidence)

        assert success is True

        # Check it moved from pending to finalized
        assert len(tracer.get_pending_reports()) == 0
        assert len(tracer.vulnerability_reports) == 1
        assert tracer.vulnerability_reports[0]["id"] == report_id
        assert tracer.vulnerability_reports[0]["status"] == "verified"

    def test_finalize_nonexistent_report_fails(self) -> None:
        """Test that finalizing a non-existent report fails gracefully."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        success = tracer.finalize_vulnerability_report("nonexistent-id", {})
        assert success is False


class TestRejectionTracksFalsePositive:
    """Tests that rejected reports go to rejected_vulnerability_reports."""

    def test_rejection_tracks_false_positive(self) -> None:
        """Test that rejected reports are tracked as false positives."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Add a pending report
        report_id = tracer.add_pending_vulnerability_report(
            title="False Positive",
            content="This is not actually a vulnerability.",
            severity="high",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url"},
        )

        # Reject the report (use 'reason' as the parameter name)
        success = tracer.reject_vulnerability_report(
            report_id,
            reason="Could not reproduce - timing-based false positive",
        )

        assert success is True

        # Check it's no longer pending
        assert len(tracer.get_pending_reports()) == 0

        # Check it's in rejected reports
        assert len(tracer.rejected_vulnerability_reports) == 1
        rejected = tracer.rejected_vulnerability_reports[0]
        assert rejected["id"] == report_id
        assert rejected["status"] == "rejected"
        assert "timing-based false positive" in rejected["rejection_reason"]

    def test_reject_nonexistent_report_fails(self) -> None:
        """Test that rejecting a non-existent report fails gracefully."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        success = tracer.reject_vulnerability_report("nonexistent-id", "reason")
        assert success is False


class TestCreateVulnerabilityReportWithEvidence:
    """Tests for create_vulnerability_report tool with evidence parameter."""

    def test_report_without_evidence_fails(self) -> None:
        """Test that creating a report without evidence fails."""
        from strix.tools.reporting.reporting_actions import create_vulnerability_report

        mock_state = MagicMock()

        result = create_vulnerability_report(
            title="Test Vulnerability",
            content="This is a test.",
            severity="high",
            evidence={},
            agent_state=mock_state,
        )

        assert result["success"] is False
        assert "evidence" in result["message"].lower()

    def test_report_with_missing_primary_evidence_fails(self) -> None:
        """Test that report without primary_evidence fails."""
        from strix.tools.reporting.reporting_actions import create_vulnerability_report

        mock_state = MagicMock()

        result = create_vulnerability_report(
            title="Test Vulnerability",
            content="This is a test.",
            severity="high",
            evidence={
                "reproduction_steps": [{"step_number": 1, "description": "test step"}],
                "poc_payload": "test",
                "target_url": "https://example.com",
            },
            agent_state=mock_state,
        )

        assert result["success"] is False
        assert "evidence" in result["message"].lower() or "validation" in result["message"].lower()

    def test_invalid_severity_fails(self) -> None:
        """Test that invalid severity is rejected."""
        from strix.tools.reporting.reporting_actions import create_vulnerability_report

        mock_state = MagicMock()

        result = create_vulnerability_report(
            title="Test Vulnerability",
            content="This is a test.",
            severity="unknown",  # Invalid severity
            evidence={
                "primary_evidence": [{}],
                "poc_payload": "test",
                "target_url": "https://example.com",
            },
            agent_state=mock_state,
        )

        assert result["success"] is False
        assert "severity" in result["message"].lower()

    def test_empty_title_fails(self) -> None:
        """Test that empty title is rejected."""
        from strix.tools.reporting.reporting_actions import create_vulnerability_report

        mock_state = MagicMock()

        result = create_vulnerability_report(
            title="",
            content="This is a test.",
            severity="high",
            evidence={
                "primary_evidence": [{}],
                "poc_payload": "test",
                "target_url": "https://example.com",
            },
            agent_state=mock_state,
        )

        assert result["success"] is False
        assert "title" in result["message"].lower()

    def test_empty_content_fails(self) -> None:
        """Test that empty content is rejected."""
        from strix.tools.reporting.reporting_actions import create_vulnerability_report

        mock_state = MagicMock()

        result = create_vulnerability_report(
            title="Test Vulnerability",
            content="",
            severity="high",
            evidence={
                "primary_evidence": [{}],
                "poc_payload": "test",
                "target_url": "https://example.com",
            },
            agent_state=mock_state,
        )

        assert result["success"] is False
        assert "content" in result["message"].lower()


class TestIsReportVerified:
    """Tests for the is_report_verified helper method."""

    def test_returns_false_for_pending_report(self) -> None:
        """Test that pending reports return False."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Add a pending report
        report_id = tracer.add_pending_vulnerability_report(
            title="Pending Report",
            content="Still pending verification.",
            severity="high",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url"},
        )

        # Should return False since report is still pending
        assert tracer.is_report_verified(report_id) is False

    def test_returns_true_after_finalization(self) -> None:
        """Test that finalized reports return True."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Add and finalize a report
        report_id = tracer.add_pending_vulnerability_report(
            title="Finalized Report",
            content="Will be verified.",
            severity="high",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url"},
        )

        tracer.finalize_vulnerability_report(report_id, {"verified_by": "test"})

        # Should return True since report is no longer pending
        assert tracer.is_report_verified(report_id) is True

    def test_returns_true_after_rejection(self) -> None:
        """Test that rejected reports return True."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Add and reject a report
        report_id = tracer.add_pending_vulnerability_report(
            title="Rejected Report",
            content="Will be rejected.",
            severity="high",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url"},
        )

        tracer.reject_vulnerability_report(report_id, reason="False positive")

        # Should return True since report is no longer pending
        assert tracer.is_report_verified(report_id) is True

    def test_returns_false_for_nonexistent_report(self) -> None:
        """Test that non-existent reports return False (not in any finalized state)."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Non-existent report should return False (not verified, rejected, or in manual review)
        # This prevents verification agents from bypassing verification with invalid report IDs
        assert tracer.is_report_verified("nonexistent-id") is False


class TestManualReviewQueue:
    """Tests for the manual review queue functionality."""

    def test_add_to_manual_review_moves_from_pending(self) -> None:
        """Test that add_to_manual_review moves report from pending queue."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Add a pending report
        report_id = tracer.add_pending_vulnerability_report(
            title="Manual Review Report",
            content="Needs manual review.",
            severity="high",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url"},
        )

        # Verify it's pending
        assert len(tracer.get_pending_reports()) == 1

        # Move to manual review
        success = tracer.add_to_manual_review(
            report_id,
            reason="Verification agent hit max iterations",
            notes=["Agent failed to decide"],
        )

        assert success is True

        # Check it's no longer pending
        assert len(tracer.get_pending_reports()) == 0

        # Check it's in manual review queue
        assert len(tracer.needs_manual_review_reports) == 1
        review_report = tracer.needs_manual_review_reports[0]
        assert review_report["id"] == report_id
        assert review_report["status"] == "needs_manual_review"
        assert "max iterations" in review_report["review_reason"]
        assert "Agent failed to decide" in review_report["review_notes"]

    def test_add_to_manual_review_nonexistent_fails(self) -> None:
        """Test that moving non-existent report to manual review fails."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        success = tracer.add_to_manual_review("nonexistent-id", "reason")
        assert success is False

    def test_is_report_verified_true_after_manual_review(self) -> None:
        """Test that is_report_verified returns True after moving to manual review."""
        from strix.telemetry.tracer import Tracer

        tracer = Tracer(run_name="test-run")

        # Add a pending report
        report_id = tracer.add_pending_vulnerability_report(
            title="Manual Review Report",
            content="Needs manual review.",
            severity="high",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url"},
        )

        # Move to manual review
        tracer.add_to_manual_review(report_id, reason="Agent failed")

        # Should return True since report is no longer pending
        assert tracer.is_report_verified(report_id) is True


class TestAgentFinishBlocksUnverifiedVerificationAgents:
    """Tests that agent_finish blocks verification agents that haven't verified."""

    def test_agent_finish_blocked_without_verification(self) -> None:
        """Test that agent_finish returns error for unverified verification agents."""
        from strix.telemetry.tracer import Tracer, set_global_tracer
        from strix.tools.agents_graph.agents_graph_actions import (
            _agent_graph,
            agent_finish,
        )

        # Setup tracer
        tracer = Tracer(run_name="test-run")
        set_global_tracer(tracer)

        # Add a pending report
        report_id = tracer.add_pending_vulnerability_report(
            title="Test Vulnerability",
            content="Needs verification.",
            severity="high",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url"},
        )

        # Create mock agent state for verification agent
        mock_state = MagicMock()
        mock_state.agent_id = "test-verifier-123"
        mock_state.parent_id = "parent-agent"

        # Register verification agent in graph
        _agent_graph["nodes"]["test-verifier-123"] = {
            "name": "Test Verifier",
            "task": "Verify vulnerability",
            "status": "running",
            "parent_id": "parent-agent",
            "type": "verification",  # This marks it as a verification agent
            "report_id": report_id,
        }

        # Try to call agent_finish without verifying
        result = agent_finish(
            agent_state=mock_state,
            result_summary="Done",
            success=True,
        )

        # Should be blocked
        assert result["agent_completed"] is False
        assert "verify_vulnerability_report" in result["error"]
        assert "required_action" in result
        assert result["required_action"]["report_id"] == report_id

        # Cleanup
        _agent_graph["nodes"].pop("test-verifier-123", None)

    def test_agent_finish_allowed_after_verification(self) -> None:
        """Test that agent_finish works after verify_vulnerability_report is called."""
        from strix.telemetry.tracer import Tracer, set_global_tracer
        from strix.tools.agents_graph.agents_graph_actions import (
            _agent_graph,
            agent_finish,
        )

        # Setup tracer
        tracer = Tracer(run_name="test-run")
        set_global_tracer(tracer)

        # Add a pending report
        report_id = tracer.add_pending_vulnerability_report(
            title="Test Vulnerability",
            content="Needs verification.",
            severity="high",
            evidence={"primary_evidence": [{}], "poc_payload": "test", "target_url": "url"},
        )

        # Finalize (verify) the report first
        tracer.finalize_vulnerability_report(report_id, {"verified_by": "test"})

        # Create mock agent state for verification agent
        mock_state = MagicMock()
        mock_state.agent_id = "test-verifier-456"
        mock_state.parent_id = "parent-agent"

        # Register verification agent in graph with parent node
        _agent_graph["nodes"]["parent-agent"] = {
            "name": "Parent Agent",
            "status": "running",
        }
        _agent_graph["nodes"]["test-verifier-456"] = {
            "name": "Test Verifier",
            "task": "Verify vulnerability",
            "status": "running",
            "parent_id": "parent-agent",
            "type": "verification",
            "report_id": report_id,
        }

        # Now agent_finish should work
        result = agent_finish(
            agent_state=mock_state,
            result_summary="Verified successfully",
            success=True,
        )

        # Should succeed
        assert result["agent_completed"] is True

        # Cleanup
        _agent_graph["nodes"].pop("test-verifier-456", None)
        _agent_graph["nodes"].pop("parent-agent", None)

    def test_regular_agent_not_blocked(self) -> None:
        """Test that regular (non-verification) agents are not blocked."""
        from strix.tools.agents_graph.agents_graph_actions import (
            _agent_graph,
            agent_finish,
        )

        # Create mock agent state for regular agent
        mock_state = MagicMock()
        mock_state.agent_id = "regular-agent-789"
        mock_state.parent_id = "parent-agent"

        # Register regular agent in graph (no "type": "verification")
        _agent_graph["nodes"]["parent-agent"] = {
            "name": "Parent Agent",
            "status": "running",
        }
        _agent_graph["nodes"]["regular-agent-789"] = {
            "name": "Regular Agent",
            "task": "Do something",
            "status": "running",
            "parent_id": "parent-agent",
            # No "type" field - this is a regular agent
        }

        # agent_finish should work for regular agents
        result = agent_finish(
            agent_state=mock_state,
            result_summary="Done",
            success=True,
        )

        # Should succeed
        assert result["agent_completed"] is True

        # Cleanup
        _agent_graph["nodes"].pop("regular-agent-789", None)
        _agent_graph["nodes"].pop("parent-agent", None)
