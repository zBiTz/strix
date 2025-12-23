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
