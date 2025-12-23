"""Tests for vulnerability evidence validation."""

from datetime import UTC, datetime

import pytest

from strix.tools.reporting.evidence import (
    HttpEvidence,
    ReproductionStep,
    VulnerabilityEvidence,
    evidence_to_dict,
    validate_evidence,
)


class TestHttpEvidence:
    """Tests for HttpEvidence model."""

    def test_valid_http_evidence(self) -> None:
        """Test that valid HTTP evidence passes validation."""
        evidence = HttpEvidence(
            method="POST",
            url="https://example.com/api/users",
            request_headers={"Content-Type": "application/json"},
            request_body='{"name": "test"}',
            response_status=200,
            response_body_snippet='{"id": 1, "name": "test"}',
            timestamp=datetime.now(UTC).isoformat(),
        )
        assert evidence.method == "POST"
        assert evidence.response_status == 200

    def test_http_method_is_uppercased(self) -> None:
        """Test that HTTP method is converted to uppercase."""
        evidence = HttpEvidence(
            method="get",
            url="https://example.com/test",
            response_status=200,
            timestamp=datetime.now(UTC).isoformat(),
        )
        assert evidence.method == "GET"

    def test_invalid_http_method_raises(self) -> None:
        """Test that invalid HTTP method raises ValueError."""
        with pytest.raises(ValueError, match="Invalid HTTP method"):
            HttpEvidence(
                method="INVALID",
                url="https://example.com/test",
                response_status=200,
                timestamp=datetime.now(UTC).isoformat(),
            )


class TestReproductionStep:
    """Tests for ReproductionStep model."""

    def test_valid_reproduction_step(self) -> None:
        """Test that valid reproduction step passes validation."""
        step = ReproductionStep(
            step_number=1,
            description="Send a POST request to the login endpoint",
            tool_used="browser",
            expected_result="User should be logged in",
            actual_result="User was logged in successfully",
        )
        assert step.step_number == 1
        assert step.tool_used == "browser"

    def test_step_number_must_be_positive(self) -> None:
        """Test that step number must be >= 1."""
        with pytest.raises(ValueError):
            ReproductionStep(
                step_number=0,
                description="This step has invalid number",
                expected_result="Should fail",
                actual_result="Failed validation",
            )

    def test_description_too_short_raises(self) -> None:
        """Test that description must be at least 10 characters."""
        with pytest.raises(ValueError):
            ReproductionStep(
                step_number=1,
                description="Short",
                expected_result="Should fail",
                actual_result="Failed validation",
            )


class TestVulnerabilityEvidence:
    """Tests for VulnerabilityEvidence model."""

    @pytest.fixture
    def valid_http_evidence(self) -> HttpEvidence:
        """Create valid HTTP evidence for testing."""
        return HttpEvidence(
            method="POST",
            url="https://example.com/api/admin",
            request_headers={"Content-Type": "application/json"},
            request_body='{"role": "admin"}',
            response_status=200,
            response_body_snippet='{"success": true, "role": "admin"}',
            timestamp=datetime.now(UTC).isoformat(),
        )

    @pytest.fixture
    def valid_reproduction_step(self) -> ReproductionStep:
        """Create valid reproduction step for testing."""
        return ReproductionStep(
            step_number=1,
            description="Send a POST request with role=admin to escalate privileges",
            tool_used="terminal",
            expected_result="User should gain admin privileges",
            actual_result="User gained admin privileges as shown in response",
        )

    def test_valid_vulnerability_evidence(
        self, valid_http_evidence: HttpEvidence, valid_reproduction_step: ReproductionStep
    ) -> None:
        """Test that valid evidence passes validation."""
        evidence = VulnerabilityEvidence(
            primary_evidence=[valid_http_evidence],
            reproduction_steps=[valid_reproduction_step],
            poc_payload='{"role": "admin"}',
            target_url="https://example.com/api/admin",
            affected_parameter="role",
        )
        assert len(evidence.primary_evidence) == 1
        assert len(evidence.reproduction_steps) == 1
        assert evidence.poc_payload == '{"role": "admin"}'

    def test_empty_primary_evidence_raises(
        self, valid_reproduction_step: ReproductionStep
    ) -> None:
        """Test that empty primary evidence raises ValueError."""
        with pytest.raises(ValueError):
            VulnerabilityEvidence(
                primary_evidence=[],
                reproduction_steps=[valid_reproduction_step],
                poc_payload="test payload",
                target_url="https://example.com",
            )

    def test_empty_reproduction_steps_raises(
        self, valid_http_evidence: HttpEvidence
    ) -> None:
        """Test that empty reproduction steps raises ValueError."""
        with pytest.raises(ValueError):
            VulnerabilityEvidence(
                primary_evidence=[valid_http_evidence],
                reproduction_steps=[],
                poc_payload="test payload",
                target_url="https://example.com",
            )

    def test_empty_poc_payload_raises(
        self, valid_http_evidence: HttpEvidence, valid_reproduction_step: ReproductionStep
    ) -> None:
        """Test that empty POC payload raises ValueError."""
        with pytest.raises(ValueError):
            VulnerabilityEvidence(
                primary_evidence=[valid_http_evidence],
                reproduction_steps=[valid_reproduction_step],
                poc_payload="",
                target_url="https://example.com",
            )

    def test_non_sequential_steps_raises(self, valid_http_evidence: HttpEvidence) -> None:
        """Test that non-sequential step numbers raise ValueError."""
        step1 = ReproductionStep(
            step_number=1,
            description="First step of the reproduction process",
            expected_result="Expected for step 1",
            actual_result="Actual for step 1",
        )
        step3 = ReproductionStep(
            step_number=3,  # Missing step 2
            description="Third step of the reproduction process",
            expected_result="Expected for step 3",
            actual_result="Actual for step 3",
        )
        with pytest.raises(ValueError, match="sequentially numbered"):
            VulnerabilityEvidence(
                primary_evidence=[valid_http_evidence],
                reproduction_steps=[step1, step3],
                poc_payload="test payload",
                target_url="https://example.com",
            )


class TestValidateEvidence:
    """Tests for validate_evidence function."""

    def test_valid_evidence_dict_passes(self) -> None:
        """Test that valid evidence dictionary passes validation."""
        evidence_dict = {
            "primary_evidence": [
                {
                    "method": "GET",
                    "url": "https://example.com/api/users/1",
                    "response_status": 200,
                    "response_body_snippet": '{"id": 1, "name": "test"}',
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            ],
            "reproduction_steps": [
                {
                    "step_number": 1,
                    "description": "Access the user endpoint with another user's ID",
                    "expected_result": "Should receive user data for different user",
                    "actual_result": "Received user data for user ID 1",
                }
            ],
            "poc_payload": "GET /api/users/1",
            "target_url": "https://example.com/api/users/1",
            "affected_parameter": "id",
        }
        validated, error = validate_evidence(evidence_dict)
        assert error is None
        assert validated is not None
        assert len(validated.primary_evidence) == 1

    def test_missing_primary_evidence_fails(self) -> None:
        """Test that missing primary evidence returns error."""
        evidence_dict = {
            "reproduction_steps": [
                {
                    "step_number": 1,
                    "description": "Some reproduction step here",
                    "expected_result": "Expected behavior",
                    "actual_result": "Actual behavior",
                }
            ],
            "poc_payload": "test",
            "target_url": "https://example.com",
        }
        validated, error = validate_evidence(evidence_dict)
        assert validated is None
        assert error is not None
        assert "validation failed" in error.lower()

    def test_missing_reproduction_steps_fails(self) -> None:
        """Test that missing reproduction steps returns error."""
        evidence_dict = {
            "primary_evidence": [
                {
                    "method": "GET",
                    "url": "https://example.com",
                    "response_status": 200,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            ],
            "poc_payload": "test",
            "target_url": "https://example.com",
        }
        validated, error = validate_evidence(evidence_dict)
        assert validated is None
        assert error is not None

    def test_missing_poc_payload_fails(self) -> None:
        """Test that missing POC payload returns error."""
        evidence_dict = {
            "primary_evidence": [
                {
                    "method": "GET",
                    "url": "https://example.com",
                    "response_status": 200,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            ],
            "reproduction_steps": [
                {
                    "step_number": 1,
                    "description": "Some reproduction step here",
                    "expected_result": "Expected behavior",
                    "actual_result": "Actual behavior",
                }
            ],
            "target_url": "https://example.com",
        }
        validated, error = validate_evidence(evidence_dict)
        assert validated is None
        assert error is not None


class TestEvidenceToDict:
    """Tests for evidence_to_dict function."""

    def test_evidence_to_dict_roundtrip(self) -> None:
        """Test that evidence can be converted to dict and back."""
        evidence = VulnerabilityEvidence(
            primary_evidence=[
                HttpEvidence(
                    method="POST",
                    url="https://example.com/api",
                    response_status=200,
                    timestamp=datetime.now(UTC).isoformat(),
                )
            ],
            reproduction_steps=[
                ReproductionStep(
                    step_number=1,
                    description="Send a malicious POST request",
                    expected_result="Should trigger vulnerability",
                    actual_result="Vulnerability triggered successfully",
                )
            ],
            poc_payload="malicious payload",
            target_url="https://example.com/api",
        )

        evidence_dict = evidence_to_dict(evidence)
        assert isinstance(evidence_dict, dict)
        assert "primary_evidence" in evidence_dict
        assert "reproduction_steps" in evidence_dict
        assert "poc_payload" in evidence_dict

        # Validate the dict can be used to create evidence again
        validated, error = validate_evidence(evidence_dict)
        assert error is None
        assert validated is not None
