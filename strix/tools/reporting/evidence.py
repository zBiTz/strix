"""Structured evidence models for vulnerability reports.

This module defines Pydantic models that enforce structured evidence
requirements for vulnerability reports, helping to eliminate false positives
by requiring concrete proof of exploitation.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from strix.tools.reporting.vulnerability_types import (
    get_vulnerability_type_spec,
    validate_vulnerability_type,
)


class HttpEvidence(BaseModel):
    """HTTP request/response pair as evidence of exploitation.

    Captures the actual HTTP exchange that demonstrates the vulnerability,
    including the malicious payload and the server's response showing impact.
    """

    method: str = Field(description="HTTP method (GET, POST, PUT, DELETE, etc.)")
    url: str = Field(description="Full URL including query parameters")
    request_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Request headers sent",
    )
    request_body: str = Field(
        default="",
        description="Request body (for POST/PUT requests)",
    )
    response_status: int = Field(description="HTTP response status code")
    response_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Response headers received",
    )
    response_body_snippet: str = Field(
        default="",
        description="Relevant portion of response body (first 2000 chars or key section)",
    )
    timestamp: str = Field(description="ISO timestamp when request was made")
    request_id: str | None = Field(
        default=None,
        description="Reference to proxy history request ID if available",
    )

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        """Validate HTTP method is uppercase and known."""
        v = v.upper().strip()
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}
        if v not in valid_methods:
            msg = f"Invalid HTTP method: {v}"
            raise ValueError(msg)
        return v


class ReproductionStep(BaseModel):
    """A single step in the vulnerability reproduction process.

    Documents each step required to reproduce the vulnerability,
    including the expected and actual results for verification.
    """

    step_number: int = Field(ge=1, description="Step sequence number (1-indexed)")
    description: str = Field(
        min_length=10,
        description="Clear description of the action to take",
    )
    tool_used: str | None = Field(
        default=None,
        description="Tool used for this step (browser, terminal, proxy, etc.)",
    )
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments passed to the tool",
    )
    expected_result: str = Field(
        min_length=5,
        description="What should happen if vulnerability exists",
    )
    actual_result: str = Field(
        min_length=5,
        description="What actually happened during testing",
    )


class ControlTestResult(BaseModel):
    """Result of an independent control test performed by the reporter.

    Control tests are required to validate that a vulnerability is genuine
    and not a false positive. Each control test verifies a specific aspect
    of the vulnerability claim.
    """

    test_name: str = Field(
        min_length=1,
        description="Name of the control test (must match type-specific requirement)",
    )
    description: str = Field(
        min_length=10,
        description="Description of what this test verifies",
    )
    request: HttpEvidence = Field(
        description="The HTTP request made for this control test",
    )
    expected_if_vulnerable: str = Field(
        min_length=5,
        description="What response would indicate the vulnerability is genuine",
    )
    expected_if_not_vulnerable: str = Field(
        min_length=5,
        description="What response would indicate this is a false positive",
    )
    actual_result: str = Field(
        min_length=5,
        description="What actually happened when the test was executed",
    )
    conclusion: str = Field(
        min_length=5,
        description="Conclusion: 'vulnerable' or 'not_vulnerable' based on result",
    )

    @field_validator("conclusion")
    @classmethod
    def validate_conclusion(cls, v: str) -> str:
        """Validate conclusion is a valid value."""
        v = v.lower().strip()
        valid_conclusions = {"vulnerable", "not_vulnerable", "inconclusive"}
        if v not in valid_conclusions:
            msg = f"Conclusion must be one of: {valid_conclusions}"
            raise ValueError(msg)
        return v


class VulnerabilityEvidence(BaseModel):
    """Complete evidence package for a vulnerability report.

    This model enforces structured evidence requirements to ensure
    vulnerability reports have concrete proof of exploitation.
    Reports without proper evidence cannot be submitted.
    """

    # Vulnerability type classification (REQUIRED)
    vulnerability_type: str = Field(
        ...,
        min_length=1,
        description="Vulnerability type from registry (e.g., 'path_traversal_lfi_rfi', 'idor')",
    )

    # Claim assertion (REQUIRED)
    claim_assertion: str = Field(
        ...,
        min_length=20,
        description="The specific security claim being made (e.g., 'Path traversal allows reading /etc/passwd')",
    )

    # Primary evidence: at least one HTTP exchange proving the vulnerability
    primary_evidence: list[HttpEvidence] = Field(
        min_length=1,
        description="At least one HTTP request/response pair proving the vulnerability",
    )

    # Reproduction steps: clear instructions to reproduce
    reproduction_steps: list[ReproductionStep] = Field(
        min_length=1,
        description="Step-by-step instructions to reproduce the vulnerability",
    )

    # The actual exploit payload
    poc_payload: str = Field(
        min_length=1,
        description="The actual payload or code that exploits the vulnerability",
    )

    # Target information
    target_url: str = Field(description="The primary URL affected by this vulnerability")
    affected_parameter: str | None = Field(
        default=None,
        description="The specific parameter vulnerable (if applicable)",
    )
    affected_endpoint: str | None = Field(
        default=None,
        description="The API endpoint or route affected",
    )

    # Before/after state comparison (critical for state-changing vulnerabilities)
    baseline_state: str | None = Field(
        default=None,
        description="State before exploitation (e.g., 'user has no admin access')",
    )
    exploited_state: str | None = Field(
        default=None,
        description="State after exploitation (e.g., 'user now has admin access')",
    )

    # Verification metadata
    reproduction_count: int = Field(
        default=1,
        ge=1,
        description="Number of times this was successfully reproduced",
    )

    # Control test evidence (REQUIRED)
    negative_control_passed: bool = Field(
        ...,
        description="Whether the control test confirmed the vulnerability is genuine (must be True)",
    )
    negative_control_description: str = Field(
        ...,
        min_length=20,
        description="Detailed description of the negative control test performed",
    )

    # Independent control tests performed by reporter (REQUIRED)
    reporter_control_tests: list[ControlTestResult] = Field(
        min_length=1,
        description="Control tests performed by reporter to validate the vulnerability",
    )

    @field_validator("primary_evidence")
    @classmethod
    def validate_evidence_not_empty(cls, v: list[HttpEvidence]) -> list[HttpEvidence]:
        """Ensure at least one piece of HTTP evidence is provided."""
        if not v:
            msg = "At least one HTTP request/response pair is required as evidence"
            raise ValueError(msg)
        return v

    @field_validator("reproduction_steps")
    @classmethod
    def validate_steps_sequential(cls, v: list[ReproductionStep]) -> list[ReproductionStep]:
        """Ensure reproduction steps are properly numbered."""
        expected_numbers = list(range(1, len(v) + 1))
        actual_numbers = [step.step_number for step in v]
        if actual_numbers != expected_numbers:
            msg = f"Reproduction steps must be sequentially numbered 1 to {len(v)}"
            raise ValueError(msg)
        return v

    @field_validator("vulnerability_type")
    @classmethod
    def validate_vulnerability_type_exists(cls, v: str) -> str:
        """Ensure vulnerability type is valid and exists in registry."""
        is_valid, error = validate_vulnerability_type(v)
        if not is_valid:
            raise ValueError(error)
        return v

    @field_validator("negative_control_passed")
    @classmethod
    def validate_negative_control_required(cls, v: bool) -> bool:
        """Ensure negative control passed - required for valid reports."""
        if not v:
            msg = (
                "negative_control_passed must be True. "
                "You must perform a control test that confirms the vulnerability is genuine. "
                "If your control test failed, this indicates a potential false positive."
            )
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def validate_control_tests_cover_requirements(self) -> "VulnerabilityEvidence":
        """Ensure control tests cover type-specific requirements."""
        type_spec = get_vulnerability_type_spec(self.vulnerability_type)
        if type_spec is None:
            return self  # Type validation will catch invalid types

        # Get required control test names for this type
        required_tests = {req.name for req in type_spec.control_test_requirements}
        performed_tests = {test.test_name for test in self.reporter_control_tests}

        # Check all required tests were performed
        missing = required_tests - performed_tests
        if missing:
            msg = (
                f"Missing required control tests for {self.vulnerability_type}: "
                f"{', '.join(sorted(missing))}. "
                f"Each vulnerability type requires specific control tests to validate the claim."
            )
            raise ValueError(msg)

        # Check all control tests concluded as vulnerable
        for test in self.reporter_control_tests:
            if test.conclusion != "vulnerable":
                msg = (
                    f"Control test '{test.test_name}' concluded '{test.conclusion}'. "
                    f"All control tests must conclude 'vulnerable' for a valid report. "
                    f"If a control test shows 'not_vulnerable', this is a false positive."
                )
                raise ValueError(msg)

        return self


def validate_evidence(
    evidence_dict: dict[str, Any],
) -> tuple[VulnerabilityEvidence | None, str | None]:
    """Validate evidence dictionary against the VulnerabilityEvidence model.

    Args:
        evidence_dict: Dictionary containing evidence data

    Returns:
        Tuple of (validated_evidence, error_message)
        - If valid: (VulnerabilityEvidence instance, None)
        - If invalid: (None, error description string)
    """
    try:
        validated = VulnerabilityEvidence.model_validate(evidence_dict)
    except Exception as e:  # noqa: BLE001
        return None, f"Evidence validation failed: {e!s}"
    else:
        return validated, None


def evidence_to_dict(evidence: VulnerabilityEvidence) -> dict[str, Any]:
    """Convert VulnerabilityEvidence to dictionary for storage.

    Args:
        evidence: Validated VulnerabilityEvidence instance

    Returns:
        Dictionary representation suitable for JSON serialization
    """
    return evidence.model_dump(mode="json")
