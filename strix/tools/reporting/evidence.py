"""Structured evidence models for vulnerability reports.

This module defines Pydantic models that enforce structured evidence
requirements for vulnerability reports, helping to eliminate false positives
by requiring concrete proof of exploitation.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator


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


class VulnerabilityEvidence(BaseModel):
    """Complete evidence package for a vulnerability report.

    This model enforces structured evidence requirements to ensure
    vulnerability reports have concrete proof of exploitation.
    Reports without proper evidence cannot be submitted.
    """

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
    negative_control_passed: bool = Field(
        default=False,
        description="Whether unauthorized access was correctly denied in control test",
    )
    negative_control_description: str | None = Field(
        default=None,
        description="Description of the negative control test performed",
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
