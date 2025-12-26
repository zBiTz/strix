"""Verification tools for confirming or rejecting vulnerability reports.

This module provides tools for verification agents to submit their
decisions on pending vulnerability reports.

Implements TWO-PHASE VERIFICATION enforcement:
- Phase 1: Reproducibility - Can we reproduce the reported behavior?
- Phase 2: Validity - Does this behavior actually prove the vulnerability?

Reports cannot be verified without completing BOTH phases and providing
independent control test evidence for Phase 2.
"""

from typing import Any

from strix.tools.registry import register_tool
from strix.tools.reporting.vulnerability_types import get_vulnerability_type_spec


def _normalize_test_name(name: str) -> str:
    """Normalize test name for flexible matching.

    Converts to lowercase, replaces spaces/hyphens with underscores,
    and strips whitespace. This allows matching between different naming
    conventions used in prompts and validation.

    Examples:
        "AUTHORIZATION BOUNDARY TEST" -> "authorization_boundary_test"
        "authorization-boundary-test" -> "authorization_boundary_test"
        "Authorization Boundary Test" -> "authorization_boundary_test"
    """
    return name.lower().replace(" ", "_").replace("-", "_").strip()


def _validate_two_phase_evidence(
    verification_evidence: dict[str, Any] | None,
    vulnerability_type: str | None,
) -> tuple[bool, str | None]:
    """Validate that verification evidence includes proper two-phase verification.

    Args:
        verification_evidence: The evidence provided by the verification agent
        vulnerability_type: The vulnerability type from the original report

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not verification_evidence:
        return False, "Verification evidence is required when verified=True"

    # Check Phase 1 evidence
    phase1 = verification_evidence.get("phase1_reproduction")
    if not phase1:
        return False, "Phase 1 (reproducibility) evidence is required"

    reproduction_count = phase1.get("reproduction_count", 0)
    if reproduction_count < 3:
        return (
            False,
            f"Phase 1 requires at least 3 reproductions, got {reproduction_count}",
        )

    # Check Phase 2 evidence - THIS IS CRITICAL
    phase2 = verification_evidence.get("phase2_validity")
    if not phase2:
        return (
            False,
            "Phase 2 (validity) evidence is required. Reproducibility alone is NOT sufficient.",
        )

    # Require explicit validity confirmation
    if not phase2.get("validity_confirmed"):
        return (
            False,
            "Phase 2 validity_confirmed must be true. Did you complete independent control tests?",
        )

    # Require independent control tests
    control_tests = phase2.get("independent_control_tests", [])
    if not control_tests:
        return (
            False,
            "Phase 2 requires independent_control_tests. You must design and execute your OWN control tests.",
        )

    # Validate control tests against type-specific requirements
    # Use normalized names for flexible matching (handles case/spacing differences)
    if vulnerability_type and vulnerability_type != "unknown":
        type_spec = get_vulnerability_type_spec(vulnerability_type)
        if type_spec:
            required_normalized = {
                _normalize_test_name(req.name) for req in type_spec.control_test_requirements
            }
            provided_normalized = {
                _normalize_test_name(test.get("test_name", "")) for test in control_tests
            }

            # Check if at least one required test was performed (using normalized names)
            overlap = required_normalized & provided_normalized
            if not overlap:
                return (
                    False,
                    f"Phase 2 requires control tests matching type spec. "
                    f"Required (normalized): {required_normalized}, "
                    f"Provided (normalized): {provided_normalized}",
                )

    # Require validity reasoning
    if not phase2.get("validity_reasoning"):
        return (
            False,
            "Phase 2 requires validity_reasoning explaining why this is genuinely vulnerable",
        )

    return True, None


@register_tool(sandbox_execution=False)
def verify_vulnerability_report(  # noqa: PLR0911
    report_id: str,
    verified: bool,
    verification_evidence: dict[str, Any] | None = None,
    rejection_reason: str | None = None,
    rejection_phase: str | None = None,
    notes: list[str] | None = None,
    agent_state: Any = None,
) -> dict[str, Any]:
    """Submit verification decision for a pending vulnerability report.

    This tool implements TWO-PHASE VERIFICATION:
    - Phase 1: Reproducibility check (can we reproduce the behavior?)
    - Phase 2: Validity check (does this behavior prove the vulnerability?)

    IMPORTANT: A report can only be verified if BOTH phases pass. Reproducibility
    alone is NOT sufficient - you must also validate the claim with independent
    control tests.

    Args:
        report_id: The report ID to verify (format: vuln-XXXX)
        verified: True if BOTH phases passed, False otherwise
        verification_evidence: Required if verified=True, must contain:
            - phase1_reproduction: {reproduction_count, baseline_response, exploit_response}
            - phase2_validity: {vulnerability_type, independent_control_tests, validity_confirmed, validity_reasoning}
        rejection_reason: Required if verified=False - explanation with phase info
        rejection_phase: One of "phase1_reproduction", "phase2_validity", "manual_review"
        notes: Optional additional observations from verification
        agent_state: Agent state for context

    Returns:
        Dict with success status and verification outcome
    """
    # Validate report_id
    if not report_id or not report_id.strip():
        return {"success": False, "message": "Report ID is required"}

    # Validate rejection reason if not verified
    if not verified and not rejection_reason:
        return {
            "success": False,
            "message": "Rejection reason is required when verified=False",
        }

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if not tracer:
            return {"success": False, "message": "Tracer not available"}

        # Check if report exists in pending queue
        report = tracer.get_pending_report(report_id)
        if not report:
            return {
                "success": False,
                "message": f"Report {report_id} not found in pending queue or already processed",
            }

        # Cancel the verification timeout since we're now recording a decision
        try:
            from strix.tools.reporting.reporting_actions import _cancel_verification_timeout

            _cancel_verification_timeout(report_id)
        except ImportError:
            pass

        # Increment verification attempt counter
        tracer.increment_verification_attempt(report_id)

        if verified:
            # ENFORCEMENT: Validate two-phase verification evidence
            vulnerability_type = report.get("evidence", {}).get("vulnerability_type", "unknown")
            is_valid, error_msg = _validate_two_phase_evidence(
                verification_evidence, vulnerability_type
            )
            if not is_valid:
                return {
                    "success": False,
                    "message": f"Two-phase verification failed: {error_msg}",
                    "hint": "You must complete BOTH Phase 1 (reproducibility) AND Phase 2 (validity) "
                    "with independent control tests before verifying.",
                }

            # Move to verified reports
            success = tracer.finalize_vulnerability_report(
                report_id,
                verification_evidence=verification_evidence,
                notes=notes or [],
            )

            if success:
                return {
                    "success": True,
                    "message": f"Report {report_id} verified and finalized (two-phase verification passed)",
                    "status": "verified",
                    "report_id": report_id,
                    "phases_completed": ["phase1_reproduction", "phase2_validity"],
                }
            return {
                "success": False,
                "message": f"Failed to finalize report {report_id}",
            }

        # Reject the report
        # Include phase information for better tracking
        phase_info = rejection_phase or "unspecified"
        full_reason = rejection_reason or "Verification failed"

        success = tracer.reject_vulnerability_report(
            report_id,
            reason=full_reason,
            notes=notes or [],
        )

        if not success:
            return {
                "success": False,
                "message": f"Failed to reject report {report_id}",
            }

        return {  # noqa: TRY300
            "success": True,
            "message": f"Report {report_id} rejected ({phase_info})",
            "status": "rejected",
            "report_id": report_id,
            "reason": full_reason,
            "rejection_phase": phase_info,
        }

    except ImportError:
        return {
            "success": False,
            "message": "Tracer module not available",
        }
    except (ValueError, TypeError) as e:
        return {
            "success": False,
            "message": f"Verification failed: {e!s}",
        }


@register_tool(sandbox_execution=False, parallelizable=True)
def list_pending_verifications(
    agent_state: Any = None,
) -> dict[str, Any]:
    """List all vulnerability reports pending verification.

    Returns a list of pending reports with their basic information
    to help verification agents identify what needs to be verified.

    Args:
        agent_state: Agent state for context

    Returns:
        Dict with pending reports list and count
    """
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if not tracer:
            return {
                "success": False,
                "message": "Tracer not available",
                "pending_reports": [],
                "pending_count": 0,
            }

        pending = tracer.get_pending_reports()

        # Format reports for display
        formatted_reports = [
            {
                "id": report["id"],
                "title": report["title"],
                "severity": report["severity"],
                "submitted_at": report.get("timestamp"),
                "verification_attempts": report.get("verification_attempts", 0),
            }
            for report in pending
        ]

        return {
            "success": True,
            "pending_count": len(formatted_reports),
            "pending_reports": formatted_reports,
        }

    except ImportError:
        return {
            "success": False,
            "message": "Tracer module not available",
            "pending_reports": [],
            "pending_count": 0,
        }
    except (ValueError, TypeError) as e:
        return {
            "success": False,
            "message": f"Failed to list pending reports: {e!s}",
            "pending_reports": [],
            "pending_count": 0,
        }
