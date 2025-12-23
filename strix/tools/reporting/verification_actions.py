"""Verification tools for confirming or rejecting vulnerability reports.

This module provides tools for verification agents to submit their
decisions on pending vulnerability reports.
"""

from typing import Any

from strix.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def verify_vulnerability_report(  # noqa: PLR0911
    report_id: str,
    verified: bool,
    verification_evidence: dict[str, Any] | None = None,
    rejection_reason: str | None = None,
    notes: list[str] | None = None,
    agent_state: Any = None,
) -> dict[str, Any]:
    """Submit verification decision for a pending vulnerability report.

    This tool is used by verification agents to mark a pending report as
    verified (moving it to final reports) or rejected (marking as false positive).

    Args:
        report_id: The report ID to verify (format: vuln-XXXX)
        verified: True if vulnerability was successfully reproduced, False otherwise
        verification_evidence: Evidence from verification if verified, containing:
            - reproduction_count: Number of successful reproductions
            - baseline_response: Normal behavior observed
            - exploit_response: Exploit behavior observed
            - negative_control: Unauthorized access test result
        rejection_reason: Required if verified=False - explanation of rejection
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

        # Increment verification attempt counter
        tracer.increment_verification_attempt(report_id)

        if verified:
            # Move to verified reports
            success = tracer.finalize_vulnerability_report(
                report_id,
                verification_evidence=verification_evidence,
                notes=notes or [],
            )

            if success:
                return {
                    "success": True,
                    "message": f"Report {report_id} verified and finalized",
                    "status": "verified",
                    "report_id": report_id,
                }
            return {
                "success": False,
                "message": f"Failed to finalize report {report_id}",
            }

        # Reject the report
        success = tracer.reject_vulnerability_report(
            report_id,
            reason=rejection_reason or "Verification failed",
            notes=notes or [],
        )

        if not success:
            return {
                "success": False,
                "message": f"Failed to reject report {report_id}",
            }

        return {  # noqa: TRY300
            "success": True,
            "message": f"Report {report_id} rejected as false positive",
            "status": "rejected",
            "report_id": report_id,
            "reason": rejection_reason,
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
