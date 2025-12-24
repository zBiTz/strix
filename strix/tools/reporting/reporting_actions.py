"""Vulnerability reporting tools for Strix agents.

This module provides tools for creating vulnerability reports with mandatory
structured evidence to eliminate false positives.
"""

import logging
import threading
from typing import Any

from strix.tools.registry import register_tool
from strix.tools.reporting.evidence import validate_evidence


logger = logging.getLogger(__name__)


def _spawn_verification_agent(  # noqa: PLR0915
    report_id: str,
    title: str,
    evidence: dict[str, Any],
    parent_agent_state: Any | None = None,
) -> dict[str, Any]:
    """Spawn a verification agent to verify a pending vulnerability report.

    Args:
        report_id: The report ID to verify
        title: Title of the vulnerability report
        evidence: The evidence to verify
        parent_agent_state: Optional parent agent state for context

    Returns:
        Dict with spawn status and agent info
    """
    try:
        from datetime import UTC, datetime

        from strix.agents.state import AgentState
        from strix.agents.VerificationAgent import VerificationAgent

        # Create verification agent state
        task = (
            f"Verify vulnerability report '{title}' (ID: {report_id}). "
            "Reproduce the vulnerability using the provided evidence and "
            "confirm or reject the finding."
        )

        parent_id = None
        if parent_agent_state and hasattr(parent_agent_state, "agent_id"):
            parent_id = parent_agent_state.agent_id

        state = AgentState(
            task=task,
            agent_name=f"Verifier-{report_id}",
            parent_id=parent_id,
            max_iterations=50,
        )

        # Create verification agent config
        agent_config = {
            "state": state,
            "report_id": report_id,
            "evidence": evidence,
        }

        agent = VerificationAgent(agent_config)

        # Register with agent graph for visibility
        try:
            from strix.tools.agents_graph.agents_graph_actions import (
                _agent_graph,
                _agent_instances,
            )

            _agent_graph["nodes"][state.agent_id] = {
                "name": state.agent_name,
                "task": task,
                "status": "running",
                "created_at": datetime.now(UTC).isoformat(),
                "parent_id": parent_id,
                "type": "verification",
                "report_id": report_id,
            }

            if parent_id:
                _agent_graph["edges"].append(
                    {
                        "from": parent_id,
                        "to": state.agent_id,
                        "type": "spawned_verification",
                        "created_at": datetime.now(UTC).isoformat(),
                    }
                )

            _agent_instances[state.agent_id] = agent
        except ImportError:
            logger.debug("Agent graph not available - verification agent not registered")

        # Run verification in background thread
        def run_verification() -> None:
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(agent.verify_vulnerability(report_id, title, evidence))

                # Check if verification was actually recorded
                try:
                    from strix.telemetry.tracer import get_global_tracer

                    tracer = get_global_tracer()
                    if tracer and not tracer.is_report_verified(report_id):
                        # Agent completed but didn't record verification - move to manual review
                        logger.warning(
                            f"Verification agent for {report_id} completed without recording "
                            "verification decision. Moving to manual review."
                        )
                        _auto_reject_pending_report(
                            report_id, state.agent_id, "max_iterations_without_decision"
                        )
                        _update_verification_agent_status(
                            state.agent_id, "completed_without_verification"
                        )
                    else:
                        _update_verification_agent_status(state.agent_id, "completed")
                except ImportError:
                    # If tracer not available, assume completed
                    _update_verification_agent_status(state.agent_id, "completed")

            except Exception:
                logger.exception(f"Verification agent failed for {report_id}")
                # Auto-reject on exception too
                _auto_reject_pending_report(report_id, state.agent_id, "agent_exception")
                _update_verification_agent_status(state.agent_id, "failed")
            finally:
                loop.close()
                # Clean up running agents
                try:
                    from strix.tools.agents_graph.agents_graph_actions import (
                        _running_agents as running,
                    )

                    running.pop(state.agent_id, None)
                except ImportError:
                    pass

        thread = threading.Thread(
            target=run_verification,
            daemon=True,
            name=f"Verification-{report_id}",
        )
        thread.start()

        # Register the running thread
        try:
            from strix.tools.agents_graph.agents_graph_actions import (
                _running_agents as running,
            )

            running[state.agent_id] = thread
        except ImportError:
            pass

        return {  # noqa: TRY300
            "spawned": True,
            "agent_id": state.agent_id,
            "agent_name": state.agent_name,
        }

    except ImportError as e:
        logger.warning(f"Could not spawn verification agent: {e}")
        return {"spawned": False, "error": f"VerificationAgent not available: {e}"}
    except Exception as e:
        logger.exception("Failed to spawn verification agent")
        return {"spawned": False, "error": str(e)}


def _update_verification_agent_status(agent_id: str, status: str) -> None:
    """Update the verification agent status in the agent graph.

    Args:
        agent_id: The agent ID to update
        status: New status (completed, failed, etc.)
    """
    try:
        from datetime import UTC, datetime

        from strix.tools.agents_graph.agents_graph_actions import (
            _agent_graph,
            _agent_instances,
        )

        if agent_id in _agent_graph["nodes"]:
            _agent_graph["nodes"][agent_id]["status"] = status
            _agent_graph["nodes"][agent_id]["finished_at"] = datetime.now(UTC).isoformat()

        # Clean up instance reference
        _agent_instances.pop(agent_id, None)

    except ImportError:
        pass
    except (KeyError, AttributeError) as e:
        logger.debug(f"Failed to update verification agent status: {e}")


def _auto_reject_pending_report(report_id: str, agent_id: str, reason_code: str) -> None:
    """Move a pending report to manual review when verification agent fails to decide.

    This is called when a verification agent completes without calling
    verify_vulnerability_report (e.g., hit max iterations, crashed, etc.).

    Args:
        report_id: The report ID to move to manual review
        agent_id: The verification agent ID that failed to verify
        reason_code: Code indicating why auto-rejection occurred:
            - "max_iterations_without_decision": Agent hit iteration limit
            - "agent_exception": Agent crashed with exception
    """
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if not tracer:
            logger.warning(f"Cannot move {report_id} to manual review: tracer not available")
            return

        # Check if report is still pending
        if not tracer.get_pending_report(report_id):
            logger.debug(f"Report {report_id} already processed, skipping auto-reject")
            return

        reason_messages = {
            "max_iterations_without_decision": (
                f"Verification agent {agent_id} reached maximum iterations without "
                "recording a verification decision. Report requires manual review."
            ),
            "agent_exception": (
                f"Verification agent {agent_id} encountered an error during verification. "
                "Report requires manual review."
            ),
        }

        reason = reason_messages.get(reason_code, f"Auto-rejected: {reason_code}")

        success = tracer.add_to_manual_review(
            report_id,
            reason=reason,
            notes=[
                f"Auto-rejected due to verification agent failure: {reason_code}",
                f"Agent ID: {agent_id}",
                "This finding requires manual review to confirm or reject",
            ],
        )

        if success:
            logger.info(f"Moved pending report {report_id} to manual review due to {reason_code}")
        else:
            logger.warning(f"Failed to move report {report_id} to manual review")

    except ImportError:
        logger.warning(f"Cannot move {report_id} to manual review: tracer module not available")
    except Exception:
        logger.exception(f"Failed to move report {report_id} to manual review")


@register_tool(sandbox_execution=False)
def create_vulnerability_report(  # noqa: PLR0911, PLR0912
    title: str,
    content: str,
    severity: str,
    evidence: dict[str, Any],
    agent_state: Any = None,
) -> dict[str, Any]:
    """Create a vulnerability report with mandatory structured evidence.

    Reports are added to a pending verification queue and must be verified
    before becoming final. This eliminates false positives by requiring
    concrete proof of exploitation.

    Args:
        title: Clear title of the vulnerability
        content: Detailed vulnerability description including impact and remediation
        severity: Severity level (critical, high, medium, low, info)
        evidence: Structured evidence object containing:
            - primary_evidence: List of HTTP request/response pairs
            - reproduction_steps: Step-by-step instructions
            - poc_payload: The exploit payload used
            - target_url: Affected URL
            - affected_parameter: Vulnerable parameter (optional)
            - baseline_state: State before exploitation (optional)
            - exploited_state: State after exploitation (optional)
        agent_state: Agent state for context (optional)

    Returns:
        Dict with success status, report_id, and verification status
    """
    # Validate required string fields
    validation_error = None
    if not title or not title.strip():
        validation_error = "Title cannot be empty"
    elif not content or not content.strip():
        validation_error = "Content cannot be empty"
    elif not severity or not severity.strip():
        validation_error = "Severity cannot be empty"
    else:
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if severity.lower() not in valid_severities:
            validation_error = (
                f"Invalid severity '{severity}'. Must be one of: {', '.join(valid_severities)}"
            )

    if validation_error:
        return {"success": False, "message": validation_error}

    # Validate evidence structure
    if not evidence:
        return {
            "success": False,
            "message": (
                "Evidence is required. You must provide structured evidence including: "
                "primary_evidence (HTTP request/response pairs), reproduction_steps, "
                "poc_payload, and target_url."
            ),
        }

    validated_evidence, evidence_error = validate_evidence(evidence)
    if evidence_error:
        return {
            "success": False,
            "message": f"Evidence validation failed: {evidence_error}",
        }

    # Store as pending report for verification
    try:
        from strix.telemetry.tracer import get_global_tracer
        from strix.tools.reporting.evidence import evidence_to_dict

        tracer = get_global_tracer()
        if tracer:
            # Convert validated evidence to dict for storage
            evidence_dict = evidence_to_dict(validated_evidence)

            report_id = tracer.add_pending_vulnerability_report(
                title=title,
                content=content,
                severity=severity,
                evidence=evidence_dict,
            )

            # Spawn verification agent to verify the report
            spawn_result = _spawn_verification_agent(
                report_id=report_id,
                title=title,
                evidence=evidence_dict,
                parent_agent_state=agent_state,
            )

            response = {
                "success": True,
                "message": (
                    f"Vulnerability report '{title}' submitted for verification. "
                    "Report will be finalized after verification agent confirms exploitation."
                ),
                "report_id": report_id,
                "severity": severity.lower(),
                "status": "pending_verification",
            }

            if spawn_result.get("spawned"):
                response["verification_agent"] = {
                    "spawned": True,
                    "agent_id": spawn_result.get("agent_id"),
                    "agent_name": spawn_result.get("agent_name"),
                }
            else:
                response["verification_agent"] = {
                    "spawned": False,
                    "note": "Manual verification required",
                    "error": spawn_result.get("error"),
                }

            return response

        import logging

        logging.warning("Global tracer not available - vulnerability report not stored")

        return {  # noqa: TRY300
            "success": True,
            "message": f"Report '{title}' created (not persisted - tracer unavailable)",
            "warning": "Report could not be persisted - tracer unavailable",
            "status": "pending_verification",
        }

    except ImportError:
        return {
            "success": True,
            "message": f"Report '{title}' created (not persisted - module unavailable)",
            "warning": "Report could not be persisted - tracer module unavailable",
            "status": "pending_verification",
        }
    except (ValueError, TypeError) as e:
        return {"success": False, "message": f"Failed to create vulnerability report: {e!s}"}
