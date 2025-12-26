"""Vulnerability reporting tools for Strix agents.

This module provides tools for creating vulnerability reports with mandatory
structured evidence to eliminate false positives.

Reports require:
1. A valid vulnerability_type from the type registry
2. A claim_assertion describing the specific security claim
3. At least one reporter_control_test demonstrating the vulnerability
4. Proper negative_control_passed and description

These requirements enable two-phase verification where the verification agent
can independently validate the security claim.
"""

import logging
import threading
from typing import Any

from strix.tools.registry import register_tool
from strix.tools.reporting.evidence import validate_evidence
from strix.tools.reporting.vulnerability_types import (
    get_all_type_ids,
    validate_vulnerability_type,
)


logger = logging.getLogger(__name__)

# Verification timeout tracking (Phase 2 fix)
_verification_timeouts: dict[str, threading.Timer] = {}
_verification_timeouts_lock = threading.Lock()


def _register_verification_timeout(
    report_id: str,
    agent_id: str,
    timeout_seconds: int,
    thread: threading.Thread,
) -> None:
    """Register a timeout to auto-reject if verification agent hangs.

    If the verification agent is still running after timeout_seconds,
    the report will be moved to manual review.

    Args:
        report_id: The report ID being verified
        agent_id: The verification agent ID
        timeout_seconds: Seconds to wait before auto-rejecting
        thread: The thread running the verification agent
    """

    def timeout_handler() -> None:
        if thread.is_alive():
            # Agent still running after timeout - force cleanup
            logger.warning(
                f"Verification agent {agent_id} for report {report_id} timed out after {timeout_seconds} seconds. Moving to manual review."
            )
            _auto_reject_pending_report(report_id, agent_id, "verification_timeout")
            _update_verification_agent_status(agent_id, "timeout")

        with _verification_timeouts_lock:
            _verification_timeouts.pop(report_id, None)

    timer = threading.Timer(timeout_seconds, timeout_handler)
    timer.daemon = True
    timer.start()

    with _verification_timeouts_lock:
        _verification_timeouts[report_id] = timer


def _cancel_verification_timeout(report_id: str) -> None:
    """Cancel timeout when verification completes normally.

    Args:
        report_id: The report ID whose timeout should be cancelled
    """
    with _verification_timeouts_lock:
        timer = _verification_timeouts.pop(report_id, None)
        if timer:
            timer.cancel()


def _spawn_verification_agent(  # noqa: PLR0912, PLR0915
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

        # Inherit sandbox from parent (Issue 9 fix)
        if parent_agent_state:
            if hasattr(parent_agent_state, "sandbox_id") and parent_agent_state.sandbox_id:
                state.sandbox_id = parent_agent_state.sandbox_id
            if hasattr(parent_agent_state, "sandbox_token") and parent_agent_state.sandbox_token:
                state.sandbox_token = parent_agent_state.sandbox_token
            if hasattr(parent_agent_state, "sandbox_info") and parent_agent_state.sandbox_info:
                state.sandbox_info = parent_agent_state.sandbox_info

        # Inherit LLM config from parent (Issue 8 fix)
        llm_config = None
        if parent_agent_state and hasattr(parent_agent_state, "agent_id"):
            try:
                from strix.llm.config import LLMConfig
                from strix.tools.agents_graph.agents_graph_actions import _agent_instances

                parent_agent = _agent_instances.get(parent_agent_state.agent_id)
                if parent_agent and hasattr(parent_agent, "llm_config"):
                    parent_config = parent_agent.llm_config
                    # Create new config with verification module but inherited timeout/scan_mode
                    llm_config = LLMConfig(
                        prompt_modules=["verification"],
                        timeout=getattr(parent_config, "timeout", None),
                        scan_mode=getattr(parent_config, "scan_mode", "standard"),
                    )
            except ImportError:
                pass

        # Create verification agent config
        agent_config = {
            "state": state,
            "report_id": report_id,
            "evidence": evidence,
        }
        if llm_config:
            agent_config["llm_config"] = llm_config

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
                            f"Verification agent for {report_id} completed without recording verification decision. Moving to manual review."
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

        # Register the running thread BEFORE starting to avoid race condition
        try:
            from strix.tools.agents_graph.agents_graph_actions import (
                _running_agents as running,
            )

            running[state.agent_id] = thread
        except ImportError:
            pass

        thread.start()

        # Register verification timeout (10 minutes = 600 seconds)
        _register_verification_timeout(
            report_id=report_id,
            agent_id=state.agent_id,
            timeout_seconds=600,
            thread=thread,
        )

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
                f"Verification agent {agent_id} reached maximum iterations without recording a verification decision. Report requires manual review."
            ),
            "agent_exception": (
                f"Verification agent {agent_id} encountered an error during verification. Report requires manual review."
            ),
            "verification_timeout": (
                f"Verification agent {agent_id} timed out after 600 seconds without completing verification. Report requires manual review."
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
                "vulnerability_type, claim_assertion, primary_evidence (HTTP request/response pairs), "
                "reproduction_steps, poc_payload, target_url, negative_control_passed, "
                "negative_control_description, and reporter_control_tests."
            ),
        }

    # Validate vulnerability_type first (required for two-phase verification)
    vuln_type = evidence.get("vulnerability_type")
    if not vuln_type:
        all_types = get_all_type_ids()
        return {
            "success": False,
            "message": (
                f"vulnerability_type is required. Specify the type of vulnerability from the registry. Valid types: {', '.join(sorted(all_types))}"
            ),
        }

    type_valid, type_error = validate_vulnerability_type(vuln_type)
    if not type_valid:
        return {
            "success": False,
            "message": f"Invalid vulnerability_type: {type_error}",
        }

    # Validate claim_assertion (required for validity checking)
    claim = evidence.get("claim_assertion")
    if not claim or len(claim.strip()) < 20:
        return {
            "success": False,
            "message": (
                "claim_assertion is required and must be at least 20 characters. "
                "Describe the specific security claim being made (e.g., "
                "'Path traversal bypasses directory restriction to access protected files')."
            ),
        }

    # Validate negative control was performed
    if not evidence.get("negative_control_passed"):
        return {
            "success": False,
            "message": (
                "negative_control_passed must be True. You must perform a negative control test "
                "that confirms unauthorized access is denied before reporting a vulnerability."
            ),
        }

    # Validate reporter_control_tests
    control_tests = evidence.get("reporter_control_tests", [])
    if not control_tests:
        return {
            "success": False,
            "message": (
                "reporter_control_tests is required. You must include at least one control test "
                "that demonstrates the vulnerability (e.g., testing direct access vs traversal access)."
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
