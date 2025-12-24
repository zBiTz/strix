from typing import Any

from strix.tools.registry import register_tool


def _validate_root_agent(agent_state: Any) -> dict[str, Any] | None:
    if (
        agent_state is not None
        and hasattr(agent_state, "parent_id")
        and agent_state.parent_id is not None
    ):
        return {
            "success": False,
            "message": (
                "This tool can only be used by the root/main agent. Subagents must use agent_finish instead."
            ),
        }
    return None


def _validate_content(content: str) -> dict[str, Any] | None:
    if not content or not content.strip():
        return {"success": False, "message": "Content cannot be empty"}
    return None


def _check_active_agents(agent_state: Any = None) -> dict[str, Any] | None:
    try:
        from strix.tools.agents_graph.agents_graph_actions import _agent_graph

        current_agent_id = None
        if agent_state and hasattr(agent_state, "agent_id"):
            current_agent_id = agent_state.agent_id

        running_agents = []
        stopping_agents = []

        for agent_id, node in _agent_graph.get("nodes", {}).items():
            if agent_id == current_agent_id:
                continue

            status = node.get("status", "")
            if status == "running":
                running_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                        "task": node.get("task", "No task description"),
                    }
                )
            elif status == "stopping":
                stopping_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                    }
                )

        if running_agents or stopping_agents:
            message_parts = ["Cannot finish scan while other agents are still active:"]

            if running_agents:
                message_parts.append("\n\nRunning agents:")
                message_parts.extend(
                    [
                        f"  - {agent['name']} ({agent['id']}): {agent['task']}"
                        for agent in running_agents
                    ]
                )

            if stopping_agents:
                message_parts.append("\n\nStopping agents:")
                message_parts.extend(
                    [f"  - {agent['name']} ({agent['id']})" for agent in stopping_agents]
                )

            message_parts.extend(
                [
                    "\n\nSuggested actions:",
                    "1. Use wait_for_message to wait for all agents to complete",
                    "2. Send messages to agents asking them to finish if urgent",
                    "3. Use view_agent_graph to monitor agent status",
                ]
            )

            return {
                "success": False,
                "message": "\n".join(message_parts),
                "active_agents": {
                    "running": len(running_agents),
                    "stopping": len(stopping_agents),
                    "details": {
                        "running": running_agents,
                        "stopping": stopping_agents,
                    },
                },
            }

    except ImportError:
        import logging

        logging.warning("Could not check agent graph status - agents_graph module unavailable")

    return None


def _check_pending_verifications(agent_state: Any = None) -> dict[str, Any] | None:
    """Check if there are pending vulnerability reports awaiting verification.

    Returns an error dict if pending verifications exist, None otherwise.
    """
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if not tracer:
            return None

        pending_reports = tracer.get_pending_reports()
        if not pending_reports:
            return None

        message_parts = [
            "Cannot finish scan while vulnerability reports are pending verification:",
            f"\n\nPending verifications: {len(pending_reports)}",
        ]

        for report in pending_reports[:5]:  # Show first 5
            report_id = report.get("report_id", "unknown")
            title = report.get("title", "Unknown vulnerability")
            severity = report.get("severity", "unknown")
            attempts = report.get("verification_attempts", 0)
            line = f"  - [{severity.upper()}] {title} (ID: {report_id}, attempts: {attempts})"
            message_parts.append(line)

        if len(pending_reports) > 5:
            message_parts.append(f"  ... and {len(pending_reports) - 5} more")

        message_parts.extend(
            [
                "\n\nRequired actions:",
                "1. Wait for verification agents to complete their verification",
                "2. Use list_pending_verifications to check status",
                "3. Verification agents call verify_vulnerability_report to finalize/reject",
                "\n\nNote: Only VERIFIED findings will be included in the final report.",
                "Rejected findings will be saved separately for review.",
            ]
        )

        return {
            "success": False,
            "message": "\n".join(message_parts),
            "pending_verifications": {
                "count": len(pending_reports),
                "reports": [
                    {
                        "report_id": r.get("report_id"),
                        "title": r.get("title"),
                        "severity": r.get("severity"),
                        "verification_attempts": r.get("verification_attempts", 0),
                    }
                    for r in pending_reports
                ],
            },
        }

    except ImportError:
        import logging

        logging.warning("Could not check pending verifications - tracer module unavailable")

    return None


def _finalize_with_tracer(content: str, success: bool) -> dict[str, Any]:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            tracer.set_final_scan_result(
                content=content.strip(),
                success=success,
            )

            # Get counts for verified (finalized) and rejected reports
            verified_count = len(tracer.vulnerability_reports)
            rejected_count = len(tracer.rejected_vulnerability_reports)

            result = {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed successfully"
                if success
                else "Scan completed with errors",
                "vulnerabilities_found": verified_count,
            }

            # Add rejected count if any were rejected
            if rejected_count > 0:
                result["false_positives_rejected"] = rejected_count
                result["note"] = (
                    f"{rejected_count} potential finding(s) were rejected during verification. See rejected_false_positives/ directory for details."
                )

            return result

        import logging

        logging.warning("Global tracer not available - final scan result not stored")

        return {  # noqa: TRY300
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully (not persisted)"
            if success
            else "Scan completed with errors (not persisted)",
            "warning": "Final result could not be persisted - tracer unavailable",
        }

    except ImportError:
        return {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully (not persisted)"
            if success
            else "Scan completed with errors (not persisted)",
            "warning": "Final result could not be persisted - tracer module unavailable",
        }


@register_tool(sandbox_execution=False)
def finish_scan(
    content: str,
    success: bool = True,
    agent_state: Any = None,
) -> dict[str, Any]:
    try:
        validation_error = _validate_root_agent(agent_state)
        if validation_error:
            return validation_error

        validation_error = _validate_content(content)
        if validation_error:
            return validation_error

        active_agents_error = _check_active_agents(agent_state)
        if active_agents_error:
            return active_agents_error

        pending_verifications_error = _check_pending_verifications(agent_state)
        if pending_verifications_error:
            return pending_verifications_error

        return _finalize_with_tracer(content, success)

    except (ValueError, TypeError, KeyError) as e:
        return {"success": False, "message": f"Failed to complete scan: {e!s}"}
