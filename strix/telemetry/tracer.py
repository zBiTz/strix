import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional
from uuid import uuid4


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

_global_tracer: Optional["Tracer"] = None


def get_global_tracer() -> Optional["Tracer"]:
    return _global_tracer


def set_global_tracer(tracer: "Tracer") -> None:
    global _global_tracer  # noqa: PLW0603
    _global_tracer = tracer


class Tracer:
    def __init__(self, run_name: str | None = None):
        self.run_name = run_name
        self.run_id = run_name or f"run-{uuid4().hex[:8]}"
        self.start_time = datetime.now(UTC).isoformat()
        self.end_time: str | None = None

        self.agents: dict[str, dict[str, Any]] = {}
        self.tool_executions: dict[int, dict[str, Any]] = {}
        self.chat_messages: list[dict[str, Any]] = []

        self.vulnerability_reports: list[dict[str, Any]] = []
        self.pending_vulnerability_reports: list[dict[str, Any]] = []
        self.rejected_vulnerability_reports: list[dict[str, Any]] = []
        self.needs_manual_review_reports: list[dict[str, Any]] = []
        self.final_scan_result: str | None = None

        self.scan_results: dict[str, Any] | None = None
        self.scan_config: dict[str, Any] | None = None
        self.run_metadata: dict[str, Any] = {
            "run_id": self.run_id,
            "run_name": self.run_name,
            "start_time": self.start_time,
            "end_time": None,
            "targets": [],
            "status": "running",
        }
        self._run_dir: Path | None = None
        self._next_execution_id = 1
        self._next_message_id = 1
        self._saved_vuln_ids: set[str] = set()
        self._saved_pending_ids: set[str] = set()
        self._saved_rejected_ids: set[str] = set()
        self._saved_manual_review_ids: set[str] = set()

        self.vulnerability_found_callback: Callable[[str, str, str, str], None] | None = None

    def set_run_name(self, run_name: str) -> None:
        self.run_name = run_name
        self.run_id = run_name

    def get_run_dir(self) -> Path:
        if self._run_dir is None:
            runs_dir = Path.cwd() / "strix_runs"
            runs_dir.mkdir(exist_ok=True)

            run_dir_name = self.run_name if self.run_name else self.run_id
            self._run_dir = runs_dir / run_dir_name
            self._run_dir.mkdir(exist_ok=True)

        return self._run_dir

    def add_vulnerability_report(
        self,
        title: str,
        content: str,
        severity: str,
    ) -> str:
        report_id = f"vuln-{len(self.vulnerability_reports) + 1:04d}"

        report = {
            "id": report_id,
            "title": title.strip(),
            "content": content.strip(),
            "severity": severity.lower().strip(),
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

        self.vulnerability_reports.append(report)
        logger.info(f"Added vulnerability report: {report_id} - {title}")

        if self.vulnerability_found_callback:
            self.vulnerability_found_callback(
                report_id, title.strip(), content.strip(), severity.lower().strip()
            )

        self.save_run_data()
        return report_id

    def add_pending_vulnerability_report(
        self,
        title: str,
        content: str,
        severity: str,
        evidence: dict[str, Any],
    ) -> str:
        """Add a vulnerability report to the pending verification queue.

        Reports added here will not be finalized until verified by a verification agent.

        Args:
            title: Vulnerability title
            content: Detailed vulnerability description
            severity: Severity level (critical, high, medium, low, info)
            evidence: Structured evidence dictionary

        Returns:
            Report ID (format: vuln-XXXX)
        """
        # Use combined count for unique IDs across all report lists
        total_reports = (
            len(self.vulnerability_reports)
            + len(self.pending_vulnerability_reports)
            + len(self.rejected_vulnerability_reports)
        )
        report_id = f"vuln-{total_reports + 1:04d}"

        report = {
            "id": report_id,
            "title": title.strip(),
            "content": content.strip(),
            "severity": severity.lower().strip(),
            "evidence": evidence,
            "status": "pending_verification",
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "verification_attempts": 0,
        }

        self.pending_vulnerability_reports.append(report)
        logger.info(f"Added pending vulnerability report: {report_id} - {title}")

        self.save_run_data()
        return report_id

    def get_pending_report(self, report_id: str) -> dict[str, Any] | None:
        """Get a pending report by ID.

        Args:
            report_id: The report ID to look up

        Returns:
            The report dictionary if found, None otherwise
        """
        for report in self.pending_vulnerability_reports:
            if report["id"] == report_id:
                return report
        return None

    def get_pending_reports(self) -> list[dict[str, Any]]:
        """Get all pending verification reports.

        Returns:
            Copy of the pending reports list
        """
        return self.pending_vulnerability_reports.copy()

    def finalize_vulnerability_report(
        self,
        report_id: str,
        verification_evidence: dict[str, Any] | None = None,
        notes: list[str] | None = None,
    ) -> bool:
        """Move a pending report to verified status.

        Moves the report from pending queue to the main vulnerability_reports
        list and triggers the vulnerability_found_callback.

        Args:
            report_id: The report ID to finalize
            verification_evidence: Evidence from the verification process
            notes: Optional notes from verification

        Returns:
            True if report was found and finalized, False otherwise
        """
        for i, report in enumerate(self.pending_vulnerability_reports):
            if report["id"] == report_id:
                report["status"] = "verified"
                report["verified_at"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
                report["verification_evidence"] = verification_evidence
                report["verification_notes"] = notes or []

                # Move to main vulnerability reports
                self.vulnerability_reports.append(report)
                self.pending_vulnerability_reports.pop(i)

                logger.info(f"Finalized vulnerability report: {report_id} - {report['title']}")

                # Trigger callback if exists
                if self.vulnerability_found_callback:
                    self.vulnerability_found_callback(
                        report["id"],
                        report["title"],
                        report["content"],
                        report["severity"],
                    )

                self.save_run_data()
                return True
        return False

    def reject_vulnerability_report(
        self,
        report_id: str,
        reason: str,
        notes: list[str] | None = None,
    ) -> bool:
        """Reject a pending report as a false positive.

        Moves the report from pending queue to the rejected list.

        Args:
            report_id: The report ID to reject
            reason: Reason for rejection
            notes: Optional notes from verification

        Returns:
            True if report was found and rejected, False otherwise
        """
        for i, report in enumerate(self.pending_vulnerability_reports):
            if report["id"] == report_id:
                report["status"] = "rejected"
                report["rejection_reason"] = reason
                report["rejection_notes"] = notes or []
                report["rejected_at"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

                # Move to rejected reports
                self.rejected_vulnerability_reports.append(report)
                self.pending_vulnerability_reports.pop(i)

                logger.info(
                    f"Rejected vulnerability report: {report_id} - {report['title']} (Reason: {reason})"
                )

                self.save_run_data()
                return True
        return False

    def increment_verification_attempt(self, report_id: str) -> bool:
        """Increment the verification attempt counter for a pending report.

        Args:
            report_id: The report ID to update

        Returns:
            True if report was found and updated, False otherwise
        """
        for report in self.pending_vulnerability_reports:
            if report["id"] == report_id:
                report["verification_attempts"] = report.get("verification_attempts", 0) + 1
                return True
        return False

    def is_report_verified(self, report_id: str) -> bool:
        """Check if a report has been verified (finalized, rejected, or moved to manual review).

        A report is considered "verified" (i.e., no longer pending) if it has been
        processed by a verification agent and moved out of the pending queue.

        Args:
            report_id: The report ID to check

        Returns:
            True if report was verified/rejected/moved, False if still pending
        """
        # Return True if report is not in pending queue (i.e., it was processed)
        return all(report["id"] != report_id for report in self.pending_vulnerability_reports)

    def add_to_manual_review(
        self,
        report_id: str,
        reason: str,
        notes: list[str] | None = None,
    ) -> bool:
        """Move a pending report to manual review queue.

        Used when a verification agent fails to make a decision (e.g., hit max
        iterations, crashed, etc.). These reports require human review.

        Args:
            report_id: The report ID to move
            reason: Reason for requiring manual review
            notes: Optional notes about why manual review is needed

        Returns:
            True if report was found and moved, False otherwise
        """
        report = None
        for i, r in enumerate(self.pending_vulnerability_reports):
            if r["id"] == report_id:
                report = self.pending_vulnerability_reports.pop(i)
                break

        if not report:
            return False

        report["status"] = "needs_manual_review"
        report["review_reason"] = reason
        report["review_notes"] = notes or []
        report["moved_at"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

        self.needs_manual_review_reports.append(report)

        logger.info(
            f"Moved report to manual review: {report_id} - {report['title']} (Reason: {reason})"
        )

        self.save_run_data()
        return True

    def set_final_scan_result(
        self,
        content: str,
        success: bool = True,
    ) -> None:
        self.final_scan_result = content.strip()

        self.scan_results = {
            "scan_completed": True,
            "content": content,
            "success": success,
        }

        logger.info(f"Set final scan result: success={success}")
        self.save_run_data(mark_complete=True)

    def log_agent_creation(
        self, agent_id: str, name: str, task: str, parent_id: str | None = None
    ) -> None:
        agent_data: dict[str, Any] = {
            "id": agent_id,
            "name": name,
            "task": task,
            "status": "running",
            "parent_id": parent_id,
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
            "tool_executions": [],
        }

        self.agents[agent_id] = agent_data

    def log_chat_message(
        self,
        content: str,
        role: str,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        message_id = self._next_message_id
        self._next_message_id += 1

        message_data = {
            "message_id": message_id,
            "content": content,
            "role": role,
            "agent_id": agent_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "metadata": metadata or {},
        }

        self.chat_messages.append(message_data)
        return message_id

    def log_tool_execution_start(self, agent_id: str, tool_name: str, args: dict[str, Any]) -> int:
        execution_id = self._next_execution_id
        self._next_execution_id += 1

        now = datetime.now(UTC).isoformat()
        execution_data = {
            "execution_id": execution_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "args": args,
            "status": "running",
            "result": None,
            "timestamp": now,
            "started_at": now,
            "completed_at": None,
        }

        self.tool_executions[execution_id] = execution_data

        if agent_id in self.agents:
            self.agents[agent_id]["tool_executions"].append(execution_id)

        return execution_id

    def update_tool_execution(
        self, execution_id: int, status: str, result: Any | None = None
    ) -> None:
        if execution_id in self.tool_executions:
            self.tool_executions[execution_id]["status"] = status
            self.tool_executions[execution_id]["result"] = result
            self.tool_executions[execution_id]["completed_at"] = datetime.now(UTC).isoformat()

    def update_agent_status(
        self, agent_id: str, status: str, error_message: str | None = None
    ) -> None:
        if agent_id in self.agents:
            self.agents[agent_id]["status"] = status
            self.agents[agent_id]["updated_at"] = datetime.now(UTC).isoformat()
            if error_message:
                self.agents[agent_id]["error_message"] = error_message

    def set_scan_config(self, config: dict[str, Any]) -> None:
        self.scan_config = config
        self.run_metadata.update(
            {
                "targets": config.get("targets", []),
                "user_instructions": config.get("user_instructions", ""),
                "max_iterations": config.get("max_iterations", 200),
            }
        )
        self.get_run_dir()

    def save_run_data(self, mark_complete: bool = False) -> None:  # noqa: PLR0912, PLR0915
        try:
            run_dir = self.get_run_dir()
            if mark_complete:
                self.end_time = datetime.now(UTC).isoformat()

            if self.final_scan_result:
                penetration_test_report_file = run_dir / "penetration_test_report.md"
                with penetration_test_report_file.open("w", encoding="utf-8") as f:
                    f.write("# Security Penetration Test Report\n\n")
                    f.write(
                        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                    )
                    f.write(f"{self.final_scan_result}\n")
                logger.info(
                    f"Saved final penetration test report to: {penetration_test_report_file}"
                )

            if self.vulnerability_reports:
                vuln_dir = run_dir / "vulnerabilities"
                vuln_dir.mkdir(exist_ok=True)

                new_reports = [
                    report
                    for report in self.vulnerability_reports
                    if report["id"] not in self._saved_vuln_ids
                ]

                for report in new_reports:
                    vuln_file = vuln_dir / f"{report['id']}.md"
                    with vuln_file.open("w", encoding="utf-8") as f:
                        f.write(f"# {report['title']}\n\n")
                        f.write(f"**ID:** {report['id']}\n")
                        f.write(f"**Severity:** {report['severity'].upper()}\n")
                        f.write(f"**Found:** {report['timestamp']}\n\n")
                        f.write("## Description\n\n")
                        f.write(f"{report['content']}\n")
                    self._saved_vuln_ids.add(report["id"])

                if self.vulnerability_reports:
                    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                    sorted_reports = sorted(
                        self.vulnerability_reports,
                        key=lambda x: (severity_order.get(x["severity"], 5), x["timestamp"]),
                    )

                    vuln_csv_file = run_dir / "vulnerabilities.csv"
                    with vuln_csv_file.open("w", encoding="utf-8", newline="") as f:
                        import csv

                        fieldnames = ["id", "title", "severity", "timestamp", "file"]
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()

                        for report in sorted_reports:
                            writer.writerow(
                                {
                                    "id": report["id"],
                                    "title": report["title"],
                                    "severity": report["severity"].upper(),
                                    "timestamp": report["timestamp"],
                                    "file": f"vulnerabilities/{report['id']}.md",
                                }
                            )

                if new_reports:
                    logger.info(
                        f"Saved {len(new_reports)} new vulnerability report(s) to: {vuln_dir}"
                    )
                logger.info(f"Updated vulnerability index: {vuln_csv_file}")

            # Save pending verification reports
            if self.pending_vulnerability_reports:
                pending_dir = run_dir / "pending_verifications"
                pending_dir.mkdir(exist_ok=True)

                import json

                new_pending = [
                    report
                    for report in self.pending_vulnerability_reports
                    if report["id"] not in self._saved_pending_ids
                ]

                for report in new_pending:
                    pending_file = pending_dir / f"{report['id']}.json"
                    with pending_file.open("w", encoding="utf-8") as f:
                        json.dump(report, f, indent=2)
                    self._saved_pending_ids.add(report["id"])

                if new_pending:
                    logger.info(
                        f"Saved {len(new_pending)} pending verification report(s) to: {pending_dir}"
                    )

            # Save rejected reports (false positives)
            if self.rejected_vulnerability_reports:
                rejected_dir = run_dir / "rejected_false_positives"
                rejected_dir.mkdir(exist_ok=True)

                import json

                new_rejected = [
                    report
                    for report in self.rejected_vulnerability_reports
                    if report["id"] not in self._saved_rejected_ids
                ]

                for report in new_rejected:
                    rejected_file = rejected_dir / f"{report['id']}.json"
                    with rejected_file.open("w", encoding="utf-8") as f:
                        json.dump(report, f, indent=2)
                    self._saved_rejected_ids.add(report["id"])

                if new_rejected:
                    logger.info(f"Saved {len(new_rejected)} rejected report(s) to: {rejected_dir}")

            # Save manual review reports (auto-rejected due to verification agent failure)
            if self.needs_manual_review_reports:
                manual_review_dir = run_dir / "needs_manual_review"
                manual_review_dir.mkdir(exist_ok=True)

                import json

                new_manual_review = [
                    report
                    for report in self.needs_manual_review_reports
                    if report["id"] not in self._saved_manual_review_ids
                ]

                for report in new_manual_review:
                    review_file = manual_review_dir / f"{report['id']}.json"
                    with review_file.open("w", encoding="utf-8") as f:
                        json.dump(report, f, indent=2)
                    self._saved_manual_review_ids.add(report["id"])

                if new_manual_review:
                    logger.info(
                        f"Saved {len(new_manual_review)} report(s) requiring manual review to: {manual_review_dir}"
                    )

            logger.info(f"📊 Essential scan data saved to: {run_dir}")

        except (OSError, RuntimeError):
            logger.exception("Failed to save scan data")

    def _calculate_duration(self) -> float:
        try:
            start = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
            if self.end_time:
                end = datetime.fromisoformat(self.end_time.replace("Z", "+00:00"))
                return (end - start).total_seconds()
        except (ValueError, TypeError):
            pass
        return 0.0

    def get_agent_tools(self, agent_id: str) -> list[dict[str, Any]]:
        return [
            exec_data
            for exec_data in list(self.tool_executions.values())
            if exec_data.get("agent_id") == agent_id
        ]

    def get_real_tool_count(self) -> int:
        return sum(
            1
            for exec_data in list(self.tool_executions.values())
            if exec_data.get("tool_name") not in ["scan_start_info", "subagent_start_info"]
        )

    def get_total_llm_stats(self) -> dict[str, Any]:
        from strix.tools.agents_graph.agents_graph_actions import _agent_instances

        total_stats = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
            "cache_creation_tokens": 0,
            "cost": 0.0,
            "requests": 0,
            "failed_requests": 0,
        }

        for agent_instance in _agent_instances.values():
            if hasattr(agent_instance, "llm") and hasattr(agent_instance.llm, "_total_stats"):
                agent_stats = agent_instance.llm._total_stats
                total_stats["input_tokens"] += agent_stats.input_tokens
                total_stats["output_tokens"] += agent_stats.output_tokens
                total_stats["cached_tokens"] += agent_stats.cached_tokens
                total_stats["cache_creation_tokens"] += agent_stats.cache_creation_tokens
                total_stats["cost"] += agent_stats.cost
                total_stats["requests"] += agent_stats.requests
                total_stats["failed_requests"] += agent_stats.failed_requests

        total_stats["cost"] = round(total_stats["cost"], 4)

        return {
            "total": total_stats,
            "total_tokens": total_stats["input_tokens"] + total_stats["output_tokens"],
        }

    def cleanup(self) -> None:
        """Clean up all agents and save run data.

        This method first stops all running agents and waits for their threads
        to complete, then saves the run data to disk.
        """
        # Stop all agents first
        try:
            from strix.tools.agents_graph.agents_graph_actions import cleanup_all_agents

            cleanup_all_agents(timeout=5.0)
        except ImportError:
            pass

        self.save_run_data(mark_complete=True)
