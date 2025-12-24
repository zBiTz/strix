"""Verification Agent for reproducing and validating vulnerability reports.

This agent is specialized for verification tasks - it attempts to reproduce
reported vulnerabilities using the provided evidence and marks reports as
verified or rejected based on the results.
"""

from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig


class VerificationAgent(BaseAgent):
    """Agent specialized for vulnerability verification.

    The VerificationAgent has a limited iteration count (50) and uses
    a specialized prompt module focused on reproduction and validation.
    It does not create new vulnerability reports - only verifies existing ones.
    """

    max_iterations = 50  # Limited iterations for verification tasks

    def __init__(self, config: dict[str, Any]):
        """Initialize the verification agent.

        Args:
            config: Agent configuration containing:
                - state: AgentState for tracking
                - llm_config: Optional LLM configuration (defaults to verification module)
        """
        # Always use verification prompt module
        self.default_llm_config = LLMConfig(prompt_modules=["verification"])
        super().__init__(config)

    async def verify_vulnerability(
        self,
        report_id: str,
        title: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        """Attempt to reproduce and verify a vulnerability.

        Args:
            report_id: The ID of the report to verify
            title: Title of the vulnerability
            evidence: Structured evidence from the original report containing:
                - primary_evidence: HTTP request/response pairs
                - reproduction_steps: Steps to reproduce
                - poc_payload: The exploit payload
                - target_url: Affected URL
                - affected_parameter: Vulnerable parameter

        Returns:
            Result dict with verification outcome
        """
        task = self._build_verification_task(report_id, title, evidence)
        return await self.agent_loop(task=task)

    def _build_verification_task(
        self,
        report_id: str,
        title: str,
        evidence: dict[str, Any],
    ) -> str:
        """Build the verification task description.

        Args:
            report_id: Report identifier
            title: Vulnerability title
            evidence: Evidence dictionary

        Returns:
            Formatted task string for the agent
        """
        # Extract key evidence components
        primary_evidence = evidence.get("primary_evidence", [])
        reproduction_steps = evidence.get("reproduction_steps", [])
        poc_payload = evidence.get("poc_payload", "")
        target_url = evidence.get("target_url", "")
        affected_parameter = evidence.get("affected_parameter", "")
        baseline_state = evidence.get("baseline_state", "")
        exploited_state = evidence.get("exploited_state", "")

        # Format HTTP evidence
        http_evidence_text = ""
        for i, ev in enumerate(primary_evidence, 1):
            http_evidence_text += f"""
### HTTP Evidence #{i}
**Request:** {ev.get("method", "GET")} {ev.get("url", "")}
**Request Body:** {ev.get("request_body", "N/A")[:500]}
**Response Status:** {ev.get("response_status", "N/A")}
**Response Body Snippet:** {ev.get("response_body_snippet", "")[:500]}
"""

        # Format reproduction steps
        steps_text = ""
        for step in reproduction_steps:
            steps_text += f"""
{step.get("step_number", "?")}. {step.get("description", "")}
   - Tool: {step.get("tool_used", "N/A")}
   - Expected: {step.get("expected_result", "N/A")}
   - Actual: {step.get("actual_result", "N/A")}
"""

        return f"""<verification_task>
<report_id>{report_id}</report_id>
<title>{title}</title>

<objective>
Verify this vulnerability by independently reproducing it.
You must attempt to reproduce the exact same vulnerability behavior described in the evidence.
</objective>

<evidence>
## Target Information
- **URL:** {target_url}
- **Parameter:** {affected_parameter or "N/A"}
- **Baseline State:** {baseline_state or "N/A"}
- **Exploited State:** {exploited_state or "N/A"}

## PoC Payload
```
{poc_payload}
```

## HTTP Evidence
{http_evidence_text}

## Reproduction Steps
{steps_text}
</evidence>

<instructions>
1. Review the provided evidence and reproduction steps carefully
2. Establish a baseline: verify normal application behavior first
3. Attempt to reproduce using the SAME payload and approach
4. Execute at least 3 reproduction attempts
5. Compare your results with the reported results

VERIFICATION OUTCOMES:
- If you can reproduce the same vulnerability behavior:
  → Call verify_vulnerability_report(report_id="{report_id}", verified=True)

- If you cannot reproduce despite following all steps:
  → Call verify_vulnerability_report(report_id="{report_id}", verified=False, rejection_reason="...")

- If results are ambiguous or edge case:
  → Call verify_vulnerability_report(report_id="{report_id}", verified=False, rejection_reason="Requires manual review: ...")

IMPORTANT RULES:
- Do NOT create new vulnerability reports
- Do NOT modify the original report content
- Focus ONLY on verification of this specific finding
- Be thorough but efficient - you have limited iterations
</instructions>
</verification_task>"""
