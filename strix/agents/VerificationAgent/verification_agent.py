"""Verification Agent for reproducing and validating vulnerability reports.

This agent is specialized for verification tasks - it implements TWO-PHASE
VERIFICATION:
  - Phase 1: Reproducibility - Can we reproduce the reported behavior?
  - Phase 2: Validity - Does this behavior actually prove the vulnerability?

The agent designs its OWN independent control tests based on the vulnerability
type, rather than simply reproducing the reporter's tests.
"""

from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig
from strix.tools.reporting.vulnerability_types import (
    get_vulnerability_type_spec,
    VulnerabilityTypeSpec,
)


class VerificationAgent(BaseAgent):
    """Agent specialized for vulnerability verification using two-phase verification.

    The VerificationAgent implements a two-phase verification approach:
    1. Phase 1 (Reproducibility): Can the reported behavior be reproduced?
    2. Phase 2 (Validity): Does the behavior prove the claimed vulnerability?

    The agent has a limited iteration count (50) and uses a specialized prompt
    module focused on reproduction and validation. It does not create new
    vulnerability reports - only verifies existing ones.

    Critical: The agent designs its OWN independent control tests based on the
    vulnerability type specification, NOT reproducing the reporter's tests.
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
        """Attempt to reproduce and validate a vulnerability using two-phase verification.

        Phase 1 (Reproducibility): Attempts to reproduce the exact reported behavior.
        Phase 2 (Validity): Designs independent control tests to validate the claim.

        Args:
            report_id: The ID of the report to verify
            title: Title of the vulnerability
            evidence: Structured evidence from the original report containing:
                - vulnerability_type: Type from registry (e.g., "path_traversal")
                - claim_assertion: The specific security claim being made
                - primary_evidence: HTTP request/response pairs
                - reproduction_steps: Steps to reproduce
                - poc_payload: The exploit payload
                - target_url: Affected URL
                - affected_parameter: Vulnerable parameter
                - reporter_control_tests: Control tests performed by reporter

        Returns:
            Result dict with verification outcome including:
                - phase1_reproduction: Reproducibility results
                - phase2_validity: Validity check results
        """
        # Extract vulnerability type for type-specific validation
        vuln_type = evidence.get("vulnerability_type", "unknown")
        type_spec = get_vulnerability_type_spec(vuln_type)

        # Build type-aware verification task
        task = self._build_verification_task(report_id, title, evidence, type_spec)

        # Set vulnerability_type in context for prompt template
        if self.state:
            self.state.prompt_context = self.state.prompt_context or {}
            self.state.prompt_context["vulnerability_type"] = vuln_type

        return await self.agent_loop(task=task)

    def _build_verification_task(
        self,
        report_id: str,
        title: str,
        evidence: dict[str, Any],
        type_spec: VulnerabilityTypeSpec | None,
    ) -> str:
        """Build the two-phase verification task description.

        Args:
            report_id: Report identifier
            title: Vulnerability title
            evidence: Evidence dictionary
            type_spec: Vulnerability type specification for type-aware validation

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
        vulnerability_type = evidence.get("vulnerability_type", "unknown")
        claim_assertion = evidence.get("claim_assertion", "")
        reporter_control_tests = evidence.get("reporter_control_tests", [])

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

        # Format reporter's control tests (for reference, NOT to reproduce)
        reporter_tests_text = ""
        if reporter_control_tests:
            reporter_tests_text = "\n## Reporter's Control Tests (FOR REFERENCE ONLY - DO NOT REPRODUCE)\n"
            for i, test in enumerate(reporter_control_tests, 1):
                reporter_tests_text += f"""
### Test #{i}: {test.get("test_name", "Unnamed")}
- **Description:** {test.get("description", "N/A")}
- **Conclusion:** {test.get("conclusion", "N/A")}
**WARNING:** You must design your OWN control tests. Do not simply reproduce these.
"""

        # Build type-specific validation requirements
        type_validation_text = self._build_type_validation_section(type_spec)

        return f"""<verification_task>
<report_id>{report_id}</report_id>
<title>{title}</title>
<vulnerability_type>{vulnerability_type}</vulnerability_type>

<objective>
Implement TWO-PHASE VERIFICATION for this vulnerability report.

PHASE 1 (Reproducibility): Can you reproduce the exact reported behavior?
PHASE 2 (Validity): Does this behavior ACTUALLY prove the claimed vulnerability?

CRITICAL: Reproducibility alone is NOT sufficient. A test can be 100% reproducible
but still be a FALSE POSITIVE if it doesn't prove the vulnerability claim.
</objective>

<claim_being_verified>
**Vulnerability Type:** {vulnerability_type}
**Claim Assertion:** {claim_assertion or "Not specified"}
</claim_being_verified>

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
{reporter_tests_text}
</evidence>

{type_validation_text}

<two_phase_instructions>
## PHASE 1: REPRODUCIBILITY CHECK
1. Review the provided evidence and reproduction steps carefully
2. Establish a baseline: verify normal application behavior first
3. Attempt to reproduce using the SAME payload and approach
4. Execute at least 3 reproduction attempts
5. Compare your results with the reported results

→ IF CANNOT REPRODUCE: REJECT immediately (Phase 1 failure)
→ IF REPRODUCED: Proceed to Phase 2

## PHASE 2: VALIDITY CHECK (MANDATORY)
1. Review the type-specific validation requirements above
2. Design YOUR OWN independent control tests based on the vulnerability type
3. Execute each control test you designed
4. Compare results to validity criteria for this type

→ IF CONTROL TESTS CONFIRM: VERIFY
→ IF CONTROL TESTS FAIL: REJECT (Phase 2 failure)
→ IF AMBIGUOUS: Mark for manual review

CRITICAL WARNING:
- DO NOT simply reproduce the reporter's control tests
- You must INDEPENDENTLY validate the security claim
- A reproducible test that proves the wrong thing is still a false positive
</two_phase_instructions>

<verification_outcomes>
VERIFIED (verified=True):
- Phase 1: Reproducible (3+ consistent attempts)
- Phase 2: Your independent control tests confirm validity
- Call: verify_vulnerability_report(report_id="{report_id}", verified=True, verification_evidence={{...}})

REJECTED - Phase 1 Failure (verified=False):
- Cannot reproduce despite following all steps
- Call: verify_vulnerability_report(report_id="{report_id}", verified=False, rejection_reason="Phase 1 failure: <reason>")

REJECTED - Phase 2 Failure (verified=False):
- Reproducible BUT your control tests show it's not a real vulnerability
- Call: verify_vulnerability_report(report_id="{report_id}", verified=False, rejection_reason="Phase 2 failure: <reason>")

MANUAL REVIEW (verified=False):
- Ambiguous results requiring human judgment
- Call: verify_vulnerability_report(report_id="{report_id}", verified=False, rejection_reason="Requires manual review: <reason>")
</verification_outcomes>

<rules>
- Do NOT create new vulnerability reports
- Do NOT modify the original report content
- ALWAYS complete BOTH phases
- NEVER verify based on reproducibility alone
- Be thorough but efficient - you have limited iterations
</rules>
</verification_task>"""

    def _build_type_validation_section(
        self, type_spec: VulnerabilityTypeSpec | None
    ) -> str:
        """Build the type-specific validation requirements section.

        Args:
            type_spec: Vulnerability type specification

        Returns:
            Formatted validation requirements section
        """
        if not type_spec:
            return """<type_validation>
**Warning:** Unknown vulnerability type. Apply general validation principles:
1. Verify the claimed behavior actually proves a security impact
2. Test that the target resource is actually protected/restricted
3. Design control tests that would FAIL if this isn't a real vulnerability
</type_validation>"""

        # Format control test requirements
        control_tests_text = ""
        for test in type_spec.control_test_requirements:
            control_tests_text += f"""
### {test.name}
**Purpose:** {test.description}
**How to Test:** {test.test_template}
**Success Criteria:** {test.success_criteria}
**If This Fails:** {test.failure_indicates}
"""

        # Format validity criteria
        validity_text = "\n".join(f"- {c}" for c in type_spec.validity_criteria)

        # Format false positive patterns
        fp_text = "\n".join(f"- {p}" for p in type_spec.false_positive_patterns)

        return f"""<type_validation>
## Validation Requirements for: {type_spec.display_name}

**Semantic Claim:** {type_spec.semantic_claim}

### Required Control Tests (YOU MUST DESIGN AND EXECUTE)
{control_tests_text}

### Validity Criteria (ALL must be confirmed)
{validity_text}

### False Positive Patterns (REJECT if observed)
{fp_text}
</type_validation>"""
