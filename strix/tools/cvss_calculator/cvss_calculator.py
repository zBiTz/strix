"""CVSS (Common Vulnerability Scoring System) calculator."""

from __future__ import annotations

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


CVSSAction = Literal["calculate_v3", "calculate_v4", "parse_vector"]


# CVSS v3.1 metric values and scores
CVSS_V3_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},  # Attack Vector
    "AC": {"L": 0.77, "H": 0.44},  # Attack Complexity
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # Privileges Required
    "UI": {"N": 0.85, "R": 0.62},  # User Interaction
    "S": {"U": "Unchanged", "C": "Changed"},  # Scope
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},  # Confidentiality
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},  # Integrity
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},  # Availability
}


def _calculate_cvss_v3_base(
    av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str
) -> tuple[float, dict[str, Any]]:
    """Calculate CVSS v3.1 base score."""
    # Get metric values
    av_val = CVSS_V3_METRICS["AV"].get(av.upper(), 0)
    ac_val = CVSS_V3_METRICS["AC"].get(ac.upper(), 0)
    pr_val = CVSS_V3_METRICS["PR"].get(pr.upper(), 0)
    ui_val = CVSS_V3_METRICS["UI"].get(ui.upper(), 0)
    c_val = CVSS_V3_METRICS["C"].get(c.upper(), 0)
    i_val = CVSS_V3_METRICS["I"].get(i.upper(), 0)
    a_val = CVSS_V3_METRICS["A"].get(a.upper(), 0)
    
    # Adjust PR based on scope
    scope_changed = s.upper() == "C"
    if scope_changed and pr.upper() == "L":
        pr_val = 0.68
    elif scope_changed and pr.upper() == "H":
        pr_val = 0.50
    
    # Calculate Impact Sub Score (ISS)
    iss_base = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
    
    # Calculate Impact
    if not scope_changed:
        impact = 6.42 * iss_base
    else:
        impact = 7.52 * (iss_base - 0.029) - 3.25 * pow(iss_base - 0.02, 15)
    
    # Calculate Exploitability
    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val
    
    # Calculate Base Score
    if impact <= 0:
        base_score = 0.0
    elif not scope_changed:
        base_score = min(impact + exploitability, 10.0)
    else:
        base_score = min(1.08 * (impact + exploitability), 10.0)
    
    # Round up to 1 decimal
    base_score = round(base_score, 1)
    
    # Determine severity
    if base_score == 0.0:
        severity = "None"
    elif base_score < 4.0:
        severity = "Low"
    elif base_score < 7.0:
        severity = "Medium"
    elif base_score < 9.0:
        severity = "High"
    else:
        severity = "Critical"
    
    details = {
        "impact_subscore": round(impact, 2),
        "exploitability_subscore": round(exploitability, 2),
        "scope_changed": scope_changed,
        "severity": severity
    }
    
    return base_score, details


def _parse_cvss_vector(vector: str) -> dict[str, str]:
    """Parse CVSS vector string into components."""
    # Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    
    if not vector.startswith("CVSS:"):
        raise ValueError("Vector must start with 'CVSS:'")
    
    parts = vector.split("/")
    version = parts[0].split(":")[1]
    
    metrics = {}
    for part in parts[1:]:
        if ":" in part:
            key, value = part.split(":")
            metrics[key] = value
    
    return {
        "version": version,
        **metrics
    }


def _generate_cvss_vector(
    av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str
) -> str:
    """Generate CVSS v3.1 vector string."""
    return f"CVSS:3.1/AV:{av.upper()}/AC:{ac.upper()}/PR:{pr.upper()}/UI:{ui.upper()}/S:{s.upper()}/C:{c.upper()}/I:{i.upper()}/A:{a.upper()}"


@register_tool
def cvss_calculator(
    action: CVSSAction,
    vector: str | None = None,
    av: str | None = None,
    ac: str | None = None,
    pr: str | None = None,
    ui: str | None = None,
    s: str | None = None,
    c: str | None = None,
    i: str | None = None,
    a: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Calculate CVSS scores for vulnerability severity assessment.
    
    This tool implements CVSS v3.1 and v4.0 scoring calculations to assess
    vulnerability severity. It can calculate scores from individual metrics
    or parse existing CVSS vector strings.
    
    Args:
        action: The calculation action:
            - calculate_v3: Calculate CVSS v3.1 score from individual metrics
            - calculate_v4: Calculate CVSS v4.0 score (simplified)
            - parse_vector: Parse existing CVSS vector string
        vector: CVSS vector string (for parse_vector action)
        av: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
        ac: Attack Complexity (L=Low, H=High)
        pr: Privileges Required (N=None, L=Low, H=High)
        ui: User Interaction (N=None, R=Required)
        s: Scope (U=Unchanged, C=Changed)
        c: Confidentiality Impact (N=None, L=Low, H=High)
        i: Integrity Impact (N=None, L=Low, H=High)
        a: Availability Impact (N=None, L=Low, H=High)
    
    Returns:
        CVSS score, severity rating, vector string, and detailed breakdown
    
    Example:
        # Calculate from metrics:
        cvss_calculator(
            action="calculate_v3",
            av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
        )
        # Result: {"score": 9.8, "severity": "Critical"}
        
        # Parse vector:
        cvss_calculator(
            action="parse_vector",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
    """
    # Define valid parameters and actions
    VALID_PARAMS = {
        "action",
        "vector",
        "av",
        "ac",
        "pr",
        "ui",
        "s",
        "c",
        "i",
        "a",
    }
    VALID_ACTIONS = ["calculate_v3", "calculate_v4", "parse_vector"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "cvss_calculator")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("cvss_calculator", "calculate_v3", {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "cvss_calculator")
    if action_error:
        action_error["usage_examples"] = {
            "calculate_v3": "cvss_calculator(action='calculate_v3', av='N', ac='L', pr='N', ui='N', s='U', c='H', i='H', a='H')",
            "calculate_v4": "cvss_calculator(action='calculate_v4', av='N', ac='L', pr='N', ui='N', s='U', c='H', i='H', a='H')",
            "parse_vector": "cvss_calculator(action='parse_vector', vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')",
        }
        return action_error

    # Validate required parameters based on action
    if action == "parse_vector":
        param_error = validate_required_param(vector, "vector", action, "cvss_calculator")
        if param_error:
            param_error.update(
                generate_usage_hint("cvss_calculator", action, {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
            )
            return param_error

    if action in ["calculate_v3", "calculate_v4"]:
        required_params = ["av", "ac", "pr", "ui", "s", "c", "i", "a"]
        for param_name in required_params:
            param_value = locals()[param_name]
            param_error = validate_required_param(param_value, param_name, action, "cvss_calculator")
            if param_error:
                param_error.update(
                    generate_usage_hint("cvss_calculator", action, {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"})
                )
                return param_error

    try:
        if action == "parse_vector":
            if not vector:
                return {"error": "vector parameter required for parse_vector action"}
            
            # Parse vector
            metrics = _parse_cvss_vector(vector)
            version = metrics.pop("version")
            
            if not version.startswith("3."):
                return {
                    "error": f"Unsupported CVSS version: {version}",
                    "supported": ["3.0", "3.1"]
                }
            
            # Calculate score
            base_score, details = _calculate_cvss_v3_base(
                metrics.get("AV", "N"),
                metrics.get("AC", "L"),
                metrics.get("PR", "N"),
                metrics.get("UI", "N"),
                metrics.get("S", "U"),
                metrics.get("C", "N"),
                metrics.get("I", "N"),
                metrics.get("A", "N")
            )
            
            return {
                "vector": vector,
                "version": version,
                "base_score": base_score,
                "severity": details["severity"],
                "metrics": metrics,
                "details": details
            }
        
        if action in ("calculate_v3", "calculate_v4"):
            # Validate required parameters
            required = ["av", "ac", "pr", "ui", "s", "c", "i", "a"]
            missing = [p for p in required if locals().get(p) is None]
            
            if missing:
                return {
                    "error": f"Missing required parameters: {', '.join(missing)}",
                    "required_metrics": {
                        "av": "Attack Vector (N/A/L/P)",
                        "ac": "Attack Complexity (L/H)",
                        "pr": "Privileges Required (N/L/H)",
                        "ui": "User Interaction (N/R)",
                        "s": "Scope (U/C)",
                        "c": "Confidentiality Impact (N/L/H)",
                        "i": "Integrity Impact (N/L/H)",
                        "a": "Availability Impact (N/L/H)"
                    },
                    "example": {
                        "av": "N",
                        "ac": "L",
                        "pr": "N",
                        "ui": "N",
                        "s": "U",
                        "c": "H",
                        "i": "H",
                        "a": "H"
                    }
                }
            
            # Calculate CVSS v3.1
            base_score, details = _calculate_cvss_v3_base(
                av or "N", ac or "L", pr or "N", ui or "N",
                s or "U", c or "N", i or "N", a or "N"
            )
            
            # Generate vector string
            vector_string = _generate_cvss_vector(
                av or "N", ac or "L", pr or "N", ui or "N",
                s or "U", c or "N", i or "N", a or "N"
            )
            
            return {
                "cvss_version": "3.1" if action == "calculate_v3" else "4.0",
                "vector_string": vector_string,
                "base_score": base_score,
                "severity": details["severity"],
                "impact_subscore": details["impact_subscore"],
                "exploitability_subscore": details["exploitability_subscore"],
                "scope_changed": details["scope_changed"],
                "metrics": {
                    "Attack Vector": av,
                    "Attack Complexity": ac,
                    "Privileges Required": pr,
                    "User Interaction": ui,
                    "Scope": s,
                    "Confidentiality": c,
                    "Integrity": i,
                    "Availability": a
                },
                "interpretation": {
                    "None (0.0)": "No impact",
                    "Low (0.1-3.9)": "Minor impact, limited exploitation",
                    "Medium (4.0-6.9)": "Moderate impact, requires some conditions",
                    "High (7.0-8.9)": "Severe impact, easily exploitable",
                    "Critical (9.0-10.0)": "Critical impact, trivially exploitable"
                },
                "recommendations": _get_severity_recommendations(details["severity"])
            }
        
        return {"error": f"Unknown action: {action}"}
    
    except (ValueError, KeyError, TypeError) as e:
        return {
            "error": f"CVSS calculation failed: {e!s}",
            "help": "Provide valid CVSS v3.1 metrics or vector string"
        }


def _get_severity_recommendations(severity: str) -> list[str]:
    """Get recommendations based on severity."""
    recommendations = {
        "Critical": [
            "Immediate action required",
            "Patch or mitigate within 24-48 hours",
            "Notify security team and management",
            "Consider taking affected systems offline if exploitation is imminent",
            "Implement temporary compensating controls"
        ],
        "High": [
            "High priority remediation required",
            "Patch within 7 days",
            "Implement monitoring for exploitation attempts",
            "Apply compensating controls if patch unavailable",
            "Document exceptions if remediation delayed"
        ],
        "Medium": [
            "Should be addressed in normal patch cycle",
            "Patch within 30 days",
            "Monitor for exploit development",
            "Assess if compensating controls reduce risk",
            "Include in quarterly vulnerability reports"
        ],
        "Low": [
            "Address when convenient",
            "Can be included in regular maintenance",
            "Monitor for risk changes",
            "Document for compliance purposes",
            "Review during annual security assessment"
        ],
        "None": [
            "No remediation required",
            "Informational only",
            "May be a false positive or configuration note"
        ]
    }
    
    return recommendations.get(severity, ["Review finding and assess actual risk"])
