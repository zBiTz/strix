"""SAST Engine for detecting security vulnerabilities in code."""

from __future__ import annotations

import re
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


SASTAction = Literal["scan_code", "scan_file", "list_rules"]


# SAST detection patterns
SAST_RULES = {
    "hardcoded_secrets": {
        "patterns": [
            r"(?i)(password|passwd|pwd)\s*=\s*['\"]([^'\"]{8,})['\"]",
            r"(?i)(api[_-]?key|apikey)\s*=\s*['\"]([^'\"]{20,})['\"]",
            r"(?i)(secret[_-]?key|secret)\s*=\s*['\"]([^'\"]{16,})['\"]",
            r"(?i)(auth[_-]?token|token)\s*=\s*['\"]([^'\"]{20,})['\"]",
            r"['\"]sk_live_[a-zA-Z0-9]{24,}['\"]",  # Stripe secret
            r"['\"]sk_test_[a-zA-Z0-9]{24,}['\"]",  # Stripe test
            r"['\"]AKIA[0-9A-Z]{16}['\"]",  # AWS access key
        ],
        "severity": "critical",
        "description": "Hardcoded secrets or credentials detected",
    },
    "sql_injection": {
        "patterns": [
            r"execute\(['\"].*\+.*['\"]",  # String concatenation in execute
            r"executemany\(['\"].*\%.*['\"]",  # String formatting in execute
            r"\.raw\(['\"].*\+.*['\"]",  # Django ORM raw query
            r"cursor\.execute\(['\"].*format\(",  # Format string in execute
            r"cursor\.execute\(f['\"]",  # F-string in execute
            r"db\.exec\(['\"].*\+.*['\"]",  # Database exec with concat
        ],
        "severity": "high",
        "description": "Potential SQL injection vulnerability",
    },
    "command_injection": {
        "patterns": [
            r"os\.system\([^)]*input\(",
            r"os\.system\([^)]*request\.",
            r"subprocess\.call\(.*shell=True",
            r"subprocess\.run\(.*shell=True",
            r"exec\([^)]*input\(",
            r"eval\([^)]*input\(",
            r"eval\([^)]*request\.",
        ],
        "severity": "critical",
        "description": "Potential command injection vulnerability",
    },
    "path_traversal": {
        "patterns": [
            r"open\([^)]*input\(",
            r"open\([^)]*request\.",
            r"os\.path\.join\([^)]*input\(",
            r"os\.path\.join\([^)]*request\.",
            r"\.read_file\([^)]*input\(",
            r"\.read_file\([^)]*request\.",
        ],
        "severity": "high",
        "description": "Potential path traversal vulnerability",
    },
    "insecure_crypto": {
        "patterns": [
            r"hashlib\.md5\(",
            r"hashlib\.sha1\(",
            r"Crypto\.Cipher\.DES",
            r"Crypto\.Cipher\.ARC2",
            r"Crypto\.Cipher\.ARC4",
            r"from Crypto import Random",
            r"random\.random\(\)",  # Non-crypto random
        ],
        "severity": "medium",
        "description": "Use of weak or insecure cryptographic algorithm",
    },
    "xxe_vulnerability": {
        "patterns": [
            r"xml\.etree\.ElementTree\.parse\(",
            r"xml\.dom\.minidom\.parse\(",
            r"lxml\.etree\.parse\([^)]*resolve_entities=True",
            r"defusedxml",  # Check if NOT using defusedxml
        ],
        "severity": "high",
        "description": "Potential XML External Entity (XXE) vulnerability",
    },
    "deserialization": {
        "patterns": [
            r"pickle\.loads\([^)]*request\.",
            r"pickle\.loads\([^)]*input\(",
            r"yaml\.load\([^)]*Loader=yaml\.Loader",
            r"yaml\.unsafe_load\(",
            r"jsonpickle\.decode\(",
        ],
        "severity": "critical",
        "description": "Insecure deserialization vulnerability",
    },
    "ssrf": {
        "patterns": [
            r"requests\.(get|post)\([^)]*request\.",
            r"urllib\.request\.urlopen\([^)]*request\.",
            r"httpx\.(get|post)\([^)]*request\.",
        ],
        "severity": "high",
        "description": "Potential Server-Side Request Forgery (SSRF)",
    },
    "debug_enabled": {
        "patterns": [
            r"DEBUG\s*=\s*True",
            r"app\.debug\s*=\s*True",
            r"app\.run\(debug=True",
        ],
        "severity": "medium",
        "description": "Debug mode enabled in production code",
    },
}


def _scan_code_content(
    code: str,
    rules: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Scan code content for security vulnerabilities."""
    if rules is None:
        rules = SAST_RULES

    findings: list[dict[str, Any]] = []
    lines = code.split("\n")

    for rule_name, rule_info in rules.items():
        patterns = rule_info["patterns"]
        for pattern in patterns:
            for line_num, line in enumerate(lines, 1):
                matches = re.finditer(pattern, line)
                for _ in matches:
                    context_start = max(0, line_num - 3)
                    context_end = min(len(lines), line_num + 2)
                    context_lines = lines[context_start:context_end]
                    context = "\n".join(
                        f"{i + context_start + 1}: {l}"
                        for i, l in enumerate(context_lines)
                    )

                    findings.append({
                        "rule": rule_name,
                        "severity": rule_info["severity"],
                        "description": rule_info["description"],
                        "line": line_num,
                        "code": line.strip(),
                        "matched_pattern": pattern,
                        "context": context,
                    })

    return findings


@register_tool
def sast_engine(
    action: SASTAction,
    code: str | None = None,
    filename: str | None = None,
    custom_rules: dict[str, dict[str, Any]] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Static Application Security Testing (SAST) engine for code analysis.

    This tool performs static analysis to detect common security vulnerabilities
    including SQL injection, command injection, hardcoded secrets, insecure
    cryptography, and more.

    Args:
        action: The SAST action to perform:
            - scan_code: Scan provided code content
            - scan_file: Scan a file (requires filename)
            - list_rules: List all available detection rules
        code: Code content to scan (for scan_code action)
        filename: Path to file to scan (for scan_file action)
        custom_rules: Additional custom rules to apply

    Returns:
        Scan results including vulnerabilities found with severity and location
    """
    # Define valid parameters and actions
    VALID_PARAMS = {
        "action",
        "code",
        "filename",
        "custom_rules",
    }
    VALID_ACTIONS = ["scan_code", "scan_file", "list_rules"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "sast_engine")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("sast_engine", "scan_code", {"code": "import os; os.system(user_input)"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "sast_engine")
    if action_error:
        action_error["usage_examples"] = {
            "scan_code": "sast_engine(action='scan_code', code='import os; os.system(user_input)')",
            "scan_file": "sast_engine(action='scan_file', filename='/path/to/file.py')",
            "list_rules": "sast_engine(action='list_rules')",
        }
        return action_error

    # Validate required parameters based on action
    if action == "scan_code":
        param_error = validate_required_param(code, "code", action, "sast_engine")
        if param_error:
            param_error.update(
                generate_usage_hint("sast_engine", action, {"code": "import os; os.system(user_input)"})
            )
            return param_error

    if action == "scan_file":
        param_error = validate_required_param(filename, "filename", action, "sast_engine")
        if param_error:
            param_error.update(
                generate_usage_hint("sast_engine", action, {"filename": "/path/to/file.py"})
            )
            return param_error

    try:
        if action == "list_rules":
            return {
                "rules": [
                    {
                        "name": name,
                        "severity": info["severity"],
                        "description": info["description"],
                        "pattern_count": len(info["patterns"]),
                    }
                    for name, info in SAST_RULES.items()
                ],
                "total_rules": len(SAST_RULES),
            }

        if action == "scan_code":
            if not code:
                return {"error": "code parameter required for scan_code action"}

            # Combine default and custom rules
            rules = dict(SAST_RULES)
            if custom_rules:
                rules.update(custom_rules)

            findings = _scan_code_content(code, rules)

            # Categorize by severity
            critical = [f for f in findings if f["severity"] == "critical"]
            high = [f for f in findings if f["severity"] == "high"]
            medium = [f for f in findings if f["severity"] == "medium"]
            low = [f for f in findings if f["severity"] == "low"]

            return {
                "total_findings": len(findings),
                "findings": findings,
                "summary": {
                    "critical": len(critical),
                    "high": len(high),
                    "medium": len(medium),
                    "low": len(low),
                },
                "recommendations": [
                    "Review all critical and high severity findings immediately",
                    "Never hardcode secrets or credentials in source code",
                    "Use parameterized queries to prevent SQL injection",
                    "Avoid using shell=True in subprocess calls",
                    "Use secure cryptographic algorithms (SHA-256+, AES)",
                    "Validate and sanitize all user input",
                    "Disable debug mode in production",
                ] if findings else ["No security issues detected in the code"],
            }

        if action == "scan_file":
            if not filename:
                return {"error": "filename parameter required for scan_file action"}

            try:
                with open(filename, encoding="utf-8", errors="ignore") as f:
                    code_content = f.read()

                rules = dict(SAST_RULES)
                if custom_rules:
                    rules.update(custom_rules)

                findings = _scan_code_content(code_content, rules)

                critical = [f for f in findings if f["severity"] == "critical"]
                high = [f for f in findings if f["severity"] == "high"]
                medium = [f for f in findings if f["severity"] == "medium"]
                low = [f for f in findings if f["severity"] == "low"]

                return {
                    "filename": filename,
                    "total_findings": len(findings),
                    "findings": findings,
                    "summary": {
                        "critical": len(critical),
                        "high": len(high),
                        "medium": len(medium),
                        "low": len(low),
                    },
                    "recommendations": [
                        "Review all critical and high severity findings immediately",
                        "Fix hardcoded secrets by using environment variables or secret management",
                        "Remediate SQL injection by using parameterized queries",
                        "Fix command injection by avoiding shell=True and using argument lists",
                    ] if findings else [f"No security issues detected in {filename}"],
                }
            except (FileNotFoundError, PermissionError, OSError) as e:
                return {"error": f"Failed to read file {filename}: {e!s}"}

        return {"error": f"Unknown action: {action}"}

    except (re.error, ValueError) as e:
        return {"error": f"SAST scanning failed: {e!s}"}
