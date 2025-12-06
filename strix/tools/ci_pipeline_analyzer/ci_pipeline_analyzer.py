"""CI/CD pipeline configuration security analyzer."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


CIPipelineAction = Literal[
    "analyze_github_actions",
    "analyze_gitlab_ci",
    "analyze_jenkinsfile",
    "find_secrets",
    "full_audit",
]

# Dangerous patterns in CI configurations
GITHUB_ACTIONS_DANGEROUS_PATTERNS = {
    "expression_injection": [
        r"\$\{\{\s*github\.event\.(issue|pull_request|comment)\.(title|body|comment)",
        r"\$\{\{\s*github\.event\..*\.head\.ref",
        r"\$\{\{\s*github\.head_ref",
    ],
    "dangerous_triggers": [
        r"on:\s*pull_request_target",
        r"on:\s*issue_comment",
        r"on:\s*workflow_run",
    ],
    "excessive_permissions": [
        r"permissions:\s*write-all",
        r"contents:\s*write",
        r"pull-requests:\s*write",
        r"actions:\s*write",
    ],
    "checkout_pr_head": [
        r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(ref|sha)",
        r"repository:\s*\$\{\{\s*github\.event\.pull_request\.head\.repo",
    ],
    "unpinned_actions": [
        r"uses:\s*[^@]+@(main|master|v\d+)(?!\.\d)",
    ],
    "secrets_in_commands": [
        r"echo\s+\"\$\{\{\s*secrets\.",
        r"curl.*\$\{\{\s*secrets\.",
    ],
}

GITLAB_CI_DANGEROUS_PATTERNS = {
    "variable_injection": [
        r"\$\{?\w+\}?\s*[;&|]",
        r"eval\s+\$",
    ],
    "debug_mode": [
        r"CI_DEBUG_TRACE:\s*[\"']?true",
    ],
    "external_includes": [
        r"include:\s*\n\s*-\s*remote:",
        r"include:\s*\n\s*-\s*project:",
    ],
    "artifact_exposure": [
        r"artifacts:\s*\n\s*paths:",
        r"when:\s*always",
    ],
    "unprotected_variables": [
        r"variables:\s*\n(?:.*\n)*?\s*\w+:\s*[\"']?[A-Za-z0-9+/=]{20,}",
    ],
}

JENKINSFILE_DANGEROUS_PATTERNS = {
    "script_injection": [
        r"sh\s+[\"'].*\$\{params\.",
        r"sh\s+[\"'].*\$\{env\.",
        r"groovy\.lang\..*execute",
    ],
    "credential_exposure": [
        r"echo\s+.*credentials",
        r"print.*password",
    ],
    "unsafe_plugins": [
        r"@Grab",
        r"evaluate\s*\(",
    ],
    "missing_sandbox": [
        r"script\s*\{",  # Script blocks may bypass sandbox
    ],
}

# Secret patterns
SECRET_PATTERNS = {
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret": r"[A-Za-z0-9/+=]{40}",
    "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "gitlab_token": r"glpat-[A-Za-z0-9_-]{20}",
    "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,}",
    "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "generic_api_key": r"['\"][A-Za-z0-9_-]{32,}['\"]",
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    "docker_token": r"dckr_pat_[A-Za-z0-9_-]+",
}


def _load_yaml_file(file_path: str) -> dict[str, Any] | list | None:
    """Load and parse a YAML file."""
    try:
        with open(file_path) as f:
            content = f.read()
        return yaml.safe_load(content)
    except Exception:
        return None


def _load_file_content(file_path: str) -> str | None:
    """Load file content as string."""
    try:
        with open(file_path) as f:
            return f.read()
    except Exception:
        return None


def _check_patterns(content: str, patterns: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Check content against pattern dictionary."""
    findings = []
    for category, pattern_list in patterns.items():
        for pattern in pattern_list:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "category": category,
                    "pattern": pattern,
                    "match": match.group()[:100],
                    "line": line_num,
                    "severity": _get_severity(category),
                })
    return findings


def _get_severity(category: str) -> str:
    """Get severity level for a finding category."""
    critical = ["expression_injection", "script_injection", "credential_exposure", "secrets_in_commands"]
    high = ["dangerous_triggers", "checkout_pr_head", "variable_injection", "external_includes"]
    if category in critical:
        return "critical"
    if category in high:
        return "high"
    return "medium"


def _analyze_github_actions(file_path: str) -> dict[str, Any]:
    """Analyze GitHub Actions workflow file."""
    content = _load_file_content(file_path)
    if not content:
        return {"error": f"Could not read file: {file_path}"}

    yaml_content = _load_yaml_file(file_path)
    findings = _check_patterns(content, GITHUB_ACTIONS_DANGEROUS_PATTERNS)

    # Additional structural checks
    structural_findings = []
    if yaml_content and isinstance(yaml_content, dict):
        # Check for overly permissive GITHUB_TOKEN
        permissions = yaml_content.get("permissions", {})
        if permissions == "write-all" or (isinstance(permissions, dict) and permissions.get("contents") == "write"):
            structural_findings.append({
                "category": "excessive_permissions",
                "description": "Workflow has write permissions that may be excessive",
                "severity": "medium",
            })

        # Check trigger types
        triggers = yaml_content.get("on", {})
        if isinstance(triggers, dict):
            if "pull_request_target" in triggers:
                structural_findings.append({
                    "category": "dangerous_trigger",
                    "description": "pull_request_target trigger can access secrets from base repo",
                    "severity": "high",
                })

        # Check for secrets usage patterns
        jobs = yaml_content.get("jobs", {})
        for job_name, job_config in jobs.items() if isinstance(jobs, dict) else []:
            if isinstance(job_config, dict):
                steps = job_config.get("steps", [])
                for idx, step in enumerate(steps) if isinstance(steps, list) else []:
                    if isinstance(step, dict):
                        run_cmd = step.get("run", "")
                        if "${{ secrets." in str(run_cmd) and "echo" in str(run_cmd).lower():
                            structural_findings.append({
                                "category": "potential_secret_leak",
                                "description": f"Job '{job_name}' step {idx} may leak secrets in logs",
                                "severity": "high",
                            })

    return {
        "file": file_path,
        "type": "github_actions",
        "pattern_findings": findings,
        "structural_findings": structural_findings,
        "total_findings": len(findings) + len(structural_findings),
        "critical_count": len([f for f in findings + structural_findings if f.get("severity") == "critical"]),
        "high_count": len([f for f in findings + structural_findings if f.get("severity") == "high"]),
    }


def _analyze_gitlab_ci(file_path: str) -> dict[str, Any]:
    """Analyze GitLab CI configuration file."""
    content = _load_file_content(file_path)
    if not content:
        return {"error": f"Could not read file: {file_path}"}

    yaml_content = _load_yaml_file(file_path)
    findings = _check_patterns(content, GITLAB_CI_DANGEROUS_PATTERNS)

    structural_findings = []
    if yaml_content and isinstance(yaml_content, dict):
        # Check for external includes
        includes = yaml_content.get("include", [])
        if isinstance(includes, list):
            for inc in includes:
                if isinstance(inc, dict) and ("remote" in inc or "project" in inc):
                    structural_findings.append({
                        "category": "external_include",
                        "description": f"External include from: {inc}",
                        "severity": "medium",
                    })

        # Check for debug trace
        variables = yaml_content.get("variables", {})
        if isinstance(variables, dict) and variables.get("CI_DEBUG_TRACE"):
            structural_findings.append({
                "category": "debug_enabled",
                "description": "CI_DEBUG_TRACE is enabled - may expose secrets",
                "severity": "high",
            })

    return {
        "file": file_path,
        "type": "gitlab_ci",
        "pattern_findings": findings,
        "structural_findings": structural_findings,
        "total_findings": len(findings) + len(structural_findings),
        "critical_count": len([f for f in findings + structural_findings if f.get("severity") == "critical"]),
        "high_count": len([f for f in findings + structural_findings if f.get("severity") == "high"]),
    }


def _analyze_jenkinsfile(file_path: str) -> dict[str, Any]:
    """Analyze Jenkinsfile."""
    content = _load_file_content(file_path)
    if not content:
        return {"error": f"Could not read file: {file_path}"}

    findings = _check_patterns(content, JENKINSFILE_DANGEROUS_PATTERNS)

    structural_findings = []
    # Check for common Jenkins security issues
    if "script {" in content:
        structural_findings.append({
            "category": "script_block",
            "description": "Script blocks may bypass Jenkins sandbox security",
            "severity": "medium",
        })

    if "@Grab" in content:
        structural_findings.append({
            "category": "external_dependency",
            "description": "@Grab directive can load arbitrary code",
            "severity": "high",
        })

    if "credentials(" in content and "echo" in content.lower():
        structural_findings.append({
            "category": "potential_credential_leak",
            "description": "Credentials used with echo may leak to logs",
            "severity": "high",
        })

    return {
        "file": file_path,
        "type": "jenkinsfile",
        "pattern_findings": findings,
        "structural_findings": structural_findings,
        "total_findings": len(findings) + len(structural_findings),
        "critical_count": len([f for f in findings + structural_findings if f.get("severity") == "critical"]),
        "high_count": len([f for f in findings + structural_findings if f.get("severity") == "high"]),
    }


def _find_secrets_in_file(file_path: str) -> list[dict[str, Any]]:
    """Search for secrets in a file."""
    content = _load_file_content(file_path)
    if not content:
        return []

    secrets = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            line_num = content[:match.start()].count("\n") + 1
            # Redact the actual secret value
            matched_text = match.group()
            if len(matched_text) > 10:
                redacted = matched_text[:4] + "*" * (len(matched_text) - 8) + matched_text[-4:]
            else:
                redacted = "*" * len(matched_text)

            secrets.append({
                "type": secret_type,
                "line": line_num,
                "redacted_value": redacted,
                "severity": "critical" if secret_type in ["private_key", "aws_secret"] else "high",
            })

    return secrets


@register_tool
def ci_pipeline_analyzer(
    action: CIPipelineAction,
    file_path: str | None = None,
    directory: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Analyze CI/CD pipeline configurations for security vulnerabilities.

    Args:
        action: The analysis action to perform:
            - analyze_github_actions: Analyze GitHub Actions workflow file
            - analyze_gitlab_ci: Analyze .gitlab-ci.yml file
            - analyze_jenkinsfile: Analyze Jenkinsfile
            - find_secrets: Search for hardcoded secrets
            - full_audit: Run all checks on a directory
        file_path: Path to the CI configuration file to analyze
        directory: Directory to scan (for full_audit action)

    Returns:
        Analysis results with findings and recommendations
    """
    VALID_PARAMS = {"action", "file_path", "directory"}
    VALID_ACTIONS = ["analyze_github_actions", "analyze_gitlab_ci", "analyze_jenkinsfile", "find_secrets", "full_audit"]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "ci_pipeline_analyzer"):
        unknown_error.update(
            generate_usage_hint("ci_pipeline_analyzer", "analyze_github_actions", {"file_path": ".github/workflows/ci.yml"})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "ci_pipeline_analyzer"):
        action_error["usage_examples"] = {
            "analyze_github_actions": "ci_pipeline_analyzer(action='analyze_github_actions', file_path='.github/workflows/ci.yml')",
            "find_secrets": "ci_pipeline_analyzer(action='find_secrets', file_path='.gitlab-ci.yml')",
            "full_audit": "ci_pipeline_analyzer(action='full_audit', directory='.')",
        }
        return action_error

    if action == "full_audit":
        if param_error := validate_required_param(directory, "directory", action, "ci_pipeline_analyzer"):
            param_error.update(generate_usage_hint("ci_pipeline_analyzer", action, {"directory": "."}))
            return param_error
    else:
        if param_error := validate_required_param(file_path, "file_path", action, "ci_pipeline_analyzer"):
            param_error.update(generate_usage_hint("ci_pipeline_analyzer", action, {"file_path": "path/to/config"}))
            return param_error

    if action == "analyze_github_actions":
        return _analyze_github_actions(file_path)

    elif action == "analyze_gitlab_ci":
        return _analyze_gitlab_ci(file_path)

    elif action == "analyze_jenkinsfile":
        return _analyze_jenkinsfile(file_path)

    elif action == "find_secrets":
        secrets = _find_secrets_in_file(file_path)
        return {
            "file": file_path,
            "secrets_found": len(secrets),
            "findings": secrets,
            "recommendation": "Remove hardcoded secrets and use secret management" if secrets else "No secrets detected",
        }

    elif action == "full_audit":
        dir_path = Path(directory)
        all_findings = []

        # Find and analyze GitHub Actions
        gh_workflows = list(dir_path.glob(".github/workflows/*.yml")) + list(dir_path.glob(".github/workflows/*.yaml"))
        for wf in gh_workflows:
            result = _analyze_github_actions(str(wf))
            if "error" not in result:
                all_findings.append(result)

        # Find and analyze GitLab CI
        gitlab_files = list(dir_path.glob(".gitlab-ci.yml")) + list(dir_path.glob("**/.gitlab-ci.yml"))
        for gl in gitlab_files[:5]:  # Limit
            result = _analyze_gitlab_ci(str(gl))
            if "error" not in result:
                all_findings.append(result)

        # Find and analyze Jenkinsfiles
        jenkinsfiles = list(dir_path.glob("**/Jenkinsfile")) + list(dir_path.glob("**/jenkinsfile"))
        for jf in jenkinsfiles[:5]:
            result = _analyze_jenkinsfile(str(jf))
            if "error" not in result:
                all_findings.append(result)

        # Search for secrets in CI files
        secrets_findings = []
        for ci_file in gh_workflows + gitlab_files + jenkinsfiles:
            secrets = _find_secrets_in_file(str(ci_file))
            if secrets:
                secrets_findings.append({"file": str(ci_file), "secrets": secrets})

        total_critical = sum(f.get("critical_count", 0) for f in all_findings)
        total_high = sum(f.get("high_count", 0) for f in all_findings)

        return {
            "action": "full_audit",
            "directory": directory,
            "files_analyzed": len(all_findings),
            "total_critical_findings": total_critical,
            "total_high_findings": total_high,
            "pipeline_findings": all_findings,
            "secrets_findings": secrets_findings,
            "recommendation": "Review critical and high severity findings immediately" if total_critical > 0 else "No critical issues found",
        }

    return {"error": "Unknown action", "tool_name": "ci_pipeline_analyzer"}
