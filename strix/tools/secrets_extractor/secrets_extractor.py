"""Extract and detect secrets from files, git history, environment variables, and Docker configs."""

from __future__ import annotations

import os
import re
import subprocess
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


SecretsAction = Literal[
    "scan_files",
    "scan_git_history",
    "scan_env_vars",
    "scan_docker",
    "full_scan",
]

# Secret patterns with descriptions and severity
SECRET_PATTERNS = {
    # AWS
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "description": "AWS Access Key ID",
        "severity": "critical",
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "description": "AWS Secret Access Key",
        "severity": "critical",
    },
    "aws_session_token": {
        "pattern": r"(?i)aws[_-]?session[_-]?token['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]+)",
        "description": "AWS Session Token",
        "severity": "critical",
    },
    # GitHub
    "github_token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "description": "GitHub Personal Access Token",
        "severity": "critical",
    },
    "github_oauth": {
        "pattern": r"gho_[A-Za-z0-9]{36,}",
        "description": "GitHub OAuth Access Token",
        "severity": "critical",
    },
    "github_app_token": {
        "pattern": r"(?:ghu|ghs)_[A-Za-z0-9]{36,}",
        "description": "GitHub App Token",
        "severity": "critical",
    },
    # GitLab
    "gitlab_token": {
        "pattern": r"glpat-[A-Za-z0-9_-]{20,}",
        "description": "GitLab Personal Access Token",
        "severity": "critical",
    },
    "gitlab_runner_token": {
        "pattern": r"GR1348941[A-Za-z0-9_-]{20,}",
        "description": "GitLab Runner Registration Token",
        "severity": "high",
    },
    # Slack
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "description": "Slack Token",
        "severity": "critical",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
        "description": "Slack Webhook URL",
        "severity": "high",
    },
    # Google/GCP
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "description": "Google API Key",
        "severity": "high",
    },
    "gcp_service_account": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "description": "GCP Service Account JSON",
        "severity": "critical",
    },
    # Azure
    "azure_storage_key": {
        "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        "description": "Azure Storage Connection String",
        "severity": "critical",
    },
    "azure_sas_token": {
        "pattern": r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=[a-z]+&s[a-z]{2}=[^&]+&se=\d{4}-\d{2}-\d{2}",
        "description": "Azure SAS Token",
        "severity": "high",
    },
    # Database
    "mongodb_uri": {
        "pattern": r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "description": "MongoDB Connection String",
        "severity": "critical",
    },
    "postgres_uri": {
        "pattern": r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "description": "PostgreSQL Connection String",
        "severity": "critical",
    },
    "mysql_uri": {
        "pattern": r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "description": "MySQL Connection String",
        "severity": "critical",
    },
    "redis_uri": {
        "pattern": r"redis://:[^\s'\"]+@[^\s'\"]+",
        "description": "Redis Connection String with Password",
        "severity": "critical",
    },
    # Generic API Keys
    "generic_api_key": {
        "pattern": r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})",
        "description": "Generic API Key",
        "severity": "high",
    },
    "generic_secret": {
        "pattern": r"(?i)(?:secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})",
        "description": "Generic Secret/Password",
        "severity": "high",
    },
    "bearer_token": {
        "pattern": r"(?i)bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "description": "Bearer Token (JWT)",
        "severity": "high",
    },
    # Private Keys
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "description": "Private Key",
        "severity": "critical",
    },
    "pgp_private_key": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "description": "PGP Private Key",
        "severity": "critical",
    },
    # JWT
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "description": "JSON Web Token",
        "severity": "medium",
    },
    # NPM
    "npm_token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "description": "NPM Access Token",
        "severity": "critical",
    },
    # Docker
    "docker_auth": {
        "pattern": r'"auth"\s*:\s*"[A-Za-z0-9+/=]+"',
        "description": "Docker Registry Auth",
        "severity": "high",
    },
    "docker_token": {
        "pattern": r"dckr_pat_[A-Za-z0-9_-]+",
        "description": "Docker Personal Access Token",
        "severity": "critical",
    },
    # Stripe
    "stripe_key": {
        "pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}",
        "description": "Stripe API Key",
        "severity": "critical",
    },
    # Twilio
    "twilio_key": {
        "pattern": r"SK[a-f0-9]{32}",
        "description": "Twilio API Key",
        "severity": "high",
    },
    # SendGrid
    "sendgrid_key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "description": "SendGrid API Key",
        "severity": "high",
    },
    # Heroku
    "heroku_api_key": {
        "pattern": r"(?i)heroku[_-]?api[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        "description": "Heroku API Key",
        "severity": "high",
    },
    # SSH
    "ssh_key_dsa": {
        "pattern": r"-----BEGIN DSA PRIVATE KEY-----",
        "description": "DSA Private Key",
        "severity": "critical",
    },
    "ssh_key_ec": {
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "description": "EC Private Key",
        "severity": "critical",
    },
    "ssh_key_openssh": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "description": "OpenSSH Private Key",
        "severity": "critical",
    },
}

# Environment variable names that commonly contain secrets
SECRET_ENV_VARS = [
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "GL_TOKEN",
    "SLACK_TOKEN", "SLACK_WEBHOOK_URL",
    "DATABASE_URL", "MONGODB_URI", "REDIS_URL", "POSTGRES_PASSWORD",
    "API_KEY", "API_SECRET", "SECRET_KEY", "PRIVATE_KEY",
    "JWT_SECRET", "JWT_KEY", "AUTH_SECRET",
    "STRIPE_SECRET_KEY", "STRIPE_API_KEY",
    "SENDGRID_API_KEY", "TWILIO_AUTH_TOKEN",
    "DOCKER_PASSWORD", "DOCKER_AUTH_CONFIG",
    "NPM_TOKEN", "PYPI_TOKEN",
    "AZURE_CLIENT_SECRET", "AZURE_STORAGE_KEY",
    "GCP_SERVICE_ACCOUNT", "GOOGLE_APPLICATION_CREDENTIALS",
    "PASSWORD", "PASSWD", "SECRET", "TOKEN", "CREDENTIAL",
]

# Default file exclusion patterns
DEFAULT_EXCLUDES = [
    "*.min.js", "*.min.css", "*.map",
    "node_modules/*", "vendor/*", ".git/*",
    "*.pyc", "__pycache__/*", ".venv/*", "venv/*",
    "*.log", "*.lock",
    "dist/*", "build/*", "target/*",
]


def _redact_secret(value: str) -> str:
    """Redact a secret value for safe display."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _should_exclude(path: str, exclude_patterns: list[str]) -> bool:
    """Check if a path should be excluded."""
    for pattern in exclude_patterns:
        if fnmatch(path, pattern) or fnmatch(os.path.basename(path), pattern):
            return True
    return False


def _scan_content(content: str, filename: str, custom_patterns: list[str] | None = None) -> list[dict[str, Any]]:
    """Scan content for secrets using all patterns."""
    findings = []
    lines = content.split("\n")

    # Combine default and custom patterns
    patterns = dict(SECRET_PATTERNS)
    if custom_patterns:
        for i, pattern in enumerate(custom_patterns):
            patterns[f"custom_{i}"] = {
                "pattern": pattern,
                "description": f"Custom pattern {i + 1}",
                "severity": "high",
            }

    for secret_type, config in patterns.items():
        try:
            matches = re.finditer(config["pattern"], content, re.MULTILINE)
            for match in matches:
                # Find line number
                line_start = content[:match.start()].count("\n") + 1
                matched_text = match.group()

                findings.append({
                    "type": secret_type,
                    "description": config["description"],
                    "severity": config["severity"],
                    "file": filename,
                    "line": line_start,
                    "redacted_value": _redact_secret(matched_text[:50]),
                    "context": lines[line_start - 1][:100] if line_start <= len(lines) else "",
                })
        except re.error:
            continue

    return findings


def _scan_files(
    path: str,
    exclude_patterns: list[str],
    custom_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """Scan files in a directory for secrets."""
    findings = []
    scanned_files = 0
    errors = []

    path_obj = Path(path)

    if path_obj.is_file():
        files = [path_obj]
    else:
        files = list(path_obj.rglob("*"))

    for file_path in files:
        if not file_path.is_file():
            continue

        rel_path = str(file_path)
        if _should_exclude(rel_path, exclude_patterns):
            continue

        # Skip binary files (simple heuristic)
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(8192)
                if b"\x00" in chunk:
                    continue
        except (OSError, PermissionError):
            continue

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            scanned_files += 1
            file_findings = _scan_content(content, rel_path, custom_patterns)
            findings.extend(file_findings)
        except (OSError, PermissionError) as e:
            errors.append({"file": rel_path, "error": str(e)})

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return {
        "action": "scan_files",
        "path": path,
        "files_scanned": scanned_files,
        "secrets_found": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"]),
        "findings": findings[:100],  # Limit output
        "errors": errors[:10] if errors else [],
        "truncated": len(findings) > 100,
    }


def _scan_git_history(path: str, depth: int = 100, custom_patterns: list[str] | None = None) -> dict[str, Any]:
    """Scan git history for leaked secrets."""
    findings = []

    try:
        # Get list of commits
        result = subprocess.run(
            ["git", "log", f"-{depth}", "--pretty=format:%H|%s|%an|%ad", "--date=short"],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            return {
                "error": "Not a git repository or git not available",
                "hint": "Run from a git repository directory",
            }

        commits = result.stdout.strip().split("\n")

        for commit_line in commits:
            if not commit_line:
                continue

            parts = commit_line.split("|", 3)
            if len(parts) < 4:
                continue

            commit_hash, subject, author, date = parts

            # Get diff for this commit
            diff_result = subprocess.run(
                ["git", "show", commit_hash, "--pretty=format:", "--no-color"],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if diff_result.returncode == 0:
                diff_content = diff_result.stdout
                commit_findings = _scan_content(diff_content, f"commit:{commit_hash[:8]}", custom_patterns)

                for finding in commit_findings:
                    finding["commit"] = commit_hash[:8]
                    finding["commit_message"] = subject[:50]
                    finding["author"] = author
                    finding["date"] = date
                    findings.append(finding)

            if len(findings) > 100:  # Limit findings
                break

    except subprocess.TimeoutExpired:
        return {"error": "Git operation timed out", "partial_results": findings[:50]}
    except FileNotFoundError:
        return {"error": "Git not found", "hint": "Ensure git is installed"}
    except Exception as e:
        return {"error": f"Git scan failed: {e!s}"}

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return {
        "action": "scan_git_history",
        "path": path,
        "commits_scanned": min(depth, len(commits)),
        "secrets_found": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "findings": findings[:50],
        "recommendation": "Use git-filter-repo to remove secrets from history" if findings else "No secrets found in git history",
    }


def _scan_env_vars() -> dict[str, Any]:
    """Scan environment variables for secrets."""
    findings = []
    env_vars = dict(os.environ)

    for var_name in SECRET_ENV_VARS:
        if var_name in env_vars:
            value = env_vars[var_name]
            if value and len(value) > 3:  # Non-empty, non-trivial value
                findings.append({
                    "type": "environment_variable",
                    "variable": var_name,
                    "redacted_value": _redact_secret(value),
                    "severity": "high" if any(s in var_name.upper() for s in ["KEY", "SECRET", "TOKEN", "PASSWORD"]) else "medium",
                })

    # Also check for pattern matches in all env vars
    for var_name, value in env_vars.items():
        if var_name in SECRET_ENV_VARS:
            continue  # Already processed

        content = f"{var_name}={value}"
        for secret_type, config in SECRET_PATTERNS.items():
            try:
                if re.search(config["pattern"], content):
                    findings.append({
                        "type": secret_type,
                        "description": config["description"],
                        "variable": var_name,
                        "redacted_value": _redact_secret(value[:50] if len(value) > 50 else value),
                        "severity": config["severity"],
                    })
                    break
            except re.error:
                continue

    return {
        "action": "scan_env_vars",
        "total_env_vars": len(env_vars),
        "secrets_found": len(findings),
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "findings": findings,
        "recommendation": "Move secrets to a secure vault" if findings else "No secrets detected in environment",
    }


def _scan_docker(path: str, custom_patterns: list[str] | None = None) -> dict[str, Any]:
    """Scan Docker configurations for exposed secrets."""
    findings = []
    docker_files = []

    path_obj = Path(path)

    # Find Docker-related files
    patterns = [
        "**/Dockerfile*", "**/docker-compose*.yml", "**/docker-compose*.yaml",
        "**/.docker/config.json", "**/docker-config.json",
    ]

    for pattern in patterns:
        docker_files.extend(path_obj.glob(pattern))

    for docker_file in docker_files:
        try:
            with open(docker_file, encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Standard pattern scanning
            file_findings = _scan_content(content, str(docker_file), custom_patterns)

            # Docker-specific checks
            lines = content.split("\n")
            for line_num, line in enumerate(lines, 1):
                # Check for secrets in ENV instructions
                if re.match(r"^\s*ENV\s+", line, re.IGNORECASE):
                    for keyword in ["PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL"]:
                        if keyword in line.upper():
                            findings.append({
                                "type": "docker_env_secret",
                                "description": f"Potential secret in Docker ENV instruction",
                                "severity": "high",
                                "file": str(docker_file),
                                "line": line_num,
                                "context": line[:100],
                            })
                            break

                # Check for secrets in ARG instructions
                if re.match(r"^\s*ARG\s+", line, re.IGNORECASE):
                    for keyword in ["PASSWORD", "SECRET", "KEY", "TOKEN"]:
                        if keyword in line.upper():
                            findings.append({
                                "type": "docker_arg_secret",
                                "description": "Potential secret in Docker ARG (visible in image history)",
                                "severity": "high",
                                "file": str(docker_file),
                                "line": line_num,
                                "context": line[:100],
                            })
                            break

                # Check for COPY of secret files
                if re.match(r"^\s*COPY\s+", line, re.IGNORECASE):
                    secret_file_patterns = [".env", "credentials", "secrets", ".pem", ".key", "id_rsa"]
                    for pattern in secret_file_patterns:
                        if pattern in line.lower():
                            findings.append({
                                "type": "docker_copy_secret",
                                "description": f"Copying potential secret file into image",
                                "severity": "medium",
                                "file": str(docker_file),
                                "line": line_num,
                                "context": line[:100],
                            })
                            break

            findings.extend(file_findings)

        except (OSError, PermissionError) as e:
            findings.append({
                "type": "error",
                "file": str(docker_file),
                "error": str(e),
            })

    return {
        "action": "scan_docker",
        "path": path,
        "docker_files_found": len(docker_files),
        "secrets_found": len([f for f in findings if f.get("type") != "error"]),
        "findings": findings,
        "recommendation": "Use Docker secrets or external secret management" if findings else "No secrets detected in Docker configs",
    }


def _full_scan(
    path: str,
    exclude_patterns: list[str],
    depth: int = 100,
    custom_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """Run all scanning methods on a directory."""
    results = {
        "action": "full_scan",
        "path": path,
        "file_scan": _scan_files(path, exclude_patterns, custom_patterns),
        "git_scan": _scan_git_history(path, depth, custom_patterns),
        "env_scan": _scan_env_vars(),
        "docker_scan": _scan_docker(path, custom_patterns),
    }

    # Calculate totals
    total_secrets = (
        results["file_scan"].get("secrets_found", 0) +
        results["git_scan"].get("secrets_found", 0) +
        results["env_scan"].get("secrets_found", 0) +
        results["docker_scan"].get("secrets_found", 0)
    )

    total_critical = (
        results["file_scan"].get("critical_count", 0) +
        results["git_scan"].get("critical_count", 0) +
        results["env_scan"].get("critical_count", 0)
    )

    results["summary"] = {
        "total_secrets_found": total_secrets,
        "total_critical": total_critical,
        "risk_level": "critical" if total_critical > 0 else "high" if total_secrets > 5 else "medium" if total_secrets > 0 else "low",
    }

    return results


@register_tool
def secrets_extractor(
    action: SecretsAction,
    path: str | None = None,
    patterns: str | None = None,
    exclude: str | None = None,
    depth: int = 100,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Extract and detect secrets from files, git history, and Docker configs.

    Args:
        action: The extraction action to perform:
            - scan_files: Scan files/directories for secrets
            - scan_git_history: Search git history for leaked secrets
            - scan_env_vars: Check environment variables for secrets
            - scan_docker: Analyze Docker configs for exposed secrets
            - full_scan: Run all scanning methods
        path: Path to file or directory to scan
        patterns: Custom regex patterns (comma-separated)
        exclude: File patterns to exclude (comma-separated)
        depth: Number of git commits to search (default: 100)

    Returns:
        Extracted secrets with type, location, and redacted values
    """
    VALID_PARAMS = {"action", "path", "patterns", "exclude", "depth"}
    VALID_ACTIONS = ["scan_files", "scan_git_history", "scan_env_vars", "scan_docker", "full_scan"]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "secrets_extractor"):
        unknown_error.update(
            generate_usage_hint("secrets_extractor", "scan_files", {"path": "./src"})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "secrets_extractor"):
        action_error["usage_examples"] = {
            "scan_files": 'secrets_extractor(action="scan_files", path="./src")',
            "scan_git_history": 'secrets_extractor(action="scan_git_history", path=".", depth=50)',
            "full_scan": 'secrets_extractor(action="full_scan", path=".")',
        }
        return action_error

    # Parse custom patterns
    custom_patterns = [p.strip() for p in patterns.split(",")] if patterns else None

    # Parse exclude patterns
    exclude_patterns = DEFAULT_EXCLUDES.copy()
    if exclude:
        exclude_patterns.extend([p.strip() for p in exclude.split(",")])

    # Actions that require path
    if action in ["scan_files", "scan_git_history", "scan_docker", "full_scan"]:
        if param_error := validate_required_param(path, "path", action, "secrets_extractor"):
            param_error.update(generate_usage_hint("secrets_extractor", action, {"path": "."}))
            return param_error

        if not Path(path).exists():
            return {
                "error": f"Path does not exist: {path}",
                "hint": "Provide a valid file or directory path",
                "tool_name": "secrets_extractor",
            }

    if action == "scan_files":
        return _scan_files(path, exclude_patterns, custom_patterns)
    elif action == "scan_git_history":
        return _scan_git_history(path, depth, custom_patterns)
    elif action == "scan_env_vars":
        return _scan_env_vars()
    elif action == "scan_docker":
        return _scan_docker(path, custom_patterns)
    elif action == "full_scan":
        return _full_scan(path, exclude_patterns, depth, custom_patterns)

    return {"error": "Unknown action", "tool_name": "secrets_extractor"}
