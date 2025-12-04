"""Secret Scanner tool for detecting exposed secrets and credentials."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


SecretAction = Literal["scan", "scan_text", "list_patterns"]


# Secret patterns with their descriptions and severity
SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "description": "AWS Access Key ID",
        "severity": "critical",
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "description": "AWS Secret Access Key",
        "severity": "critical",
    },
    "github_token": {
        "pattern": (
            r"ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}"
            r"|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}"
        ),
        "description": "GitHub Personal Access Token",
        "severity": "critical",
    },
    "github_oauth": {
        "pattern": r"gho_[a-zA-Z0-9]{36}",
        "description": "GitHub OAuth Token",
        "severity": "critical",
    },
    "stripe_secret": {
        "pattern": r"sk_live_[a-zA-Z0-9]{24,}",
        "description": "Stripe Secret Key (Live)",
        "severity": "critical",
    },
    "stripe_test": {
        "pattern": r"sk_test_[a-zA-Z0-9]{24,}",
        "description": "Stripe Secret Key (Test)",
        "severity": "high",
    },
    "stripe_publishable": {
        "pattern": r"pk_(?:live|test)_[a-zA-Z0-9]{24,}",
        "description": "Stripe Publishable Key",
        "severity": "low",
    },
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "description": "Google API Key",
        "severity": "high",
    },
    "google_oauth": {
        "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "description": "Google OAuth Client ID",
        "severity": "medium",
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "description": "Slack Token",
        "severity": "critical",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}",
        "description": "Slack Webhook URL",
        "severity": "high",
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
        "description": "Discord Webhook URL",
        "severity": "high",
    },
    "twilio_api_key": {
        "pattern": r"SK[a-f0-9]{32}",
        "description": "Twilio API Key",
        "severity": "critical",
    },
    "sendgrid_api_key": {
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "description": "SendGrid API Key",
        "severity": "critical",
    },
    "mailchimp_api_key": {
        "pattern": r"[a-f0-9]{32}-us[0-9]{1,2}",
        "description": "Mailchimp API Key",
        "severity": "high",
    },
    "jwt_token": {
        "pattern": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        "description": "JSON Web Token",
        "severity": "medium",
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "description": "Private Key",
        "severity": "critical",
    },
    "heroku_api_key": {
        "pattern": (
            r"(?i)heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
            r"-[0-9a-f]{4}-[0-9a-f]{12}['\"]"
        ),
        "description": "Heroku API Key",
        "severity": "critical",
    },
    "firebase_url": {
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "description": "Firebase Database URL",
        "severity": "medium",
    },
    "firebase_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "description": "Firebase API Key",
        "severity": "high",
    },
    "azure_storage_key": {
        "pattern": (
            r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+"
            r";AccountKey=[A-Za-z0-9+/=]{88}"
        ),
        "description": "Azure Storage Connection String",
        "severity": "critical",
    },
    "shopify_token": {
        "pattern": r"shpat_[a-fA-F0-9]{32}",
        "description": "Shopify Access Token",
        "severity": "critical",
    },
    "npm_token": {
        "pattern": r"npm_[a-zA-Z0-9]{36}",
        "description": "NPM Access Token",
        "severity": "critical",
    },
    "pypi_token": {
        "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
        "description": "PyPI API Token",
        "severity": "critical",
    },
    "password_in_url": {
        "pattern": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}",
        "description": "Password in URL",
        "severity": "high",
    },
    "generic_api_key": {
        "pattern": (
            r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*"
            r"['\"][a-zA-Z0-9_\-]{20,}['\"]"
        ),
        "description": "Generic API Key",
        "severity": "high",
    },
    "generic_secret": {
        "pattern": r"(?i)(?:secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "description": "Generic Secret/Password",
        "severity": "high",
    },
    "basic_auth": {
        "pattern": r"(?i)authorization:\s*basic\s+[a-zA-Z0-9+/=]{10,}",
        "description": "Basic Authentication Header",
        "severity": "high",
    },
    "bearer_token": {
        "pattern": r"(?i)authorization:\s*bearer\s+[a-zA-Z0-9_\-.]{20,}",
        "description": "Bearer Token Header",
        "severity": "high",
    },
}


def _scan_for_secrets(
    text: str,
    patterns: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Scan text for secrets using defined patterns."""
    if patterns is None:
        patterns = SECRET_PATTERNS

    findings: list[dict[str, Any]] = []

    for name, info in patterns.items():
        pattern = info["pattern"]
        try:
            matches = re.finditer(pattern, text)
            for match in matches:
                # Get context around the match
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end]

                # Mask the actual secret value
                secret_value = match.group()
                if len(secret_value) > 12:
                    masked = secret_value[:4] + "*" * (len(secret_value) - 8) + secret_value[-4:]
                elif len(secret_value) > 6:
                    masked = secret_value[:2] + "*" * (len(secret_value) - 4) + secret_value[-2:]
                else:
                    masked = "*" * len(secret_value)

                findings.append({
                    "type": name,
                    "description": info["description"],
                    "severity": info["severity"],
                    "masked_value": masked,
                    "context": f"...{context}...",
                    "position": {"start": match.start(), "end": match.end()},
                })
        except re.error:
            continue

    return findings


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    counter = Counter(text)
    length = len(text)
    entropy = 0.0

    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def _scan_high_entropy(
    text: str,
    min_length: int = 20,
    threshold: float = 4.0,
) -> list[dict[str, Any]]:
    """Scan for high-entropy strings that might be secrets."""
    findings: list[dict[str, Any]] = []

    # Pattern to find potential secrets (alphanumeric strings)
    pattern = r"[a-zA-Z0-9_\-+/]{20,}"

    for match in re.finditer(pattern, text):
        value = match.group()
        entropy = _calculate_entropy(value)

        if entropy >= threshold:
            # Mask the value
            masked = value[:4] + "*" * (len(value) - 8) + value[-4:]

            findings.append({
                "type": "high_entropy_string",
                "description": "High-entropy string (potential secret)",
                "severity": "medium",
                "masked_value": masked,
                "entropy": round(entropy, 2),
                "position": {"start": match.start(), "end": match.end()},
            })

    return findings


@register_tool
def secret_scanner(
    action: SecretAction,
    text: str | None = None,
    include_entropy: bool = True,
    custom_patterns: dict[str, dict[str, Any]] | None = None,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Scan text for exposed secrets, API keys, and credentials.

    This tool detects various types of secrets including:
    - Cloud provider credentials (AWS, GCP, Azure)
    - API keys (Stripe, Twilio, SendGrid, etc.)
    - Authentication tokens (JWT, OAuth, Bearer)
    - Private keys and certificates
    - Database connection strings
    - High-entropy strings that may be secrets

    Args:
        action: The scanning action to perform:
            - scan: Scan text for all known secret patterns
            - scan_text: Alias for scan
            - list_patterns: List all available detection patterns
        text: Text content to scan for secrets
        include_entropy: Include high-entropy string detection (default: True)
        custom_patterns: Additional custom patterns to scan for

    Returns:
        Scan results including found secrets, severity, and recommendations
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "text", "include_entropy", "custom_patterns"}
    VALID_ACTIONS = ["scan", "scan_text", "list_patterns"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "secret_scanner")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "secret_scanner",
                "scan",
                {"text": "Some text with potential secrets..."},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "secret_scanner")
    if action_error:
        action_error["usage_examples"] = {
            "scan": "secret_scanner(action='scan', text='Some text with secrets...')",
            "scan_text": "secret_scanner(action='scan_text', text='Code content here...')",
            "list_patterns": "secret_scanner(action='list_patterns')",
        }
        return action_error

    # Validate required parameters based on action
    if action in ("scan", "scan_text"):
        text_error = validate_required_param(text, "text", action, "secret_scanner")
        if text_error:
            text_error.update(
                generate_usage_hint(
                    "secret_scanner",
                    action,
                    {"text": "Some text with potential secrets..."},
                )
            )
            return text_error

    try:
        if action in ("scan", "scan_text"):
            if not text:
                return {"error": "text parameter required for this action"}

            # Combine default and custom patterns
            patterns = dict(SECRET_PATTERNS)
            if custom_patterns:
                patterns.update(custom_patterns)

            # Scan for known patterns
            findings = _scan_for_secrets(text, patterns)

            # Optionally scan for high-entropy strings
            if include_entropy:
                entropy_findings = _scan_high_entropy(text)
                findings.extend(entropy_findings)

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
                    "Rotate any exposed credentials immediately",
                    "Remove secrets from source code and use environment variables",
                    "Use secret management tools (Vault, AWS Secrets Manager, etc.)",
                    "Enable secret scanning in your CI/CD pipeline",
                    "Review git history for previously committed secrets",
                ] if findings else ["No secrets detected in the scanned content"],
            }

        if action == "list_patterns":
            return {
                "patterns": [
                    {
                        "name": name,
                        "description": info["description"],
                        "severity": info["severity"],
                    }
                    for name, info in SECRET_PATTERNS.items()
                ],
                "total_patterns": len(SECRET_PATTERNS),
            }

        return {"error": f"Unknown action: {action}"}

    except (re.error, ValueError) as e:
        return {"error": f"Secret scanning failed: {e!s}"}
