"""JS Link Extractor tool for extracting API endpoints and secrets from JavaScript."""

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


JSExtractorAction = Literal["extract_all", "extract_endpoints", "extract_secrets", "extract_domains"]


# Regex patterns for extraction
ENDPOINT_PATTERNS = [
    r'["\'](?P<endpoint>/api/[^"\']+)["\']',
    r'["\'](?P<endpoint>/v[0-9]+/[^"\']+)["\']',
    r'["\'](?P<endpoint>/graphql[^"\']*)["\']',
    r'["\'](?P<endpoint>/rest/[^"\']+)["\']',
    r'fetch\s*\(\s*["\'](?P<endpoint>[^"\']+)["\']',
    r'axios\.[a-z]+\s*\(\s*["\'](?P<endpoint>[^"\']+)["\']',
    r'\.(?:get|post|put|delete|patch)\s*\(\s*["\'](?P<endpoint>[^"\']+)["\']',
    r'url\s*[:=]\s*["\'](?P<endpoint>[^"\']+)["\']',
    r'endpoint\s*[:=]\s*["\'](?P<endpoint>[^"\']+)["\']',
    r'path\s*[:=]\s*["\'](?P<endpoint>/[^"\']+)["\']',
]

SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key": r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}",
    "aws_secret_key": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
    "github_token": r"ghp_[A-Za-z0-9_]{36}|gho_[A-Za-z0-9_]{36}|ghu_[A-Za-z0-9_]{36}|ghs_[A-Za-z0-9_]{36}|ghr_[A-Za-z0-9_]{36}",
    "gitlab_token": r"glpat-[A-Za-z0-9\-_]{20,}",
    "google_api_key": r"AIza[A-Za-z0-9_-]{35}",
    "google_oauth": r"[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com",
    "firebase": r"[a-zA-Z0-9-]+\.firebaseio\.com|[a-zA-Z0-9-]+\.firebaseapp\.com",
    "stripe_key": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9-]+",
    "slack_webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    "jwt_token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY",
    "heroku_api_key": r"[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "twilio": r"SK[a-f0-9]{32}",
    "sendgrid": r"SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "mailchimp": r"[a-f0-9]{32}-us[0-9]+",
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    "pypi_token": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}",
    "basic_auth": r"[Bb]asic\s+[A-Za-z0-9+/]+=*",
    "bearer_token": r"[Bb]earer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "api_key_generic": r'(?:api[_-]?key|apikey|api[_-]?secret|apiSecret)\s*[=:]\s*["\'][A-Za-z0-9_-]{16,}["\']',
    "password_field": r'(?:password|passwd|pwd|secret)\s*[=:]\s*["\'][^"\']{4,}["\']',
}

DOMAIN_PATTERNS = [
    r'https?://[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:/[^\s"\'<>]*)?',
    r'[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|io|dev|app|co|edu|gov)[^\s"\'<>]*',
]


def _extract_endpoints(js_content: str) -> list[dict[str, Any]]:
    """Extract API endpoints from JavaScript content."""
    endpoints: list[dict[str, Any]] = []
    seen: set[str] = set()

    for pattern in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, js_content, re.IGNORECASE):
            endpoint = match.group("endpoint") if "endpoint" in match.groupdict() else match.group(1)
            if endpoint and endpoint not in seen:
                seen.add(endpoint)

                # Categorize endpoint
                category = "api"
                if "/auth" in endpoint.lower() or "/login" in endpoint.lower():
                    category = "authentication"
                elif "/admin" in endpoint.lower():
                    category = "admin"
                elif "/user" in endpoint.lower() or "/profile" in endpoint.lower():
                    category = "user"
                elif "/upload" in endpoint.lower() or "/file" in endpoint.lower():
                    category = "file"
                elif "graphql" in endpoint.lower():
                    category = "graphql"

                endpoints.append({
                    "endpoint": endpoint,
                    "category": category,
                    "method": _guess_method(js_content, endpoint),
                })

    return endpoints


def _guess_method(content: str, endpoint: str) -> str:
    """Guess HTTP method used for endpoint based on context."""
    # Find the context around this endpoint
    escaped_endpoint = re.escape(endpoint)
    context_pattern = rf".{{0,50}}{escaped_endpoint}.{{0,50}}"
    context_match = re.search(context_pattern, content)

    if context_match:
        context = context_match.group(0).lower()
        if any(method in context for method in ["post", "create", "add", "submit"]):
            return "POST"
        if any(method in context for method in ["put", "update", "edit", "modify"]):
            return "PUT"
        if any(method in context for method in ["delete", "remove"]):
            return "DELETE"
        if "patch" in context:
            return "PATCH"

    return "GET"


def _extract_secrets(js_content: str) -> list[dict[str, Any]]:
    """Extract potential secrets from JavaScript content."""
    secrets: list[dict[str, Any]] = []
    seen: set[str] = set()

    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, js_content):
            value = match.group(0)

            # Skip if too short or already seen
            if len(value) < 8 or value in seen:
                continue

            # Skip common false positives
            if _is_false_positive(value, secret_type):
                continue

            seen.add(value)
            secrets.append({
                "type": secret_type,
                "value": _mask_secret(value),
                "full_match": value[:50] + "..." if len(value) > 50 else value,
                "severity": _get_secret_severity(secret_type),
            })

    return secrets


def _is_false_positive(value: str, secret_type: str) -> bool:
    """Check if a match is likely a false positive."""
    # Skip example/placeholder values
    placeholders = ["example", "test", "demo", "sample", "placeholder", "xxx", "your-"]
    if any(p in value.lower() for p in placeholders):
        return True

    # Skip very short matches for certain types
    if secret_type in ["aws_secret_key", "api_key_generic"] and len(value) < 20:
        return True

    return False


def _mask_secret(value: str) -> str:
    """Mask secret value for safe display."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _get_secret_severity(secret_type: str) -> str:
    """Get severity level for secret type."""
    high_severity = ["aws_access_key", "aws_secret_key", "private_key", "stripe_key", "github_token"]
    medium_severity = ["google_api_key", "slack_token", "jwt_token", "bearer_token"]

    if secret_type in high_severity:
        return "high"
    if secret_type in medium_severity:
        return "medium"
    return "low"


def _extract_domains(js_content: str) -> list[dict[str, Any]]:
    """Extract domains and URLs from JavaScript content."""
    domains: list[dict[str, Any]] = []
    seen: set[str] = set()

    for pattern in DOMAIN_PATTERNS:
        for match in re.finditer(pattern, js_content):
            url = match.group(0).rstrip(".,;:)\"'")

            # Extract base domain
            domain_match = re.search(r"https?://([^/\s]+)", url)
            if domain_match:
                domain = domain_match.group(1)
            else:
                domain = url.split("/")[0]

            if domain not in seen and len(domain) > 3:
                seen.add(domain)

                # Categorize domain
                domain_type = "external"
                if any(cdn in domain.lower() for cdn in ["cdn", "static", "assets", "cloudfront", "akamai"]):
                    domain_type = "cdn"
                elif any(api in domain.lower() for api in ["api", "gateway", "backend"]):
                    domain_type = "api"
                elif any(internal in domain.lower() for internal in ["internal", "local", "dev", "staging"]):
                    domain_type = "internal"

                domains.append({
                    "domain": domain,
                    "full_url": url[:100] if len(url) > 100 else url,
                    "type": domain_type,
                })

    return domains


@register_tool
def js_link_extractor(
    action: JSExtractorAction,
    js_content: str,
    include_comments: bool = False,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Extract API endpoints, secrets, and sensitive data from JavaScript files.

    This tool analyzes JavaScript content to discover hidden endpoints,
    leaked secrets, and other security-relevant information.

    Args:
        action: The extraction action to perform:
            - extract_all: Extract endpoints, secrets, and domains
            - extract_endpoints: Extract API endpoints only
            - extract_secrets: Extract potential secrets only
            - extract_domains: Extract domains and URLs only
        js_content: JavaScript file content to analyze
        include_comments: Whether to include commented code in analysis

    Returns:
        Extracted endpoints, secrets, domains, and analysis summary
    """
    try:
        # Optionally remove comments
        content = js_content
        if not include_comments:
            # Remove single-line comments
            content = re.sub(r"//[^\n]*", "", content)
            # Remove multi-line comments
            content = re.sub(r"/\*[\s\S]*?\*/", "", content)

        if action == "extract_all":
            endpoints = _extract_endpoints(content)
            secrets = _extract_secrets(content)
            domains = _extract_domains(content)

            return {
                "endpoints": endpoints,
                "endpoint_count": len(endpoints),
                "secrets": secrets,
                "secret_count": len(secrets),
                "domains": domains,
                "domain_count": len(domains),
                "summary": {
                    "total_findings": len(endpoints) + len(secrets) + len(domains),
                    "high_severity_secrets": len([s for s in secrets if s["severity"] == "high"]),
                    "auth_endpoints": len([e for e in endpoints if e["category"] == "authentication"]),
                    "admin_endpoints": len([e for e in endpoints if e["category"] == "admin"]),
                },
            }

        if action == "extract_endpoints":
            endpoints = _extract_endpoints(content)
            return {
                "endpoints": endpoints,
                "count": len(endpoints),
                "by_category": _group_by_key(endpoints, "category"),
                "by_method": _group_by_key(endpoints, "method"),
            }

        if action == "extract_secrets":
            secrets = _extract_secrets(content)
            return {
                "secrets": secrets,
                "count": len(secrets),
                "by_type": _group_by_key(secrets, "type"),
                "by_severity": _group_by_key(secrets, "severity"),
            }

        if action == "extract_domains":
            domains = _extract_domains(content)
            return {
                "domains": domains,
                "count": len(domains),
                "by_type": _group_by_key(domains, "type"),
            }

        return {"error": f"Unknown action: {action}"}

    except (TypeError, ValueError, re.error) as e:
        return {"error": f"Extraction failed: {e!s}"}


def _group_by_key(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    """Group items by a key and count occurrences."""
    groups: dict[str, int] = {}
    for item in items:
        value = item.get(key, "unknown")
        groups[value] = groups.get(value, 0) + 1
    return groups
