"""Subdomain Enumerator tool for subdomain discovery."""

from __future__ import annotations

import socket
from typing import Any, Literal
from urllib.parse import urlparse

from strix.tools.registry import register_tool


SubdomainAction = Literal["enumerate", "check", "wordlist"]


# Common subdomain wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "ns3", "blog", "pop3", "dev", "www2", "admin", "forum", "news",
    "vpn", "ns4", "www1", "mobile", "ssl", "shop", "ftp2", "api", "beta",
    "stage", "staging", "app", "apps", "cdn", "img", "images", "static",
    "assets", "media", "portal", "secure", "login", "auth", "account",
    "accounts", "my", "dashboard", "support", "help", "docs", "doc",
    "status", "services", "service", "web", "intranet", "internal",
    "git", "gitlab", "github", "jenkins", "ci", "build", "deploy",
    "prod", "production", "uat", "qa", "demo", "preview", "sandbox",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "search", "grafana", "prometheus", "kibana", "logs", "monitoring",
    "backup", "backups", "storage", "files", "download", "downloads",
    "upload", "uploads", "crm", "erp", "hr", "finance", "billing",
    "payment", "payments", "checkout", "cart", "store", "shop",
    "api-v1", "api-v2", "v1", "v2", "legacy", "old", "new",
    "mx", "mx1", "mx2", "email", "mail2", "remote", "exchange",
    "owa", "webaccess", "citrix", "sharepoint", "confluence", "jira",
    "slack", "teams", "zoom", "calendar", "meet", "video",
]


def _resolve_subdomain(subdomain: str, domain: str) -> dict[str, Any] | None:
    """Attempt to resolve a subdomain."""
    fqdn = f"{subdomain}.{domain}"

    try:
        # Try to resolve A record
        ip_addresses = socket.gethostbyname_ex(fqdn)[2]
    except (socket.gaierror, socket.herror, OSError):
        return None
    else:
        return {
            "subdomain": subdomain,
            "fqdn": fqdn,
            "ip_addresses": ip_addresses,
            "resolved": True,
        }


def _check_wildcard(domain: str) -> bool:
    """Check if domain has wildcard DNS."""
    random_subdomain = f"random-nonexistent-{hash(domain) % 10000}"
    result = _resolve_subdomain(random_subdomain, domain)
    return result is not None


def _enumerate_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    timeout: int = 2,
) -> dict[str, Any]:
    """Enumerate subdomains for a domain."""
    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    # Set DNS timeout
    socket.setdefaulttimeout(timeout)

    # Check for wildcard DNS
    has_wildcard = _check_wildcard(domain)
    wildcard_ips: set[str] = set()

    if has_wildcard:
        # Get wildcard IP(s) for filtering
        random_result = _resolve_subdomain(f"random-{hash(domain) % 10000}", domain)
        if random_result:
            wildcard_ips = set(random_result["ip_addresses"])

    found_subdomains: list[dict[str, Any]] = []

    for subdomain in wordlist:
        result = _resolve_subdomain(subdomain, domain)

        if result:
            # Filter out wildcard results
            if has_wildcard and set(result["ip_addresses"]) == wildcard_ips:
                continue

            found_subdomains.append(result)

    return {
        "domain": domain,
        "has_wildcard": has_wildcard,
        "wildcard_ips": list(wildcard_ips) if wildcard_ips else None,
        "subdomains_found": len(found_subdomains),
        "subdomains": found_subdomains,
        "wordlist_size": len(wordlist),
    }


def _check_single_subdomain(subdomain: str, domain: str) -> dict[str, Any]:
    """Check if a single subdomain exists."""
    result = _resolve_subdomain(subdomain, domain)

    if result:
        return {
            "exists": True,
            **result,
        }
    return {
        "exists": False,
        "subdomain": subdomain,
        "fqdn": f"{subdomain}.{domain}",
    }


@register_tool
def subdomain_enum(
    action: SubdomainAction,
    domain: str,
    subdomain: str | None = None,
    wordlist: list[str] | None = None,
    timeout: int = 2,
) -> dict[str, Any]:
    """Enumerate subdomains for a target domain.

    This tool performs subdomain enumeration using DNS resolution
    with a configurable wordlist. It includes wildcard detection
    to filter false positives.

    Args:
        action: The enumeration action to perform:
            - enumerate: Full subdomain enumeration with wordlist
            - check: Check if a specific subdomain exists
            - wordlist: List available wordlist entries
        domain: Target domain to enumerate (e.g., example.com)
        subdomain: Specific subdomain to check (for check action)
        wordlist: Custom wordlist to use (optional)
        timeout: DNS resolution timeout in seconds (default: 2)

    Returns:
        Enumeration results including found subdomains and their IP addresses
    """
    try:
        # Clean domain input
        domain = domain.lower().strip()
        if domain.startswith(("http://", "https://")):
            domain = urlparse(domain).netloc or domain
        domain = domain.split("/")[0]  # Remove any path

        if action == "enumerate":
            return _enumerate_subdomains(domain, wordlist, timeout)

        if action == "check":
            if not subdomain:
                return {"error": "subdomain parameter required for check action"}

            return _check_single_subdomain(subdomain, domain)

        if action == "wordlist":
            return {
                "wordlist": COMMON_SUBDOMAINS,
                "total_entries": len(COMMON_SUBDOMAINS),
                "description": "Common subdomain wordlist for enumeration",
            }

        return {"error": f"Unknown action: {action}"}

    except (OSError, ValueError) as e:
        return {"error": f"Subdomain enumeration failed: {e!s}"}
