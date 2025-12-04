"""ASN and IP range lookup tool for network reconnaissance."""

from __future__ import annotations

import socket
from typing import Any, Literal

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


ASNAction = Literal["lookup_ip", "lookup_asn", "prefixes"]


def _lookup_ip_info(ip_address: str) -> dict[str, Any]:
    """Lookup ASN and network info for an IP address."""
    try:
        # Use ipinfo.io API for ASN lookup
        response = requests.get(
            f"https://ipinfo.io/{ip_address}/json",
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        asn_org = data.get("org", "")
        asn = ""
        org = ""
        if asn_org:
            parts = asn_org.split(" ", 1)
            if parts[0].startswith("AS"):
                asn = parts[0]
                org = parts[1] if len(parts) > 1 else ""

        return {
            "ip_address": ip_address,
            "asn": asn,
            "organization": org,
            "hostname": data.get("hostname", ""),
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
            "location": data.get("loc", ""),
            "timezone": data.get("timezone", ""),
        }

    except requests.exceptions.RequestException as e:
        return {
            "ip_address": ip_address,
            "error": f"Lookup failed: {e!s}",
        }


def _lookup_asn_info(asn: str) -> dict[str, Any]:
    """Lookup information for an ASN."""
    # Normalize ASN format
    asn = asn.upper().replace("AS", "").strip()

    try:
        # Use BGPView API for ASN info
        response = requests.get(
            f"https://api.bgpview.io/asn/{asn}",
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "ok":
            return {
                "asn": f"AS{asn}",
                "error": data.get("status_message", "Unknown error"),
            }

        asn_data = data.get("data", {})

        return {
            "asn": f"AS{asn}",
            "name": asn_data.get("name", ""),
            "description": asn_data.get("description_short", ""),
            "country_code": asn_data.get("country_code", ""),
            "website": asn_data.get("website", ""),
            "email_contacts": asn_data.get("email_contacts", []),
            "abuse_contacts": asn_data.get("abuse_contacts", []),
            "rir_allocation": {
                "rir_name": asn_data.get("rir_allocation", {}).get("rir_name", ""),
                "date_allocated": asn_data.get(
                    "rir_allocation", {},
                ).get("date_allocated", ""),
            },
        }

    except requests.exceptions.RequestException as e:
        return {
            "asn": f"AS{asn}",
            "error": f"Lookup failed: {e!s}",
        }


def _lookup_prefixes(asn: str) -> dict[str, Any]:
    """Lookup IP prefixes announced by an ASN."""
    # Normalize ASN format
    asn = asn.upper().replace("AS", "").strip()

    try:
        response = requests.get(
            f"https://api.bgpview.io/asn/{asn}/prefixes",
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "ok":
            return {
                "asn": f"AS{asn}",
                "error": data.get("status_message", "Unknown error"),
            }

        prefix_data = data.get("data", {})

        ipv4_prefixes = []
        for prefix in prefix_data.get("ipv4_prefixes", []):
            ipv4_prefixes.append({
                "prefix": prefix.get("prefix", ""),
                "ip": prefix.get("ip", ""),
                "cidr": prefix.get("cidr", 0),
                "name": prefix.get("name", ""),
                "description": prefix.get("description", ""),
                "country_code": prefix.get("country_code", ""),
            })

        ipv6_prefixes = []
        for prefix in prefix_data.get("ipv6_prefixes", []):
            ipv6_prefixes.append({
                "prefix": prefix.get("prefix", ""),
                "ip": prefix.get("ip", ""),
                "cidr": prefix.get("cidr", 0),
                "name": prefix.get("name", ""),
                "description": prefix.get("description", ""),
                "country_code": prefix.get("country_code", ""),
            })

        return {
            "asn": f"AS{asn}",
            "ipv4_prefix_count": len(ipv4_prefixes),
            "ipv6_prefix_count": len(ipv6_prefixes),
            "ipv4_prefixes": ipv4_prefixes,
            "ipv6_prefixes": ipv6_prefixes,
        }

    except requests.exceptions.RequestException as e:
        return {
            "asn": f"AS{asn}",
            "error": f"Prefix lookup failed: {e!s}",
        }


def _resolve_domain_to_ip(domain: str) -> str | None:
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.herror, OSError):
        return None


@register_tool
def asn_lookup(
    action: ASNAction,
    ip_address: str | None = None,
    asn: str | None = None,
    domain: str | None = None,
    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Lookup ASN and IP range information for network reconnaissance.

    This tool queries ASN databases to map IP addresses to their
    autonomous systems, find related IP ranges, and enumerate
    an organization's network infrastructure.

    Args:
        action: The lookup action to perform:
            - lookup_ip: Get ASN info for an IP address
            - lookup_asn: Get details for an ASN number
            - prefixes: Get IP prefixes announced by an ASN
        ip_address: IP address to lookup (for lookup_ip)
        asn: ASN number to lookup (for lookup_asn, prefixes)
        domain: Domain to resolve and lookup (alternative to ip_address)

    Returns:
        ASN information, IP ranges, and network details
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "ip_address", "asn", "domain"}
    VALID_ACTIONS = ["lookup_ip", "lookup_asn", "prefixes"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "asn_lookup")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("asn_lookup", "lookup_ip", {"ip_address": "8.8.8.8"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "asn_lookup")
    if action_error:
        action_error["usage_examples"] = {
            "lookup_ip": "asn_lookup(action='lookup_ip', ip_address='8.8.8.8')",
            "lookup_asn": "asn_lookup(action='lookup_asn', asn='AS15169')",
            "prefixes": "asn_lookup(action='prefixes', asn='AS15169')",
        }
        return action_error

    try:
        if action == "lookup_ip":
            if domain and not ip_address:
                ip_address = _resolve_domain_to_ip(domain)
                if not ip_address:
                    return {"error": f"Could not resolve domain: {domain}"}

            if not ip_address:
                return {"error": "ip_address or domain parameter required"}

            return _lookup_ip_info(ip_address)

        if action == "lookup_asn":
            if not asn:
                return {"error": "asn parameter required for lookup_asn action"}

            return _lookup_asn_info(asn)

        if action == "prefixes":
            if not asn:
                return {"error": "asn parameter required for prefixes action"}

            return _lookup_prefixes(asn)

        return {"error": f"Unknown action: {action}"}

    except (OSError, ValueError) as e:
        return {"error": f"ASN lookup failed: {e!s}"}
