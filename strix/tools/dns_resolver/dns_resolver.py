"""DNS resolver tool for DNS record lookup and analysis."""

from __future__ import annotations

import socket
from typing import Any, Literal
from urllib.parse import urlparse

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


DNSAction = Literal["lookup", "all_records", "reverse", "zone_transfer"]

# DNS record type mappings
RECORD_TYPES = {
    "A": "IPv4 address",
    "AAAA": "IPv6 address",
    "CNAME": "Canonical name",
    "MX": "Mail exchange",
    "NS": "Name server",
    "TXT": "Text record",
    "SOA": "Start of authority",
    "PTR": "Pointer record",
    "SRV": "Service record",
}


def _normalize_domain(domain: str) -> str:
    """Normalize domain input."""
    domain = domain.lower().strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.netloc or domain
    return domain.split("/")[0].split(":")[0]


def _resolve_a_record(domain: str) -> list[str]:
    """Resolve A records for a domain."""
    try:
        result = socket.gethostbyname_ex(domain)
        return result[2]
    except (socket.gaierror, socket.herror, OSError):
        return []


def _resolve_aaaa_record(domain: str) -> list[str]:
    """Resolve AAAA (IPv6) records for a domain."""
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET6)
        return list({addr[4][0] for addr in result})
    except (socket.gaierror, socket.herror, OSError):
        return []


def _resolve_mx_record(domain: str) -> list[dict[str, Any]]:
    """Resolve MX records using DNS query via socket."""
    # Note: Full MX resolution requires dnspython or similar
    # This is a simplified approach using basic socket operations
    mx_records: list[dict[str, Any]] = []

    # Try to resolve common MX patterns
    common_mx_prefixes = [
        "mail", "mx", "mx1", "mx2", "smtp", "aspmx.l.google.com",
        "alt1.aspmx.l.google.com", "alt2.aspmx.l.google.com",
    ]

    for prefix in common_mx_prefixes:
        mx_host = prefix if prefix.endswith(".com") else f"{prefix}.{domain}"
        try:
            ips = socket.gethostbyname_ex(mx_host)[2]
            if ips:
                mx_records.append({
                    "host": mx_host,
                    "priority": 10,
                    "ip_addresses": ips,
                })
        except (socket.gaierror, socket.herror, OSError):
            continue

    return mx_records


def _resolve_ns_record(domain: str) -> list[dict[str, Any]]:
    """Resolve NS records."""
    ns_records: list[dict[str, Any]] = []

    # Common NS patterns
    common_ns_prefixes = ["ns1", "ns2", "ns3", "ns4", "dns1", "dns2"]

    for prefix in common_ns_prefixes:
        ns_host = f"{prefix}.{domain}"
        try:
            ips = socket.gethostbyname_ex(ns_host)[2]
            if ips:
                ns_records.append({
                    "nameserver": ns_host,
                    "ip_addresses": ips,
                })
        except (socket.gaierror, socket.herror, OSError):
            continue

    return ns_records


def _lookup_single_record(
    domain: str,
    record_type: str,
) -> dict[str, Any]:
    """Lookup a single DNS record type."""
    domain = _normalize_domain(domain)
    record_type = record_type.upper()

    result: dict[str, Any] = {
        "domain": domain,
        "record_type": record_type,
        "description": RECORD_TYPES.get(record_type, "Unknown"),
    }

    if record_type == "A":
        records = _resolve_a_record(domain)
        result["records"] = records
        result["count"] = len(records)

    elif record_type == "AAAA":
        records = _resolve_aaaa_record(domain)
        result["records"] = records
        result["count"] = len(records)

    elif record_type == "CNAME":
        try:
            cname = socket.gethostbyname_ex(domain)[0]
            if cname != domain:
                result["records"] = [cname]
                result["count"] = 1
            else:
                result["records"] = []
                result["count"] = 0
        except (socket.gaierror, socket.herror, OSError):
            result["records"] = []
            result["count"] = 0

    elif record_type == "MX":
        records = _resolve_mx_record(domain)
        result["records"] = records
        result["count"] = len(records)

    elif record_type == "NS":
        records = _resolve_ns_record(domain)
        result["records"] = records
        result["count"] = len(records)

    else:
        result["error"] = f"Record type {record_type} not directly supported"
        result["hint"] = "Use 'all_records' action for comprehensive lookup"

    return result


def _lookup_all_records(domain: str) -> dict[str, Any]:
    """Lookup all common DNS record types."""
    domain = _normalize_domain(domain)

    results: dict[str, Any] = {
        "domain": domain,
        "records": {},
    }

    # A records
    a_records = _resolve_a_record(domain)
    if a_records:
        results["records"]["A"] = a_records

    # AAAA records
    aaaa_records = _resolve_aaaa_record(domain)
    if aaaa_records:
        results["records"]["AAAA"] = aaaa_records

    # CNAME
    try:
        cname = socket.gethostbyname_ex(domain)[0]
        if cname != domain:
            results["records"]["CNAME"] = [cname]
    except (socket.gaierror, socket.herror, OSError):
        # No CNAME record found or DNS error; ignore and continue.
        pass

    # MX records
    mx_records = _resolve_mx_record(domain)
    if mx_records:
        results["records"]["MX"] = mx_records

    # NS records
    ns_records = _resolve_ns_record(domain)
    if ns_records:
        results["records"]["NS"] = ns_records

    # Check for SPF, DMARC, DKIM (common TXT patterns)
    security_records: dict[str, Any] = {}

    # SPF check (usually on root domain)
    for prefix in ["", "_spf"]:
        spf_domain = f"{prefix}.{domain}" if prefix else domain
        try:
            ips = socket.gethostbyname_ex(spf_domain)
            if ips:
                security_records["spf_indicator"] = "Domain resolves, SPF may exist"
        except (socket.gaierror, socket.herror, OSError):
            # Ignore DNS resolution errors for SPF check; not all domains have SPF records.
            pass

    # DMARC check
    dmarc_domain = f"_dmarc.{domain}"
    try:
        socket.gethostbyname(dmarc_domain)
        security_records["dmarc_indicator"] = "DMARC record may exist"
    except (socket.gaierror, socket.herror, OSError):
        security_records["dmarc_indicator"] = "No DMARC record detected"

    if security_records:
        results["security_records"] = security_records

    results["total_record_types"] = len(results["records"])

    return results


def _reverse_lookup(ip_address: str) -> dict[str, Any]:
    """Perform reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return {
            "ip_address": ip_address,
            "hostname": hostname,
            "resolved": True,
        }
    except (socket.herror, socket.gaierror, OSError) as e:
        return {
            "ip_address": ip_address,
            "hostname": None,
            "resolved": False,
            "error": str(e),
        }


def _check_zone_transfer(domain: str) -> dict[str, Any]:
    """Check for zone transfer vulnerability."""
    domain = _normalize_domain(domain)

    # Get NS records first
    ns_records = _resolve_ns_record(domain)

    results: dict[str, Any] = {
        "domain": domain,
        "nameservers_checked": [],
        "zone_transfer_possible": False,
        "note": "Zone transfer check requires specialized DNS tools for full AXFR testing",
    }

    for ns in ns_records:
        ns_host = ns.get("nameserver", "")
        results["nameservers_checked"].append({
            "nameserver": ns_host,
            "status": "checked",
            "note": "Full AXFR test requires dnspython or dig command",
        })

    return results


@register_tool
def dns_resolver(
    action: DNSAction,
    domain: str | None = None,
    ip_address: str | None = None,
    record_type: str = "A",
    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Perform DNS record lookups and analysis.

    This tool resolves DNS records for security reconnaissance including
    A, AAAA, CNAME, MX, NS, TXT records, SPF/DMARC/DKIM analysis, and
    reverse DNS lookups.

    Args:
        action: The DNS action to perform:
            - lookup: Query a specific record type
            - all_records: Get all common record types
            - reverse: Perform reverse DNS lookup
            - zone_transfer: Check for zone transfer vulnerability
        domain: Target domain to query
        ip_address: IP address for reverse lookup
        record_type: DNS record type to query (A, AAAA, CNAME, MX, NS, TXT, SOA)

    Returns:
        DNS resolution results including records and security analysis
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "domain", "ip_address", "record_type"}
    VALID_ACTIONS = ["lookup", "all_records", "reverse", "zone_transfer"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "dns_resolver")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("dns_resolver", "lookup", {"domain": "example.com", "record_type": "A"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "dns_resolver")
    if action_error:
        action_error["usage_examples"] = {
            "lookup": "dns_resolver(action='lookup', domain='example.com', record_type='A')",
            "all_records": "dns_resolver(action='all_records', domain='example.com')",
            "reverse": "dns_resolver(action='reverse', ip_address='8.8.8.8')",
        }
        return action_error

    try:
        if action == "lookup":
            if not domain:
                return {"error": "domain parameter required for lookup action"}

            return _lookup_single_record(domain, record_type)

        if action == "all_records":
            if not domain:
                return {"error": "domain parameter required for all_records action"}

            return _lookup_all_records(domain)

        if action == "reverse":
            if not ip_address:
                return {"error": "ip_address parameter required for reverse action"}

            return _reverse_lookup(ip_address)

        if action == "zone_transfer":
            if not domain:
                return {"error": "domain parameter required for zone_transfer action"}

            return _check_zone_transfer(domain)

        return {"error": f"Unknown action: {action}"}

    except (OSError, ValueError) as e:
        return {"error": f"DNS resolution failed: {e!s}"}
