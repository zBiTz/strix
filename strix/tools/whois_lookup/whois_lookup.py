"""WHOIS lookup tool for domain information gathering."""

from __future__ import annotations

import socket
from typing import Any, Literal
from urllib.parse import urlparse

from strix.tools.registry import register_tool


WhoisAction = Literal["lookup", "registrar", "dates"]

# WHOIS server mappings by TLD
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "eu": "whois.eu",
    "nl": "whois.domain-registry.nl",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "ru": "whois.tcinet.ru",
    "cn": "whois.cnnic.cn",
    "jp": "whois.jprs.jp",
    "kr": "whois.kr",
    "br": "whois.registro.br",
    "in": "whois.registry.in",
    "edu": "whois.educause.edu",
    "gov": "whois.dotgov.gov",
    "mil": "whois.nic.mil",
    "biz": "whois.biz",
    "mobi": "whois.dotmobi.mobi",
    "name": "whois.nic.name",
    "tv": "whois.nic.tv",
    "cc": "ccwhois.verisign-grs.com",
}


def _normalize_domain(domain: str) -> str:
    """Normalize domain input."""
    domain = domain.lower().strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.netloc or domain
    domain = domain.split("/")[0].split(":")[0]

    # Remove www. prefix
    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def _get_tld(domain: str) -> str:
    """Extract TLD from domain."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-1]
    return ""


def _get_whois_server(domain: str) -> str:
    """Get WHOIS server for domain."""
    tld = _get_tld(domain)
    return WHOIS_SERVERS.get(tld, "whois.iana.org")


def _query_whois(domain: str, server: str) -> str:
    """Query WHOIS server for domain information."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, 43))
        sock.send(f"{domain}\r\n".encode())

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()
        return response.decode("utf-8", errors="ignore")
    except (OSError, TimeoutError) as e:
        return f"Error: {e!s}"


def _parse_whois_response(response: str) -> dict[str, Any]:
    """Parse WHOIS response into structured data."""
    data: dict[str, Any] = {
        "raw_response": response,
        "parsed": {},
    }

    # Common WHOIS field mappings
    field_mappings = {
        "domain name": "domain_name",
        "registrar": "registrar",
        "registrar url": "registrar_url",
        "registrar whois server": "registrar_whois",
        "creation date": "creation_date",
        "updated date": "updated_date",
        "registry expiry date": "expiry_date",
        "expiration date": "expiry_date",
        "registrant name": "registrant_name",
        "registrant organization": "registrant_org",
        "registrant country": "registrant_country",
        "name server": "name_servers",
        "nserver": "name_servers",
        "dnssec": "dnssec",
        "status": "status",
        "domain status": "status",
    }

    parsed = data["parsed"]
    name_servers: list[str] = []
    statuses: list[str] = []

    for raw_line in response.split("\n"):
        line = raw_line.strip()
        if ":" not in line:
            continue

        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if not value:
            continue

        for pattern, field in field_mappings.items():
            if pattern in key:
                if field == "name_servers":
                    name_servers.append(value)
                elif field == "status":
                    statuses.append(value)
                elif field not in parsed:
                    parsed[field] = value
                break

    if name_servers:
        parsed["name_servers"] = name_servers

    if statuses:
        parsed["statuses"] = statuses

    # Check for privacy protection
    privacy_indicators = ["privacy", "proxy", "redacted", "protected", "private"]
    for field_value in parsed.values():
        if isinstance(field_value, str) and \
                any(ind in field_value.lower() for ind in privacy_indicators):
            parsed["privacy_protected"] = True
            break
    else:
        parsed["privacy_protected"] = False

    return data


def _lookup_domain(domain: str) -> dict[str, Any]:
    """Perform full WHOIS lookup for a domain."""
    domain = _normalize_domain(domain)
    whois_server = _get_whois_server(domain)

    response = _query_whois(domain, whois_server)

    if response.startswith("Error:"):
        return {
            "domain": domain,
            "whois_server": whois_server,
            "error": response,
        }

    parsed = _parse_whois_response(response)

    return {
        "domain": domain,
        "whois_server": whois_server,
        "tld": _get_tld(domain),
        **parsed,
    }


def _get_registrar_info(domain: str) -> dict[str, Any]:
    """Get registrar information for a domain."""
    result = _lookup_domain(domain)

    if "error" in result:
        return result

    parsed = result.get("parsed", {})

    return {
        "domain": result.get("domain", ""),
        "registrar": parsed.get("registrar", "Unknown"),
        "registrar_url": parsed.get("registrar_url", ""),
        "registrar_whois": parsed.get("registrar_whois", ""),
        "name_servers": parsed.get("name_servers", []),
        "dnssec": parsed.get("dnssec", "Unknown"),
    }


def _get_dates(domain: str) -> dict[str, Any]:
    """Get registration dates for a domain."""
    result = _lookup_domain(domain)

    if "error" in result:
        return result

    parsed = result.get("parsed", {})

    return {
        "domain": result.get("domain", ""),
        "creation_date": parsed.get("creation_date", "Unknown"),
        "updated_date": parsed.get("updated_date", "Unknown"),
        "expiry_date": parsed.get("expiry_date", "Unknown"),
        "statuses": parsed.get("statuses", []),
    }


@register_tool
def whois_lookup(
    action: WhoisAction,
    domain: str,
) -> dict[str, Any]:
    """Perform WHOIS lookups for domain information gathering.

    This tool queries WHOIS servers to retrieve domain registration
    information including registrar details, registration dates,
    nameservers, and privacy protection status.

    Args:
        action: The lookup action to perform:
            - lookup: Full WHOIS lookup with all available information
            - registrar: Get registrar and nameserver information
            - dates: Get registration, update, and expiry dates
        domain: Target domain to query

    Returns:
        WHOIS information including registration details and dates
    """
    try:
        if action == "lookup":
            return _lookup_domain(domain)

        if action == "registrar":
            return _get_registrar_info(domain)

        if action == "dates":
            return _get_dates(domain)

        return {"error": f"Unknown action: {action}"}

    except (OSError, ValueError) as e:
        return {"error": f"WHOIS lookup failed: {e!s}"}
