"""Rate limit testing tool for API security analysis."""

from __future__ import annotations

import time
from typing import Any, Literal
from urllib.parse import urlparse

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


RateLimitAction = Literal["detect", "test_bypass", "analyze"]

# Common bypass headers
BYPASS_HEADERS = {
    "x-forwarded-for": ["127.0.0.1", "10.0.0.1", "192.168.1.1"],
    "x-real-ip": ["127.0.0.1", "10.0.0.1"],
    "x-originating-ip": ["127.0.0.1"],
    "x-remote-ip": ["127.0.0.1"],
    "x-client-ip": ["127.0.0.1"],
    "true-client-ip": ["127.0.0.1"],
    "cf-connecting-ip": ["127.0.0.1"],
    "x-cluster-client-ip": ["127.0.0.1"],
}


def _extract_rate_limit_headers(
    headers: dict[str, str],
) -> dict[str, Any]:
    """Extract rate limit information from response headers."""
    rate_limit_info: dict[str, Any] = {}

    header_patterns = [
        ("x-ratelimit-limit", "limit"),
        ("x-ratelimit-remaining", "remaining"),
        ("x-ratelimit-reset", "reset"),
        ("x-rate-limit-limit", "limit"),
        ("x-rate-limit-remaining", "remaining"),
        ("x-rate-limit-reset", "reset"),
        ("ratelimit-limit", "limit"),
        ("ratelimit-remaining", "remaining"),
        ("ratelimit-reset", "reset"),
        ("retry-after", "retry_after"),
        ("x-retry-after", "retry_after"),
    ]

    for header_name, key in header_patterns:
        if header_name in headers:
            try:
                rate_limit_info[key] = int(headers[header_name])
            except ValueError:
                rate_limit_info[key] = headers[header_name]

    return rate_limit_info


def _detect_rate_limit(
    url: str,
    method: str = "GET",
    num_requests: int = 20,
    delay: float = 0.1,
) -> dict[str, Any]:
    """Detect rate limiting on an endpoint."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"

    results: list[dict[str, Any]] = []
    rate_limited = False
    limit_threshold = None
    rate_limit_status_codes = {429, 503, 403}

    try:
        for i in range(num_requests):
            start_time = time.time()

            if method.upper() == "GET":
                response = requests.get(url, timeout=10)
            else:
                response = requests.post(url, timeout=10)

            elapsed = time.time() - start_time

            result = {
                "request_number": i + 1,
                "status_code": response.status_code,
                "response_time": round(elapsed, 3),
                "rate_limit_headers": _extract_rate_limit_headers(
                    {k.lower(): v for k, v in response.headers.items()},
                ),
            }

            if response.status_code in rate_limit_status_codes:
                rate_limited = True
                limit_threshold = i + 1
                result["rate_limited"] = True

            results.append(result)

            if rate_limited:
                break

            time.sleep(delay)

    except requests.exceptions.RequestException as e:
        return {
            "url": url,
            "error": f"Request failed: {e!s}",
        }

    return {
        "url": url,
        "method": method,
        "requests_sent": len(results),
        "rate_limited": rate_limited,
        "limit_threshold": limit_threshold,
        "rate_limit_detected": rate_limited,
        "results": results[-5:],
        "recommendations": [
            "Check if rate limit applies per IP or per session",
            "Test with different authentication tokens",
            "Try header-based bypass techniques",
        ] if rate_limited else [
            "No rate limit detected, but may exist at higher volume",
            "Test with more requests to confirm",
        ],
    }


def _test_bypass(
    url: str,
    method: str = "GET",
    num_requests: int = 10,
) -> dict[str, Any]:
    """Test rate limit bypass techniques."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"

    bypass_results: list[dict[str, Any]] = []

    # First, establish baseline
    baseline_result = _detect_rate_limit(url, method, 5, 0.05)
    baseline_limited = baseline_result.get("rate_limited", False)

    # Test each bypass header
    for header_name, header_values in BYPASS_HEADERS.items():
        for value in header_values:
            try:
                headers = {header_name: value}

                if method.upper() == "GET":
                    response = requests.get(url, headers=headers, timeout=10)
                else:
                    response = requests.post(url, headers=headers, timeout=10)

                bypass_results.append({
                    "header": header_name,
                    "value": value,
                    "status_code": response.status_code,
                    "rate_limit_headers": _extract_rate_limit_headers(
                        {k.lower(): v for k, v in response.headers.items()},
                    ),
                    "potentially_bypassed": response.status_code == 200,
                })

            except requests.exceptions.RequestException:
                continue

    # Test path variations
    path_variations = [
        url,
        url + "/",
        url.replace("/api/", "/API/"),
        url + "?_=" + str(int(time.time())),
    ]

    path_results = []
    for variation in path_variations:
        try:
            response = requests.get(variation, timeout=10)
            path_results.append({
                "url": variation,
                "status_code": response.status_code,
            })
        except requests.exceptions.RequestException:
            continue

    return {
        "url": url,
        "baseline_rate_limited": baseline_limited,
        "bypass_tests": bypass_results,
        "path_variation_tests": path_results,
        "potential_bypasses": [
            r for r in bypass_results if r.get("potentially_bypassed")
        ],
    }


def _analyze_rate_limit(
    url: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Analyze rate limit implementation details."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"

    try:
        # Send initial request
        if method.upper() == "GET":
            response = requests.get(url, timeout=10)
        else:
            response = requests.post(url, timeout=10)

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        rate_limit_info = _extract_rate_limit_headers(headers_lower)

        # Analyze implementation
        analysis: dict[str, Any] = {
            "url": url,
            "status_code": response.status_code,
            "rate_limit_headers": rate_limit_info,
            "implementation_details": {},
            "vulnerabilities": [],
        }

        # Check if rate limit headers present
        if rate_limit_info:
            analysis["implementation_details"]["headers_present"] = True
            analysis["implementation_details"]["header_types"] = list(
                rate_limit_info.keys(),
            )

            # Check limit value
            limit_val = rate_limit_info.get("limit")
            if limit_val:
                analysis["implementation_details"]["limit"] = limit_val
                if isinstance(limit_val, int) and limit_val > 1000:
                    analysis["vulnerabilities"].append({
                        "type": "high_limit",
                        "description": f"Rate limit is high ({limit_val}), may allow abuse",
                    })

            # Check remaining
            remaining_val = rate_limit_info.get("remaining")
            if remaining_val is not None:
                analysis["implementation_details"]["remaining"] = remaining_val

            # Check reset
            reset_val = rate_limit_info.get("reset")
            if reset_val:
                analysis["implementation_details"]["reset"] = reset_val

        else:
            analysis["implementation_details"]["headers_present"] = False
            analysis["vulnerabilities"].append({
                "type": "no_headers",
                "description": "No rate limit headers present, harder to detect limits",
            })

        # Check for CORS that might allow bypass
        cors_header = headers_lower.get("access-control-allow-origin", "")
        if cors_header == "*":
            analysis["vulnerabilities"].append({
                "type": "permissive_cors",
                "description": "Permissive CORS may allow cross-origin rate limit attacks",
            })

        return analysis

    except requests.exceptions.RequestException as e:
        return {
            "url": url,
            "error": f"Analysis failed: {e!s}",
        }


@register_tool
def rate_limit_tester(
    action: RateLimitAction,
    url: str,
    method: str = "GET",
    num_requests: int = 20,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Test and analyze API rate limiting implementation.

    This tool systematically tests rate limiting on endpoints including
    detection, bypass techniques, threshold identification, and
    implementation analysis.

    Args:
        action: The testing action to perform:
            - detect: Detect if rate limiting exists and find threshold
            - test_bypass: Test common bypass techniques (headers, paths)
            - analyze: Analyze rate limit implementation details
        url: Target URL to test
        method: HTTP method to use (GET or POST)
        num_requests: Number of requests for detection (default: 20)

    Returns:
        Rate limit detection results, bypass potential, and analysis
    """
    try:
        if action == "detect":
            return _detect_rate_limit(url, method, num_requests)

        if action == "test_bypass":
            return _test_bypass(url, method, num_requests)

        if action == "analyze":
            return _analyze_rate_limit(url, method)

        return {"error": f"Unknown action: {action}"}

    except (ValueError, KeyError) as e:
        return {"error": f"Rate limit testing failed: {e!s}"}
