"""Business Logic vulnerability scanner for web application security."""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import re
import time
from typing import Any, Literal

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


BusinessLogicAction = Literal[
    "analyze_workflow", "test_race", "test_manipulation",
    "test_skip", "test_numeric", "generate_tests"
]

# Common business logic vulnerability patterns
WORKFLOW_PATTERNS = {
    "checkout": {
        "steps": ["cart", "shipping", "payment", "confirm"],
        "skip_risks": ["bypass payment", "free shipping"],
    },
    "signup": {
        "steps": ["register", "verify_email", "complete_profile"],
        "skip_risks": ["unverified accounts", "incomplete profiles"],
    },
    "payment": {
        "steps": ["initiate", "authorize", "capture"],
        "skip_risks": ["double charge", "auth without capture"],
    },
    "refund": {
        "steps": ["request", "review", "approve", "process"],
        "skip_risks": ["unauthorized refund", "double refund"],
    },
    "password_reset": {
        "steps": ["request", "verify_token", "new_password"],
        "skip_risks": ["token bypass", "password without verification"],
    },
}

# Numeric manipulation test values
NUMERIC_TESTS = {
    "price": [0, -1, -0.01, 0.001, 999999999, "1e-10", None],
    "quantity": [0, -1, 999999, 2147483647, -2147483648, 0.5, None],
    "discount": [0, 100, 101, -10, 200, 99.9999, None],
    "amount": [0, -0.01, 0.001, -1, "0.0", None],
}


def _make_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    json_data: dict[str, Any] | None = None,
    timeout: int = 10,
) -> tuple[requests.Response | None, float]:
    """Make an HTTP request and return response with timing."""
    start_time = time.time()
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, timeout=timeout)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, data=data, json=json_data, timeout=timeout)
        elif method.upper() == "PUT":
            response = requests.put(url, headers=headers, data=data, json=json_data, timeout=timeout)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers, timeout=timeout)
        elif method.upper() == "PATCH":
            response = requests.patch(url, headers=headers, data=data, json=json_data, timeout=timeout)
        else:
            response = requests.request(method.upper(), url, headers=headers, data=data, json=json_data, timeout=timeout)
        elapsed = time.time() - start_time
        return response, elapsed
    except requests.exceptions.RequestException:
        return None, time.time() - start_time


def _parallel_requests(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    count: int = 5,
    timeout: int = 10,
) -> list[dict[str, Any]]:
    """Execute multiple requests in parallel for race condition testing."""
    results = []

    def make_single_request(request_id: int) -> dict[str, Any]:
        start_time = time.time()
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, timeout=timeout)
            else:
                response = requests.post(url, headers=headers, json=data, timeout=timeout)
            elapsed = time.time() - start_time
            return {
                "request_id": request_id,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "elapsed": round(elapsed, 3),
                "success": 200 <= response.status_code < 300,
            }
        except requests.exceptions.RequestException as e:
            return {
                "request_id": request_id,
                "error": str(e),
                "elapsed": round(time.time() - start_time, 3),
                "success": False,
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(make_single_request, i) for i in range(count)]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda x: x.get("request_id", 0))


def _analyze_workflow(
    endpoints: list[str],
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze a workflow for potential business logic vulnerabilities."""
    results: dict[str, Any] = {
        "workflow_analysis": [],
        "detected_issues": [],
        "recommendations": [],
    }

    for i, endpoint in enumerate(endpoints):
        response, elapsed = _make_request(endpoint, method, headers, timeout=timeout)

        step_analysis: dict[str, Any] = {
            "step": i + 1,
            "endpoint": endpoint,
            "status": response.status_code if response else "error",
            "response_time": round(elapsed, 3),
        }

        if response:
            # Check for state tokens or session indicators
            for header in ["Set-Cookie", "X-CSRF-Token", "X-Request-Id"]:
                if header in response.headers:
                    step_analysis["state_tokens"] = step_analysis.get("state_tokens", [])
                    step_analysis["state_tokens"].append(header)

            # Check for step indicators in response
            body = response.text.lower()
            if any(ind in body for ind in ["step", "stage", "phase", "progress"]):
                step_analysis["step_indicator_found"] = True

        results["workflow_analysis"].append(step_analysis)

    # Identify patterns
    if len(endpoints) > 1:
        # Check if skipping steps is possible
        results["detected_issues"].append({
            "type": "step_skip_risk",
            "message": "Multi-step workflow detected - test direct access to later steps",
            "test": "Try accessing step N directly without completing steps 1 to N-1",
        })

    # Generate recommendations based on workflow type
    for pattern_name, pattern_info in WORKFLOW_PATTERNS.items():
        if any(pattern_name in ep.lower() for ep in endpoints):
            results["detected_pattern"] = pattern_name
            results["recommendations"].append({
                "pattern": pattern_name,
                "expected_steps": pattern_info["steps"],
                "skip_risks": pattern_info["skip_risks"],
            })

    return results


def _test_race_condition(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    parallel_count: int = 10,
    timeout: int = 10,
) -> dict[str, Any]:
    """Test for race condition vulnerabilities."""
    results: dict[str, Any] = {
        "url": url,
        "method": method,
        "parallel_requests": parallel_count,
        "vulnerable": False,
        "test_results": [],
    }

    # Execute parallel requests
    parallel_results = _parallel_requests(url, method, headers, data, parallel_count, timeout)
    results["test_results"] = parallel_results

    # Analyze results for race condition indicators
    successful_requests = [r for r in parallel_results if r.get("success")]
    results["successful_count"] = len(successful_requests)
    results["failed_count"] = parallel_count - len(successful_requests)

    # Check for indicators
    if len(successful_requests) > 1:
        # Multiple successful requests may indicate race condition
        response_lengths = [r.get("response_length", 0) for r in successful_requests]
        unique_lengths = len(set(response_lengths))

        if unique_lengths > 1:
            results["vulnerable"] = True
            results["indicator"] = "Different response lengths suggest state changes during race"

        # Check timing spread
        timings = [r.get("elapsed", 0) for r in successful_requests]
        timing_spread = max(timings) - min(timings) if timings else 0

        if timing_spread < 0.1:
            results["timing_note"] = "Tight timing window - race condition more likely"

    # Check for all successful which shouldn't be
    if len(successful_requests) == parallel_count:
        results["potential_vulnerability"] = "All requests succeeded - verify only one should have succeeded"
        results["recommendation"] = "If this endpoint should only allow one successful operation, race condition exists"

    return results


def _test_parameter_manipulation(
    url: str,
    original_data: dict[str, Any],
    param_to_test: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Test parameter manipulation vulnerabilities."""
    results: dict[str, Any] = {
        "url": url,
        "tested_parameter": param_to_test,
        "original_value": original_data.get(param_to_test),
        "tests": [],
        "vulnerable": False,
    }

    # Determine test values based on parameter type
    param_lower = param_to_test.lower()
    if any(p in param_lower for p in ["price", "amount", "cost", "total"]):
        test_values = NUMERIC_TESTS["price"]
    elif any(p in param_lower for p in ["quantity", "qty", "count", "number"]):
        test_values = NUMERIC_TESTS["quantity"]
    elif any(p in param_lower for p in ["discount", "percent", "off"]):
        test_values = NUMERIC_TESTS["discount"]
    else:
        test_values = [0, -1, 999999, "", None, [], {}]

    # Test each manipulation
    for test_value in test_values:
        test_data = copy.deepcopy(original_data)
        test_data[param_to_test] = test_value

        response, elapsed = _make_request(url, method, headers, json_data=test_data, timeout=timeout)

        test_result: dict[str, Any] = {
            "test_value": test_value,
            "response_time": round(elapsed, 3),
        }

        if response:
            test_result["status_code"] = response.status_code
            test_result["response_length"] = len(response.text)

            # Check for successful manipulation
            if response.status_code == 200:
                test_result["accepted"] = True

                # Check if response contains manipulated value
                if str(test_value) in response.text:
                    test_result["value_reflected"] = True
                    results["vulnerable"] = True

                # Check for error messages that leak information
                for indicator in ["invalid", "error", "failed", "denied"]:
                    if indicator in response.text.lower():
                        test_result["error_in_response"] = True
                        break
            else:
                test_result["accepted"] = False
        else:
            test_result["error"] = "Request failed"

        results["tests"].append(test_result)

    # Analyze for vulnerabilities
    accepted_tests = [t for t in results["tests"] if t.get("accepted")]
    if accepted_tests:
        results["accepted_manipulations"] = len(accepted_tests)
        results["recommendation"] = "Server accepts manipulated values - verify server-side validation"

    return results


def _test_step_skip(
    steps: list[dict[str, Any]],
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Test if workflow steps can be skipped."""
    results: dict[str, Any] = {
        "total_steps": len(steps),
        "skip_tests": [],
        "vulnerable": False,
    }

    if len(steps) < 2:
        return {"error": "Need at least 2 steps to test step skipping"}

    # Test accessing later steps directly without completing earlier ones
    for i, step in enumerate(steps[1:], start=2):
        url = step.get("url")
        method = step.get("method", "GET")
        data = step.get("data")

        if not url:
            continue

        response, elapsed = _make_request(url, method, headers, json_data=data, timeout=timeout)

        skip_result: dict[str, Any] = {
            "skipped_to_step": i,
            "url": url,
            "response_time": round(elapsed, 3),
        }

        if response:
            skip_result["status_code"] = response.status_code

            # Check if step was accessible without prior steps
            if response.status_code == 200:
                skip_result["accessible"] = True
                results["vulnerable"] = True
                skip_result["vulnerability"] = f"Step {i} accessible without completing previous steps"
            elif response.status_code in [401, 403]:
                skip_result["accessible"] = False
                skip_result["note"] = "Step properly protected"
            elif response.status_code == 400:
                skip_result["accessible"] = "partial"
                skip_result["note"] = "Step rejected request but may be due to missing data, not auth"
        else:
            skip_result["error"] = "Request failed"

        results["skip_tests"].append(skip_result)

    if results["vulnerable"]:
        results["recommendations"] = [
            "Implement server-side state tracking for multi-step workflows",
            "Verify completion of all prerequisite steps before allowing progression",
            "Use cryptographically signed tokens to track workflow state",
        ]

    return results


def _test_numeric_manipulation(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    original_data: dict[str, Any] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Test for numeric manipulation vulnerabilities."""
    results: dict[str, Any] = {
        "url": url,
        "tests": [],
        "vulnerable": False,
    }

    if not original_data:
        original_data = {}

    # Identify numeric fields
    numeric_fields = []
    for key, value in original_data.items():
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.replace(".", "").replace("-", "").isdigit()):
            numeric_fields.append(key)

    results["detected_numeric_fields"] = numeric_fields

    # Test each numeric field
    for field in numeric_fields:
        field_results: dict[str, Any] = {
            "field": field,
            "original_value": original_data[field],
            "manipulation_tests": [],
        }

        # Boundary tests
        test_values = [
            ("zero", 0),
            ("negative", -1),
            ("negative_decimal", -0.01),
            ("small_decimal", 0.001),
            ("large_value", 999999999),
            ("max_int", 2147483647),
            ("overflow", 9999999999999999),
            ("scientific", "1e10"),
        ]

        for test_name, test_value in test_values:
            test_data = copy.deepcopy(original_data)
            test_data[field] = test_value

            response, elapsed = _make_request(url, method, headers, json_data=test_data, timeout=timeout)

            test_result: dict[str, Any] = {
                "test": test_name,
                "value": test_value,
            }

            if response:
                test_result["status_code"] = response.status_code
                if response.status_code == 200:
                    test_result["accepted"] = True
                    field_results["potential_vulnerability"] = True
                    results["vulnerable"] = True
            else:
                test_result["error"] = "Request failed"

            field_results["manipulation_tests"].append(test_result)

        results["tests"].append(field_results)

    if results["vulnerable"]:
        results["recommendations"] = [
            "Implement server-side validation for all numeric inputs",
            "Set appropriate min/max boundaries for numeric fields",
            "Use decimal types for financial calculations",
            "Validate against overflow and underflow",
        ]

    return results


def _generate_test_cases(
    workflow_type: str,
    base_url: str,
) -> dict[str, Any]:
    """Generate business logic test cases for a workflow type."""
    results: dict[str, Any] = {
        "workflow_type": workflow_type,
        "base_url": base_url,
        "test_cases": [],
    }

    # Generic test cases applicable to most workflows
    generic_tests = [
        {
            "name": "Step Skip",
            "description": "Attempt to access later workflow steps without completing earlier ones",
            "technique": "Direct API calls to final step endpoints",
        },
        {
            "name": "Parameter Manipulation",
            "description": "Modify prices, quantities, or amounts to invalid values",
            "technique": "Send negative numbers, zeros, or extreme values",
        },
        {
            "name": "Race Condition",
            "description": "Execute multiple parallel requests to exploit timing windows",
            "technique": "Send 10+ simultaneous requests to state-changing endpoints",
        },
        {
            "name": "Replay Attack",
            "description": "Resubmit previously successful requests",
            "technique": "Capture and replay finalize/confirm requests",
        },
        {
            "name": "Token Reuse",
            "description": "Use tokens from one session in another",
            "technique": "Swap CSRF tokens, session IDs, or step tokens between users",
        },
    ]

    results["test_cases"].extend(generic_tests)

    # Add workflow-specific tests
    if workflow_type in WORKFLOW_PATTERNS:
        pattern = WORKFLOW_PATTERNS[workflow_type]
        results["expected_steps"] = pattern["steps"]
        results["known_risks"] = pattern["skip_risks"]

        # Add specific tests for this workflow
        if workflow_type == "checkout":
            results["test_cases"].extend([
                {
                    "name": "Price Modification",
                    "description": "Modify product prices after adding to cart",
                    "technique": "Intercept and modify price parameters in checkout flow",
                },
                {
                    "name": "Free Shipping Abuse",
                    "description": "Apply free shipping then remove qualifying items",
                    "technique": "Meet threshold, apply shipping, then modify cart",
                },
            ])
        elif workflow_type == "refund":
            results["test_cases"].extend([
                {
                    "name": "Double Refund",
                    "description": "Obtain multiple refunds for single transaction",
                    "technique": "Race parallel refund requests",
                },
                {
                    "name": "Partial Refund Abuse",
                    "description": "Request partials summing over original amount",
                    "technique": "Multiple partial refund requests",
                },
            ])
        elif workflow_type == "payment":
            results["test_cases"].extend([
                {
                    "name": "Auth Without Capture",
                    "description": "Hold funds without completing payment",
                    "technique": "Stop workflow after authorization",
                },
                {
                    "name": "Double Capture",
                    "description": "Capture same authorization multiple times",
                    "technique": "Race parallel capture requests",
                },
            ])

    return results


@register_tool
def business_logic_scanner(
    action: BusinessLogicAction,
    url: str | None = None,
    endpoints: str | None = None,
    data: str | None = None,
    steps: str | None = None,
    param_to_test: str | None = None,
    workflow_type: str | None = None,
    method: str = "POST",
    parallel_count: int = 10,
    headers: str | None = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """Test for business logic vulnerabilities in web applications.

    Business logic flaws exploit intended functionality to violate domain
    invariants. This tool tests for state machine abuse, race conditions,
    parameter manipulation, and workflow bypass vulnerabilities.

    Args:
        action: The testing action to perform:
            - analyze_workflow: Analyze multi-step workflow for bypass opportunities
            - test_race: Test for race condition vulnerabilities
            - test_manipulation: Test parameter manipulation (price, quantity)
            - test_skip: Test workflow step skip vulnerabilities
            - test_numeric: Test numeric boundary manipulation
            - generate_tests: Generate test cases for a workflow type
        url: Target URL for testing
        endpoints: Comma-separated list of workflow endpoints (for analyze_workflow)
        data: JSON data for request body
        steps: JSON array of workflow steps (for test_skip)
        param_to_test: Parameter name to test for manipulation
        workflow_type: Workflow type for test generation (checkout, refund, payment, signup)
        method: HTTP method to use
        parallel_count: Number of parallel requests for race testing
        headers: HTTP headers as JSON string
        timeout: Request timeout in seconds

    Returns:
        Business logic test results with vulnerability indicators
    """
    VALID_PARAMS = {
        "action", "url", "endpoints", "data", "steps", "param_to_test",
        "workflow_type", "method", "parallel_count", "headers", "timeout",
    }
    VALID_ACTIONS = [
        "analyze_workflow", "test_race", "test_manipulation",
        "test_skip", "test_numeric", "generate_tests",
    ]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "business_logic_scanner")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "business_logic_scanner",
                "test_race",
                {"url": "https://example.com/api/apply-coupon"},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "business_logic_scanner")
    if action_error:
        action_error["usage_examples"] = {
            "analyze_workflow": "business_logic_scanner(action='analyze_workflow', endpoints='https://example.com/cart,https://example.com/checkout,https://example.com/payment')",
            "test_race": "business_logic_scanner(action='test_race', url='https://example.com/api/redeem', data='{\"code\":\"DISCOUNT10\"}')",
            "test_manipulation": "business_logic_scanner(action='test_manipulation', url='https://example.com/api/order', data='{\"price\":100}', param_to_test='price')",
            "test_skip": "business_logic_scanner(action='test_skip', steps='[{\"url\":\"https://example.com/step1\"},{\"url\":\"https://example.com/step2\"}]')",
            "test_numeric": "business_logic_scanner(action='test_numeric', url='https://example.com/api/order', data='{\"quantity\":1,\"price\":100}')",
            "generate_tests": "business_logic_scanner(action='generate_tests', workflow_type='checkout', url='https://example.com')",
        }
        return action_error

    # Parse JSON inputs
    import json

    parsed_headers = None
    if headers:
        try:
            parsed_headers = json.loads(headers)
        except (json.JSONDecodeError, TypeError):
            return {"error": "Invalid headers format. Provide headers as JSON string."}

    parsed_data = None
    if data:
        try:
            parsed_data = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return {"error": "Invalid data format. Provide data as JSON string."}

    parsed_steps = None
    if steps:
        try:
            parsed_steps = json.loads(steps)
        except (json.JSONDecodeError, TypeError):
            return {"error": "Invalid steps format. Provide steps as JSON array."}

    try:
        if action == "analyze_workflow":
            if not endpoints:
                return {
                    "error": "endpoints required for analyze_workflow action",
                    "usage": "Provide comma-separated list of workflow endpoint URLs",
                }
            endpoint_list = [e.strip() for e in endpoints.split(",") if e.strip()]
            return _analyze_workflow(endpoint_list, method, parsed_headers, timeout)

        if action == "test_race":
            url_error = validate_required_param(url, "url", action, "business_logic_scanner")
            if url_error:
                return url_error
            return _test_race_condition(url, method, parsed_headers, parsed_data, parallel_count, timeout)

        if action == "test_manipulation":
            url_error = validate_required_param(url, "url", action, "business_logic_scanner")
            if url_error:
                return url_error
            if not parsed_data or not param_to_test:
                return {
                    "error": "data and param_to_test required for test_manipulation action",
                    "usage": "Provide JSON data with the parameter to test",
                }
            return _test_parameter_manipulation(url, parsed_data, param_to_test, method, parsed_headers, timeout)

        if action == "test_skip":
            if not parsed_steps:
                return {
                    "error": "steps required for test_skip action",
                    "usage": "Provide JSON array of step objects with 'url' and optional 'method' and 'data'",
                }
            return _test_step_skip(parsed_steps, parsed_headers, timeout)

        if action == "test_numeric":
            url_error = validate_required_param(url, "url", action, "business_logic_scanner")
            if url_error:
                return url_error
            if not parsed_data:
                return {
                    "error": "data required for test_numeric action",
                    "usage": "Provide JSON data containing numeric fields to test",
                }
            return _test_numeric_manipulation(url, method, parsed_headers, parsed_data, timeout)

        if action == "generate_tests":
            if not workflow_type:
                return {
                    "error": "workflow_type required for generate_tests action",
                    "available_types": list(WORKFLOW_PATTERNS.keys()),
                }
            return _generate_test_cases(workflow_type, url or "https://target.com")

        return {"error": f"Unknown action: {action}"}

    except (ValueError, json.JSONDecodeError) as e:
        return {"error": f"Business logic scanning failed: {e!s}"}
