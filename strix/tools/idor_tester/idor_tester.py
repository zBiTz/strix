"""IDOR (Insecure Direct Object Reference) testing tool for web application security."""

from __future__ import annotations

import re
import time
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


IDORAction = Literal["compare", "enumerate", "analyze", "generate_ids"]

# Common ID parameter names to look for
COMMON_ID_PARAMS = [
    "id", "user_id", "userId", "uid", "account_id", "accountId",
    "order_id", "orderId", "doc_id", "docId", "file_id", "fileId",
    "resource_id", "resourceId", "object_id", "objectId", "item_id",
    "itemId", "record_id", "recordId", "profile_id", "profileId",
    "org_id", "orgId", "organization_id", "organizationId",
    "tenant_id", "tenantId", "project_id", "projectId", "team_id",
    "teamId", "workspace_id", "workspaceId", "subscription_id",
]

# Common relationship parameter names
RELATIONSHIP_PARAMS = [
    "parentId", "ownerId", "creatorId", "assigneeId", "managerId",
    "parent_id", "owner_id", "creator_id", "assignee_id", "manager_id",
]


def _extract_ids_from_url(url: str) -> dict[str, list[str]]:
    """Extract potential ID parameters from URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Also check path segments for IDs
    path_segments = parsed.path.split("/")
    path_ids = {}

    for i, segment in enumerate(path_segments):
        # Check for numeric IDs
        if segment.isdigit():
            path_ids[f"path_segment_{i}"] = [segment]
        # Check for UUID-like patterns
        elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", segment, re.I):
            path_ids[f"path_segment_{i}_uuid"] = [segment]
        # Check for base64-encoded IDs
        elif re.match(r"^[A-Za-z0-9+/=]{20,}$", segment):
            path_ids[f"path_segment_{i}_b64"] = [segment]

    return {**params, **path_ids}


def _replace_id_in_url(url: str, param_name: str, new_value: str) -> str:
    """Replace an ID value in the URL."""
    parsed = urlparse(url)

    # Check if it's a path segment
    if param_name.startswith("path_segment_"):
        path_segments = parsed.path.split("/")
        # Extract segment index
        idx_match = re.search(r"path_segment_(\d+)", param_name)
        if idx_match:
            idx = int(idx_match.group(1))
            if idx < len(path_segments):
                path_segments[idx] = new_value
                new_path = "/".join(path_segments)
                return urlunparse(parsed._replace(path=new_path))
    else:
        # It's a query parameter
        params = parse_qs(parsed.query, keep_blank_values=True)
        if param_name in params:
            params[param_name] = [new_value]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

    return url


def _make_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    timeout: int = 10,
) -> tuple[requests.Response | None, float]:
    """Make an HTTP request and return response with timing."""
    start_time = time.time()
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, timeout=timeout)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=timeout)
        elif method.upper() == "PUT":
            response = requests.put(url, headers=headers, json=data, timeout=timeout)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers, timeout=timeout)
        elif method.upper() == "PATCH":
            response = requests.patch(url, headers=headers, json=data, timeout=timeout)
        else:
            response = requests.request(method.upper(), url, headers=headers, json=data, timeout=timeout)
        elapsed = time.time() - start_time
        return response, elapsed
    except requests.exceptions.RequestException:
        return None, time.time() - start_time


def _compare_responses(
    resp1: requests.Response,
    resp2: requests.Response,
    time1: float,
    time2: float,
) -> dict[str, Any]:
    """Compare two HTTP responses for IDOR indicators."""
    comparison = {
        "status_codes": {
            "original": resp1.status_code,
            "swapped": resp2.status_code,
            "match": resp1.status_code == resp2.status_code,
        },
        "content_length": {
            "original": len(resp1.text),
            "swapped": len(resp2.text),
            "difference": abs(len(resp1.text) - len(resp2.text)),
        },
        "timing": {
            "original": round(time1, 3),
            "swapped": round(time2, 3),
            "difference": round(abs(time1 - time2), 3),
        },
        "content_type": {
            "original": resp1.headers.get("Content-Type", ""),
            "swapped": resp2.headers.get("Content-Type", ""),
            "match": resp1.headers.get("Content-Type") == resp2.headers.get("Content-Type"),
        },
    }

    # Check for IDOR indicators
    indicators = []

    # Same status code with different content (potential IDOR)
    if resp1.status_code == resp2.status_code == 200:
        if len(resp1.text) != len(resp2.text):
            indicators.append("Different content length with same status - possible unauthorized data access")
        if resp1.text != resp2.text:
            indicators.append("Different response content - verify authorization is properly enforced")

    # Different status codes indicating authorization check
    if resp1.status_code == 200 and resp2.status_code in [401, 403, 404]:
        indicators.append("Authorization check appears to be working (different status codes)")

    # Both return 200 with identical content (might indicate data exposure)
    if resp1.status_code == resp2.status_code == 200 and resp1.text == resp2.text:
        indicators.append("Identical responses - check if this endpoint returns user-specific data")

    # Timing-based detection (significant difference might indicate processing)
    if abs(time1 - time2) > 0.5:
        indicators.append(f"Significant timing difference ({round(abs(time1 - time2), 2)}s) - may indicate different code paths")

    comparison["idor_indicators"] = indicators

    return comparison


def _compare_idor(
    url: str,
    original_id: str,
    target_id: str,
    param_name: str | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Compare responses between original and target IDs."""
    results: dict[str, Any] = {
        "url": url,
        "original_id": original_id,
        "target_id": target_id,
        "method": method,
        "vulnerable": False,
    }

    # If param_name not specified, try to detect it
    if not param_name:
        extracted_ids = _extract_ids_from_url(url)
        for pname, values in extracted_ids.items():
            if original_id in values:
                param_name = pname
                break

    if not param_name:
        return {"error": "Could not identify ID parameter in URL. Please specify param_name."}

    results["param_name"] = param_name

    # Make request with original ID
    original_url = _replace_id_in_url(url, param_name, original_id)
    original_resp, original_time = _make_request(original_url, method, headers, timeout=timeout)

    if not original_resp:
        return {"error": "Failed to make request with original ID"}

    # Make request with target ID
    target_url = _replace_id_in_url(url, param_name, target_id)
    target_resp, target_time = _make_request(target_url, method, headers, timeout=timeout)

    if not target_resp:
        return {"error": "Failed to make request with target ID"}

    # Compare responses
    comparison = _compare_responses(original_resp, target_resp, original_time, target_time)
    results["comparison"] = comparison

    # Determine vulnerability
    if (
        original_resp.status_code == target_resp.status_code == 200
        and len(target_resp.text) > 50
        and original_resp.text != target_resp.text
    ):
        results["vulnerable"] = True
        results["vulnerability_type"] = "Potential IDOR - accessed different user's data"
        results["severity"] = "HIGH"
        results["recommendations"] = [
            "Implement server-side authorization checks for object access",
            "Verify the requesting user owns or has permission to access the requested object",
            "Use session-bound object references instead of predictable IDs",
            "Consider using UUIDs with proper authorization rather than sequential IDs",
        ]

    return results


def _enumerate_idor(
    url: str,
    start_id: int,
    end_id: int,
    param_name: str | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Enumerate IDs to find accessible resources."""
    results: dict[str, Any] = {
        "url": url,
        "range": {"start": start_id, "end": end_id},
        "method": method,
        "accessible_ids": [],
        "error_ids": [],
        "status_distribution": {},
    }

    # Limit enumeration range
    max_range = 50
    if end_id - start_id > max_range:
        results["warning"] = f"Range limited to {max_range} IDs for safety"
        end_id = start_id + max_range

    # If param_name not specified, try to detect it
    if not param_name:
        extracted_ids = _extract_ids_from_url(url)
        id_params = [p for p in extracted_ids if any(id_name in p.lower() for id_name in ["id", "uuid"])]
        if id_params:
            param_name = id_params[0]
        else:
            # Default to common pattern
            for common_param in COMMON_ID_PARAMS:
                if common_param in url:
                    param_name = common_param
                    break

    if not param_name:
        return {"error": "Could not identify ID parameter. Please specify param_name."}

    results["param_name"] = param_name

    for test_id in range(start_id, end_id + 1):
        test_url = _replace_id_in_url(url, param_name, str(test_id))
        response, _ = _make_request(test_url, method, headers, timeout=timeout)

        if response:
            status = response.status_code
            results["status_distribution"][status] = results["status_distribution"].get(status, 0) + 1

            if status == 200:
                results["accessible_ids"].append({
                    "id": test_id,
                    "status": status,
                    "content_length": len(response.text),
                })
        else:
            results["error_ids"].append(test_id)

    # Analyze results
    if results["accessible_ids"]:
        results["finding"] = f"Found {len(results['accessible_ids'])} accessible resources"
        if len(results["accessible_ids"]) > 1:
            results["potential_idor"] = True
            results["recommendation"] = "Verify each accessible ID belongs to the authenticated user"

    return results


def _analyze_idor(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze a URL for potential IDOR vulnerabilities."""
    results: dict[str, Any] = {
        "url": url,
        "method": method,
        "analysis": {},
    }

    # Extract and analyze ID parameters
    extracted_ids = _extract_ids_from_url(url)

    results["detected_id_params"] = {}
    for param, values in extracted_ids.items():
        param_analysis = {
            "values": values,
            "type": "unknown",
            "predictable": False,
        }

        for value in values:
            # Analyze ID type
            if value.isdigit():
                param_analysis["type"] = "numeric"
                param_analysis["predictable"] = True
                param_analysis["risk"] = "HIGH - Sequential numeric IDs are easily enumerable"
            elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", value, re.I):
                param_analysis["type"] = "uuid"
                param_analysis["predictable"] = False
                param_analysis["risk"] = "MEDIUM - UUIDs are not guessable but authorization still required"
            elif re.match(r"^[A-Za-z0-9+/=]{20,}$", value):
                param_analysis["type"] = "base64_encoded"
                param_analysis["predictable"] = False
                param_analysis["risk"] = "LOW - Encoded IDs, but verify authorization is enforced"
            elif re.match(r"^[0-9a-f]{24}$", value, re.I):
                param_analysis["type"] = "mongodb_objectid"
                param_analysis["predictable"] = True
                param_analysis["risk"] = "MEDIUM - MongoDB ObjectIDs contain timestamp, partially predictable"

        results["detected_id_params"][param] = param_analysis

    # Check for common IDOR-prone endpoints
    idor_prone_patterns = [
        (r"/users?/", "User data endpoint - verify user can only access own data"),
        (r"/accounts?/", "Account endpoint - check for horizontal privilege escalation"),
        (r"/orders?/", "Order endpoint - verify order belongs to authenticated user"),
        (r"/files?/", "File access endpoint - ensure proper authorization"),
        (r"/documents?/", "Document endpoint - check access controls"),
        (r"/profiles?/", "Profile endpoint - verify user authorization"),
        (r"/api/v\d+/", "API endpoint - ensure consistent authorization across versions"),
        (r"/download", "Download endpoint - high-risk for unauthorized file access"),
        (r"/export", "Export endpoint - verify data ownership before export"),
    ]

    results["endpoint_analysis"] = []
    for pattern, description in idor_prone_patterns:
        if re.search(pattern, url, re.I):
            results["endpoint_analysis"].append({
                "pattern": pattern,
                "warning": description,
            })

    # Generate testing recommendations
    results["testing_recommendations"] = [
        "Test with IDs from different user accounts",
        "Try ID enumeration if using numeric IDs",
        "Test PATCH/PUT/DELETE methods with foreign object IDs",
        "Check batch/bulk endpoints for IDOR in arrays",
        "Verify authorization is checked server-side, not just by ID obscurity",
    ]

    return results


def _generate_test_ids(
    original_id: str,
    count: int = 10,
) -> dict[str, Any]:
    """Generate test IDs based on the original ID pattern."""
    results: dict[str, Any] = {
        "original_id": original_id,
        "test_ids": [],
    }

    # Detect ID type and generate appropriate test values
    if original_id.isdigit():
        # Numeric ID - generate neighboring values
        id_int = int(original_id)
        results["id_type"] = "numeric"
        results["test_ids"] = [
            str(id_int - 2), str(id_int - 1),
            str(id_int + 1), str(id_int + 2),
            "1", "0", "-1",
            str(id_int * 2), str(id_int // 2) if id_int > 1 else "0",
        ]
        results["test_ids"] = list(dict.fromkeys(results["test_ids"]))[:count]

    elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", original_id, re.I):
        # UUID - suggest common test patterns
        results["id_type"] = "uuid"
        results["test_ids"] = [
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-0000-0000-000000000001",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            original_id.replace("-", ""),  # Without dashes
            original_id.upper() if original_id.islower() else original_id.lower(),
        ]
        results["note"] = "UUIDs are not enumerable - obtain valid IDs through other means (logs, emails, API responses)"

    elif re.match(r"^[0-9a-f]{24}$", original_id, re.I):
        # MongoDB ObjectId
        results["id_type"] = "mongodb_objectid"
        # Generate IDs with similar timestamp (first 8 chars)
        timestamp_part = original_id[:8]
        results["test_ids"] = [
            timestamp_part + "000000000000" + "0001",
            timestamp_part + "000000000000" + "0002",
            "000000000000000000000000",
            "000000000000000000000001",
        ]
        results["note"] = "MongoDB ObjectIDs contain timestamp - IDs created around the same time may be close"

    else:
        # Unknown format
        results["id_type"] = "unknown"
        results["test_ids"] = [
            "1", "0", "-1", "admin", "test", "null", "undefined",
            original_id + "1", original_id[:-1] if len(original_id) > 1 else original_id,
        ]

    return results


@register_tool
def idor_tester(
    action: IDORAction,
    url: str,
    original_id: str | None = None,
    target_id: str | None = None,
    param_name: str | None = None,
    method: str = "GET",
    start_id: int | None = None,
    end_id: int | None = None,
    headers: str | None = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """Test for IDOR (Insecure Direct Object Reference) vulnerabilities.

    This tool helps identify authorization bypass vulnerabilities where users
    can access resources belonging to other users by manipulating object IDs.

    Args:
        action: The testing action to perform:
            - compare: Compare responses between two requests with swapped IDs
            - enumerate: Enumerate object IDs to find accessible resources
            - analyze: Analyze URL for potential IDOR vulnerabilities
            - generate_ids: Generate test IDs based on original ID pattern
        url: Target URL containing the ID parameter
        original_id: The original/legitimate object ID
        target_id: The target ID to test access for (for compare action)
        param_name: Name of the ID parameter (auto-detected if not provided)
        method: HTTP method to use (GET, POST, PUT, DELETE, PATCH)
        start_id: Starting ID for enumeration (for enumerate action)
        end_id: Ending ID for enumeration (for enumerate action)
        headers: HTTP headers as JSON string
        timeout: Request timeout in seconds

    Returns:
        IDOR test results with findings and recommendations
    """
    VALID_PARAMS = {
        "action", "url", "original_id", "target_id", "param_name",
        "method", "start_id", "end_id", "headers", "timeout",
    }
    VALID_ACTIONS = ["compare", "enumerate", "analyze", "generate_ids"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "idor_tester")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "idor_tester",
                "compare",
                {"url": "https://example.com/api/users/123", "original_id": "123", "target_id": "456"},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "idor_tester")
    if action_error:
        action_error["usage_examples"] = {
            "compare": "idor_tester(action='compare', url='https://example.com/api/users/123', original_id='123', target_id='456')",
            "enumerate": "idor_tester(action='enumerate', url='https://example.com/api/users/1', start_id=1, end_id=20)",
            "analyze": "idor_tester(action='analyze', url='https://example.com/api/users/123')",
            "generate_ids": "idor_tester(action='generate_ids', url='https://example.com/api/users/123', original_id='123')",
        }
        return action_error

    # Validate required parameters
    url_error = validate_required_param(url, "url", action, "idor_tester")
    if url_error:
        url_error.update(
            generate_usage_hint(
                "idor_tester",
                action,
                {"url": "https://example.com/api/users/123"},
            )
        )
        return url_error

    # Parse headers if provided
    parsed_headers = None
    if headers:
        try:
            import json
            parsed_headers = json.loads(headers)
        except (json.JSONDecodeError, TypeError):
            return {"error": "Invalid headers format. Provide headers as JSON string."}

    try:
        if action == "compare":
            if not original_id or not target_id:
                return {
                    "error": "Both original_id and target_id are required for compare action",
                    "usage": "idor_tester(action='compare', url='...', original_id='123', target_id='456')",
                }
            return _compare_idor(url, original_id, target_id, param_name, method, parsed_headers, timeout)

        if action == "enumerate":
            if start_id is None or end_id is None:
                return {
                    "error": "start_id and end_id are required for enumerate action",
                    "usage": "idor_tester(action='enumerate', url='...', start_id=1, end_id=20)",
                }
            return _enumerate_idor(url, start_id, end_id, param_name, method, parsed_headers, timeout)

        if action == "analyze":
            return _analyze_idor(url, method, parsed_headers, timeout)

        if action == "generate_ids":
            if not original_id:
                # Try to extract from URL
                extracted = _extract_ids_from_url(url)
                if extracted:
                    original_id = list(extracted.values())[0][0]
                else:
                    return {
                        "error": "original_id is required for generate_ids action",
                        "usage": "idor_tester(action='generate_ids', url='...', original_id='123')",
                    }
            return _generate_test_ids(original_id)

        return {"error": f"Unknown action: {action}"}

    except (ValueError, requests.exceptions.RequestException) as e:
        return {"error": f"IDOR testing failed: {e!s}"}
