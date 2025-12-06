"""OpenAPI/Swagger specification parser for security testing."""

import json
import re
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "parse_spec",
    "find_endpoints",
    "extract_schemas",
    "generate_tests",
    "find_auth_endpoints",
]


@register_tool(sandbox_execution=True)
def openapi_parser(
    action: ToolAction,
    spec: dict | None = None,
    spec_url: str | None = None,
    endpoint_filter: str | None = None,
    method_filter: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """OpenAPI/Swagger specification parser for security testing.

    Args:
        action: The action to perform
        spec: OpenAPI specification as dict
        spec_url: URL to fetch spec from
        endpoint_filter: Filter endpoints by pattern
        method_filter: Filter by HTTP method

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "spec", "spec_url", "endpoint_filter", "method_filter",
    }
    VALID_ACTIONS = [
        "parse_spec",
        "find_endpoints",
        "extract_schemas",
        "generate_tests",
        "find_auth_endpoints",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "openapi_parser"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "openapi_parser"):
        return action_error

    # Sample spec for demonstration if none provided
    sample_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Sample API", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    ],
                },
                "post": {
                    "summary": "Create user",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    },
                },
            },
            "/users/{id}": {
                "get": {"summary": "Get user by ID", "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                ]},
                "put": {"summary": "Update user"},
                "delete": {"summary": "Delete user"},
            },
            "/admin/users": {
                "get": {"summary": "Admin list users", "security": [{"adminAuth": []}]},
            },
            "/auth/login": {
                "post": {
                    "summary": "Login",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/auth/register": {"post": {"summary": "Register"}},
            "/auth/reset-password": {"post": {"summary": "Reset password"}},
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "username": {"type": "string"},
                        "email": {"type": "string", "format": "email"},
                        "role": {"type": "string", "enum": ["user", "admin"]},
                        "isAdmin": {"type": "boolean"},
                    }
                }
            },
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                "adminAuth": {"type": "apiKey", "in": "header", "name": "X-Admin-Key"},
            }
        }
    }

    api_spec = spec or sample_spec

    if action == "parse_spec":
        # Extract basic info
        info = api_spec.get("info", {})
        servers = api_spec.get("servers", [])
        paths = api_spec.get("paths", {})
        security_schemes = api_spec.get("components", {}).get("securitySchemes", {})

        # Count endpoints
        endpoint_count = 0
        methods_count = {"get": 0, "post": 0, "put": 0, "delete": 0, "patch": 0}

        for path, methods in paths.items():
            for method in methods:
                if method.lower() in methods_count:
                    methods_count[method.lower()] += 1
                    endpoint_count += 1

        return {
            "action": "parse_spec",
            "api_info": {
                "title": info.get("title", "Unknown"),
                "version": info.get("version", "Unknown"),
                "description": info.get("description", ""),
            },
            "servers": [s.get("url") for s in servers],
            "statistics": {
                "total_endpoints": endpoint_count,
                "paths": len(paths),
                "methods": methods_count,
            },
            "security_schemes": list(security_schemes.keys()),
            "openapi_version": api_spec.get("openapi") or api_spec.get("swagger"),
            "security_observations": [
                "Check for missing authentication on endpoints",
                "Look for admin endpoints accessible to regular users",
                "Test BOLA on ID-based endpoints",
                "Check for mass assignment in POST/PUT bodies",
            ],
        }

    elif action == "find_endpoints":
        paths = api_spec.get("paths", {})
        servers = api_spec.get("servers", [])
        base_url = servers[0].get("url", "") if servers else ""

        endpoints = []
        filter_pattern = endpoint_filter or ""
        method_filter_lower = (method_filter or "").lower()

        for path, methods in paths.items():
            if filter_pattern and filter_pattern not in path:
                continue

            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    if method_filter_lower and method.lower() != method_filter_lower:
                        continue

                    # Extract parameters
                    params = details.get("parameters", [])
                    path_params = [p for p in params if p.get("in") == "path"]
                    query_params = [p for p in params if p.get("in") == "query"]

                    # Check security
                    security = details.get("security", api_spec.get("security", []))

                    endpoints.append({
                        "path": path,
                        "full_url": f"{base_url}{path}",
                        "method": method.upper(),
                        "summary": details.get("summary", ""),
                        "path_params": [p.get("name") for p in path_params],
                        "query_params": [p.get("name") for p in query_params],
                        "has_auth": len(security) > 0,
                        "has_request_body": "requestBody" in details,
                    })

        return {
            "action": "find_endpoints",
            "filter": endpoint_filter,
            "method_filter": method_filter,
            "endpoints": endpoints,
            "total_found": len(endpoints),
            "testing_priority": [
                "Endpoints with path parameters (BOLA/IDOR)",
                "POST/PUT endpoints (mass assignment)",
                "Endpoints without auth (broken access control)",
                "Admin endpoints (privilege escalation)",
            ],
        }

    elif action == "extract_schemas":
        schemas = api_spec.get("components", {}).get("schemas", {})

        extracted = {}
        security_concerns = []

        for schema_name, schema_def in schemas.items():
            properties = schema_def.get("properties", {})

            sensitive_fields = []
            for prop_name, prop_def in properties.items():
                # Check for sensitive field names
                if any(s in prop_name.lower() for s in ["password", "secret", "token", "key", "admin", "role", "permission"]):
                    sensitive_fields.append(prop_name)

            extracted[schema_name] = {
                "type": schema_def.get("type", "object"),
                "properties": list(properties.keys()),
                "required": schema_def.get("required", []),
                "sensitive_fields": sensitive_fields,
            }

            if sensitive_fields:
                security_concerns.append({
                    "schema": schema_name,
                    "concern": "Contains sensitive fields that may be exploitable via mass assignment",
                    "fields": sensitive_fields,
                })

        return {
            "action": "extract_schemas",
            "schemas": extracted,
            "total_schemas": len(schemas),
            "security_concerns": security_concerns,
            "mass_assignment_targets": [
                s["schema"] for s in security_concerns if s["fields"]
            ],
            "testing_recommendations": [
                "Try adding sensitive fields in POST/PUT requests",
                "Check if role/admin fields can be set by users",
                "Test if ID fields can be overwritten",
                "Look for hidden properties not in schema",
            ],
        }

    elif action == "generate_tests":
        paths = api_spec.get("paths", {})
        servers = api_spec.get("servers", [])
        base_url = servers[0].get("url", "") if servers else "https://api.example.com"

        test_cases = []

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue

                # Generate test URL
                test_path = re.sub(r'\{(\w+)\}', r'1', path)  # Replace {id} with 1
                full_url = f"{base_url}{test_path}"

                # BOLA test for path params
                if '{' in path:
                    test_cases.append({
                        "name": f"BOLA Test: {method.upper()} {path}",
                        "type": "bola",
                        "curl": f'curl -X {method.upper()} "{full_url}" -H "Authorization: Bearer USER_TOKEN"',
                        "description": "Test with different user IDs to check authorization",
                    })

                # Auth bypass test
                security = details.get("security", api_spec.get("security", []))
                if security:
                    test_cases.append({
                        "name": f"Auth Bypass: {method.upper()} {path}",
                        "type": "auth_bypass",
                        "curl": f'curl -X {method.upper()} "{full_url}"',
                        "description": "Test endpoint without authentication",
                    })

                # Mass assignment test for POST/PUT
                if method.lower() in ["post", "put", "patch"]:
                    test_cases.append({
                        "name": f"Mass Assignment: {method.upper()} {path}",
                        "type": "mass_assignment",
                        "curl": f'curl -X {method.upper()} "{full_url}" -H "Content-Type: application/json" -d \'{{"role":"admin","isAdmin":true}}\'',
                        "description": "Try to escalate privileges via extra fields",
                    })

        return {
            "action": "generate_tests",
            "base_url": base_url,
            "test_cases": test_cases[:20],  # Limit output
            "total_tests": len(test_cases),
            "test_categories": {
                "bola": len([t for t in test_cases if t["type"] == "bola"]),
                "auth_bypass": len([t for t in test_cases if t["type"] == "auth_bypass"]),
                "mass_assignment": len([t for t in test_cases if t["type"] == "mass_assignment"]),
            },
            "automation_tips": [
                "Use Burp Suite to import OpenAPI spec",
                "Run nuclei with api-security templates",
                "Use OWASP ZAP API scan",
            ],
        }

    elif action == "find_auth_endpoints":
        paths = api_spec.get("paths", {})
        servers = api_spec.get("servers", [])
        base_url = servers[0].get("url", "") if servers else ""

        auth_keywords = ["auth", "login", "logout", "register", "signup", "password", "token", "oauth", "session", "verify", "forgot", "reset"]

        auth_endpoints = []
        no_auth_endpoints = []

        for path, methods in paths.items():
            is_auth_endpoint = any(kw in path.lower() for kw in auth_keywords)

            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue

                security = details.get("security", api_spec.get("security", []))

                endpoint_info = {
                    "path": path,
                    "method": method.upper(),
                    "summary": details.get("summary", ""),
                    "full_url": f"{base_url}{path}",
                }

                if is_auth_endpoint:
                    auth_endpoints.append(endpoint_info)

                if not security and not is_auth_endpoint:
                    no_auth_endpoints.append(endpoint_info)

        return {
            "action": "find_auth_endpoints",
            "auth_endpoints": auth_endpoints,
            "no_auth_endpoints": no_auth_endpoints,
            "security_findings": {
                "auth_related_count": len(auth_endpoints),
                "unauthenticated_count": len(no_auth_endpoints),
            },
            "testing_recommendations": [
                "Test login endpoint for brute force protection",
                "Check password reset flow for token leakage",
                "Test registration for duplicate accounts",
                "Verify unauthenticated endpoints should be public",
            ],
            "common_auth_vulns": [
                "Broken brute force protection",
                "Predictable password reset tokens",
                "JWT vulnerabilities",
                "Session fixation",
                "OAuth misconfigurations",
            ],
        }

    return generate_usage_hint("openapi_parser", VALID_ACTIONS)
