"""Request Logger tool for logging and analyzing HTTP requests/responses."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Literal

from strix.tools.registry import register_tool


RequestLoggerAction = Literal["log", "search", "analyze", "summarize", "clear"]


# In-memory request storage (for session-based logging)
_request_log: list[dict[str, Any]] = []


def _generate_request_id(request: dict[str, Any]) -> str:
    """Generate a unique ID for a request."""
    content = f"{request.get('method', '')}{request.get('url', '')}{request.get('timestamp', '')}"
    return hashlib.md5(content.encode()).hexdigest()[:12]  # noqa: S324


def _extract_request_features(request: dict[str, Any]) -> dict[str, Any]:
    """Extract security-relevant features from a request."""
    features: dict[str, Any] = {}

    url = request.get("url", "")
    method = request.get("method", "GET")
    headers = request.get("headers", {})
    body = request.get("body", "")

    # URL features
    features["has_parameters"] = "?" in url
    features["parameter_count"] = url.count("&") + 1 if "?" in url else 0

    # Method features
    features["method"] = method
    features["is_state_changing"] = method.upper() in ["POST", "PUT", "PATCH", "DELETE"]

    # Header features
    features["has_auth"] = any(h.lower() in ["authorization", "x-api-key", "cookie"] for h in headers)
    features["content_type"] = headers.get("Content-Type", headers.get("content-type", ""))
    features["has_json_body"] = "application/json" in features["content_type"]

    # Body features
    features["body_length"] = len(body) if body else 0
    features["has_body"] = bool(body)

    # Security indicators
    features["potential_sensitive"] = any(
        kw in url.lower() or kw in str(body).lower()
        for kw in ["password", "token", "secret", "api_key", "credit", "ssn"]
    )

    return features


def _match_filter(request: dict[str, Any], filters: dict[str, Any]) -> bool:
    """Check if a request matches the given filters."""
    for key, value in filters.items():
        if key == "method" and request.get("method", "").upper() != value.upper():
            return False
        if key == "url_contains" and value.lower() not in request.get("url", "").lower():
            return False
        if key == "status_code" and request.get("response", {}).get("status_code") != value:
            return False
        if key == "min_response_time" and request.get("response_time", 0) < value:
            return False
        if key == "has_error" and (request.get("response", {}).get("status_code", 200) < 400) == value:
            return False
        if key == "body_contains" and value.lower() not in request.get("body", "").lower():
            return False
        if key == "response_contains":
            response_body = request.get("response", {}).get("body", "")
            if value.lower() not in response_body.lower():
                return False
    return True


def _analyze_requests(requests: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze a collection of requests for patterns."""
    if not requests:
        return {"error": "No requests to analyze"}

    analysis: dict[str, Any] = {
        "total_requests": len(requests),
        "methods": {},
        "status_codes": {},
        "endpoints": {},
        "timing": {},
        "security_findings": [],
    }

    response_times: list[float] = []

    for req in requests:
        # Method distribution
        method = req.get("method", "UNKNOWN")
        analysis["methods"][method] = analysis["methods"].get(method, 0) + 1

        # Status code distribution
        status = req.get("response", {}).get("status_code", 0)
        if status:
            analysis["status_codes"][status] = analysis["status_codes"].get(status, 0) + 1

        # Endpoint analysis
        url = req.get("url", "")
        # Extract path without query string
        path = url.split("?")[0] if "?" in url else url
        # Normalize path parameters
        normalized_path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        analysis["endpoints"][normalized_path] = analysis["endpoints"].get(normalized_path, 0) + 1

        # Timing
        if "response_time" in req:
            response_times.append(req["response_time"])

        # Security findings
        features = _extract_request_features(req)
        if features.get("potential_sensitive"):
            analysis["security_findings"].append({
                "type": "sensitive_data",
                "request_id": req.get("id"),
                "url": url[:100],
            })

        # Check for interesting status codes
        if status in [401, 403, 500, 502, 503]:
            analysis["security_findings"].append({
                "type": f"status_{status}",
                "request_id": req.get("id"),
                "url": url[:100],
            })

    # Calculate timing statistics
    if response_times:
        analysis["timing"] = {
            "min": round(min(response_times), 2),
            "max": round(max(response_times), 2),
            "avg": round(sum(response_times) / len(response_times), 2),
        }

    return analysis


@register_tool
def request_logger(
    action: RequestLoggerAction,
    request: dict[str, Any] | None = None,
    filters: dict[str, Any] | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Log HTTP requests/responses with search and analysis capabilities.

    This tool maintains a log of HTTP requests and responses for analysis,
    pattern detection, and security testing workflows.

    Args:
        action: The logging action to perform:
            - log: Log a new request/response
            - search: Search logged requests with filters
            - analyze: Analyze logged requests for patterns
            - summarize: Get summary of logged requests
            - clear: Clear the request log
        request: Request data to log (for log action):
            - method: HTTP method
            - url: Request URL
            - headers: Request headers dict
            - body: Request body
            - response: Response data (status_code, headers, body)
            - response_time: Response time in ms
        filters: Search filters (for search action):
            - method: Filter by HTTP method
            - url_contains: Filter by URL substring
            - status_code: Filter by response status code
            - min_response_time: Filter by minimum response time
            - has_error: Filter by error status (4xx/5xx)
            - body_contains: Filter by request body content
            - response_contains: Filter by response body content
        limit: Maximum number of results to return

    Returns:
        Logged request details, search results, or analysis
    """
    global _request_log  # noqa: PLW0603

    try:
        if action == "log":
            if not request:
                return {"error": "request data required for log action"}

            # Add metadata
            logged_request = {
                **request,
                "id": _generate_request_id(request),
                "timestamp": datetime.now().isoformat(),  # noqa: DTZ005
                "features": _extract_request_features(request),
            }

            _request_log.append(logged_request)

            # Keep log size manageable
            if len(_request_log) > 1000:
                _request_log = _request_log[-500:]

            return {
                "logged": True,
                "request_id": logged_request["id"],
                "log_size": len(_request_log),
            }

        if action == "search":
            results = _request_log.copy()

            # Apply filters
            if filters:
                results = [r for r in results if _match_filter(r, filters)]

            # Apply limit
            results = results[-limit:]

            return {
                "results": results,
                "count": len(results),
                "total_logged": len(_request_log),
                "filters_applied": filters or {},
            }

        if action == "analyze":
            analysis = _analyze_requests(_request_log)
            return analysis

        if action == "summarize":
            if not _request_log:
                return {
                    "total": 0,
                    "message": "No requests logged",
                }

            summary: dict[str, Any] = {
                "total": len(_request_log),
                "first_request": _request_log[0].get("timestamp") if _request_log else None,
                "last_request": _request_log[-1].get("timestamp") if _request_log else None,
                "unique_endpoints": len({r.get("url", "").split("?")[0] for r in _request_log}),
                "methods": {},
                "status_overview": {
                    "success": 0,
                    "redirect": 0,
                    "client_error": 0,
                    "server_error": 0,
                },
            }

            for req in _request_log:
                method = req.get("method", "UNKNOWN")
                summary["methods"][method] = summary["methods"].get(method, 0) + 1

                status = req.get("response", {}).get("status_code", 0)
                if 200 <= status < 300:
                    summary["status_overview"]["success"] += 1
                elif 300 <= status < 400:
                    summary["status_overview"]["redirect"] += 1
                elif 400 <= status < 500:
                    summary["status_overview"]["client_error"] += 1
                elif status >= 500:
                    summary["status_overview"]["server_error"] += 1

            return summary

        if action == "clear":
            count = len(_request_log)
            _request_log = []
            return {
                "cleared": True,
                "requests_removed": count,
            }

        return {"error": f"Unknown action: {action}"}

    except (TypeError, ValueError, KeyError) as e:
        return {"error": f"Request logging failed: {e!s}"}
