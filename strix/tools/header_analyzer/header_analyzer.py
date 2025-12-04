"""Header Analyzer tool for analyzing HTTP security headers."""

from __future__ import annotations

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    add_workflow_hint_for_url_params,
    detect_url_in_unknown_params,
    generate_usage_hint,
    validate_action_param,
    validate_unknown_params,
)


HeaderAction = Literal["analyze", "check_csp", "check_hsts", "check_cookies", "recommendations"]


# Security headers and their expected values
SECURITY_HEADERS = {
    "strict-transport-security": {
        "description": "HTTP Strict Transport Security",
        "recommendation": "max-age=31536000; includeSubDomains; preload",
        "severity_missing": "high",
    },
    "content-security-policy": {
        "description": "Content Security Policy",
        "recommendation": "Define restrictive CSP based on application needs",
        "severity_missing": "high",
    },
    "x-frame-options": {
        "description": "Clickjacking protection",
        "recommendation": "DENY or SAMEORIGIN",
        "severity_missing": "medium",
    },
    "x-content-type-options": {
        "description": "MIME type sniffing protection",
        "recommendation": "nosniff",
        "severity_missing": "medium",
    },
    "x-xss-protection": {
        "description": "XSS filter (legacy)",
        "recommendation": "0 (disabled, rely on CSP instead)",
        "severity_missing": "low",
    },
    "referrer-policy": {
        "description": "Referrer information control",
        "recommendation": "strict-origin-when-cross-origin or no-referrer",
        "severity_missing": "low",
    },
    "permissions-policy": {
        "description": "Browser feature permissions",
        "recommendation": "Disable unnecessary features",
        "severity_missing": "low",
    },
    "cross-origin-opener-policy": {
        "description": "Cross-origin isolation",
        "recommendation": "same-origin",
        "severity_missing": "low",
    },
    "cross-origin-embedder-policy": {
        "description": "Cross-origin resource embedding",
        "recommendation": "require-corp",
        "severity_missing": "low",
    },
    "cross-origin-resource-policy": {
        "description": "Cross-origin resource sharing",
        "recommendation": "same-origin",
        "severity_missing": "low",
    },
}


def _analyze_all_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Analyze all security headers."""
    normalized = {k.lower(): v for k, v in headers.items()}

    present: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []

    for header, info in SECURITY_HEADERS.items():
        if header in normalized:
            present.append({
                "header": header,
                "value": normalized[header],
                "description": info["description"],
            })
        else:
            missing.append({
                "header": header,
                "description": info["description"],
                "recommendation": info["recommendation"],
                "severity": info["severity_missing"],
            })

    # Check for information disclosure headers
    disclosure_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
    info_disclosure = []
    for header in disclosure_headers:
        if header in normalized:
            info_disclosure.append({
                "header": header,
                "value": normalized[header],
                "severity": "low",
                "recommendation": "Remove or genericize this header to reduce information leakage",
            })

    return {
        "present": present,
        "missing": missing,
        "info_disclosure": info_disclosure,
    }


def _analyze_csp(csp: str) -> dict[str, Any]:
    """Analyze Content Security Policy for weaknesses."""
    issues: list[dict[str, Any]] = []
    info: list[dict[str, Any]] = []

    # Parse CSP directives
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directive = tokens[0].lower()
            values = tokens[1:] if len(tokens) > 1 else []
            directives[directive] = values

    # Check for dangerous sources
    dangerous_sources = ["'unsafe-inline'", "'unsafe-eval'", "data:", "blob:"]
    script_directives = ["script-src", "default-src"]

    for directive in script_directives:
        if directive in directives:
            for source in dangerous_sources[:2]:  # unsafe-inline and unsafe-eval
                if source in directives[directive]:
                    issues.append({
                        "severity": "high",
                        "directive": directive,
                        "issue": f"{source} allows inline scripts/eval",
                        "value": source,
                    })
            for source in dangerous_sources[2:]:  # data: and blob:
                if source in directives[directive]:
                    issues.append({
                        "severity": "medium",
                        "directive": directive,
                        "issue": f"{source} URI scheme may allow XSS",
                        "value": source,
                    })

    # Check for wildcard
    for directive, values in directives.items():
        if "*" in values:
            issues.append({
                "severity": "high",
                "directive": directive,
                "issue": "Wildcard (*) allows any source",
                "value": "*",
            })

    # Check for missing directives
    if "default-src" not in directives:
        info.append({
            "directive": "default-src",
            "message": "No default-src fallback defined",
        })

    if "script-src" not in directives and "default-src" not in directives:
        issues.append({
            "severity": "high",
            "directive": "script-src",
            "issue": "No script-src defined and no default-src fallback",
        })

    # Check for report-uri/report-to
    if "report-uri" not in directives and "report-to" not in directives:
        info.append({
            "directive": "report-uri/report-to",
            "message": "No CSP reporting configured",
        })

    # Check for JSONP endpoints or common bypass sources
    bypass_patterns = ["ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net"]
    for directive, values in directives.items():
        for value in values:
            for pattern in bypass_patterns:
                if pattern in value.lower():
                    info.append({
                        "directive": directive,
                        "message": f"{pattern} may host JSONP/callback endpoints for CSP bypass",
                        "value": value,
                    })

    return {
        "directives": directives,
        "issues": issues,
        "info": info,
        "score": "weak" if any(i["severity"] == "high" for i in issues) else "moderate" if issues else "strong",
    }


def _analyze_hsts(hsts: str) -> dict[str, Any]:
    """Analyze HSTS header configuration."""
    issues: list[dict[str, Any]] = []
    info: list[dict[str, Any]] = []

    # Parse HSTS directives
    parts = [p.strip().lower() for p in hsts.split(";")]
    max_age = None
    include_subdomains = False
    preload = False

    for part in parts:
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=")[1])
            except ValueError:
                issues.append({
                    "severity": "high",
                    "issue": "Invalid max-age value",
                    "value": part,
                })
        elif part == "includesubdomains":
            include_subdomains = True
        elif part == "preload":
            preload = True

    # Analyze configuration
    if max_age is None:
        issues.append({
            "severity": "high",
            "issue": "No max-age directive",
        })
    elif max_age < 31536000:  # Less than 1 year
        issues.append({
            "severity": "medium",
            "issue": f"max-age is less than 1 year ({max_age} seconds)",
            "recommendation": "Use max-age=31536000 (1 year) or higher",
        })

    if not include_subdomains:
        info.append({
            "directive": "includeSubDomains",
            "message": "Subdomains not included in HSTS",
        })

    if preload and not include_subdomains:
        issues.append({
            "severity": "medium",
            "issue": "preload requires includeSubDomains",
        })

    if preload and max_age and max_age < 31536000:
        issues.append({
            "severity": "medium",
            "issue": "preload requires max-age of at least 1 year",
        })

    return {
        "max_age": max_age,
        "include_subdomains": include_subdomains,
        "preload": preload,
        "issues": issues,
        "info": info,
        "preload_eligible": max_age and max_age >= 31536000 and include_subdomains and preload,
    }


def _analyze_cookies(cookies: list[str]) -> dict[str, Any]:
    """Analyze cookie security attributes."""
    analyzed_cookies: list[dict[str, Any]] = []

    for cookie in cookies:
        parts = [p.strip() for p in cookie.split(";")]
        name_value = parts[0] if parts else ""
        name = name_value.split("=")[0] if "=" in name_value else name_value

        attributes = {p.lower(): True for p in parts[1:] if "=" not in p}
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                attributes[key.lower()] = value

        issues = []

        # Check Secure flag
        if "secure" not in attributes:
            issues.append({
                "attribute": "Secure",
                "severity": "high",
                "issue": "Missing Secure flag - cookie sent over HTTP",
            })

        # Check HttpOnly flag
        if "httponly" not in attributes:
            issues.append({
                "attribute": "HttpOnly",
                "severity": "medium",
                "issue": "Missing HttpOnly flag - accessible via JavaScript",
            })

        # Check SameSite attribute
        samesite = attributes.get("samesite", "").lower()
        if not samesite:
            issues.append({
                "attribute": "SameSite",
                "severity": "medium",
                "issue": "Missing SameSite attribute",
            })
        elif samesite == "none" and "secure" not in attributes:
            issues.append({
                "attribute": "SameSite",
                "severity": "high",
                "issue": "SameSite=None requires Secure flag",
            })

        analyzed_cookies.append({
            "name": name,
            "attributes": attributes,
            "issues": issues,
        })

    return {"cookies": analyzed_cookies}


@register_tool
def header_analyzer(
    action: HeaderAction,
    headers: dict[str, str] | None = None,
    csp: str | None = None,
    hsts: str | None = None,
    cookies: list[str] | None = None,
    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Analyze HTTP security headers for misconfigurations.

    This tool provides comprehensive analysis of HTTP security headers
    including CSP, HSTS, cookie attributes, and other security-related headers.

    Args:
        action: The analysis action to perform:
            - analyze: Full header analysis
            - check_csp: Analyze Content Security Policy
            - check_hsts: Analyze HSTS configuration
            - check_cookies: Analyze cookie security attributes
            - recommendations: Get security header recommendations
        headers: HTTP response headers to analyze (dict)
        csp: Content Security Policy header value
        hsts: HSTS header value
        cookies: List of Set-Cookie header values

    Returns:
        Analysis results including issues, recommendations, and security score
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "headers", "csp", "hsts", "cookies"}
    VALID_ACTIONS = ["analyze", "check_csp", "check_hsts", "check_cookies", "recommendations"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "header_analyzer")
    if unknown_error:
        unknown_params = list(kwargs.keys())
        # Detect common mistake of passing URL instead of headers
        if detect_url_in_unknown_params(unknown_params):
            workflow_steps = [
                "1. Use send_request(method='GET', url='https://example.com') to fetch the page",
                "2. Extract headers from the response",
                "3. Call header_analyzer(action='analyze', headers={...extracted headers...})",
            ]
            unknown_error = add_workflow_hint_for_url_params(unknown_error, workflow_steps)

        unknown_error.update(
            generate_usage_hint(
                "header_analyzer",
                "analyze",
                {"headers": {"Content-Type": "text/html", "Server": "nginx"}},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "header_analyzer")
    if action_error:
        action_error["usage_examples"] = {
            "analyze": "header_analyzer(action='analyze', headers={'Content-Type': 'text/html'})",
            "check_csp": "header_analyzer(action='check_csp', csp='default-src self')",
            "check_hsts": "header_analyzer(action='check_hsts', hsts='max-age=31536000')",
            "check_cookies": "header_analyzer(action='check_cookies', cookies=['session=abc; Secure'])",
        }
        return action_error

    try:
        if action == "analyze":
            if not headers:
                return {"error": "headers parameter required for this action"}

            analysis = _analyze_all_headers(headers)

            # Calculate overall score
            high_missing = len([m for m in analysis["missing"] if m["severity"] == "high"])
            medium_missing = len([m for m in analysis["missing"] if m["severity"] == "medium"])

            if high_missing >= 2:
                overall = "poor"
            elif high_missing >= 1 or medium_missing >= 3:
                overall = "moderate"
            elif medium_missing >= 1:
                overall = "good"
            else:
                overall = "excellent"

            return {
                **analysis,
                "overall_score": overall,
                "summary": {
                    "headers_present": len(analysis["present"]),
                    "headers_missing": len(analysis["missing"]),
                    "info_disclosure": len(analysis["info_disclosure"]),
                },
            }

        if action == "check_csp":
            if not csp and headers:
                normalized = {k.lower(): v for k, v in headers.items()}
                csp = normalized.get("content-security-policy")

            if not csp:
                return {"error": "No CSP header found or provided"}

            return _analyze_csp(csp)

        if action == "check_hsts":
            if not hsts and headers:
                normalized = {k.lower(): v for k, v in headers.items()}
                hsts = normalized.get("strict-transport-security")

            if not hsts:
                return {"error": "No HSTS header found or provided"}

            return _analyze_hsts(hsts)

        if action == "check_cookies":
            if not cookies:
                return {"error": "cookies parameter required for this action"}

            return _analyze_cookies(cookies)

        if action == "recommendations":
            return {
                "recommended_headers": [
                    {
                        "header": header,
                        "description": info["description"],
                        "recommendation": info["recommendation"],
                        "priority": info["severity_missing"],
                    }
                    for header, info in SECURITY_HEADERS.items()
                ],
                "example_headers": {
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
                },
            }

        return {"error": f"Unknown action: {action}"}

    except (KeyError, ValueError, TypeError) as e:
        return {"error": f"Header analysis failed: {e!s}"}
