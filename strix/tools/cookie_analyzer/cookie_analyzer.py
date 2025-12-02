"""Cookie security analyzer for web application testing."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlparse

import requests

from strix.tools.registry import register_tool


CookieAction = Literal["analyze", "check_attributes", "list"]


def _parse_set_cookie(header: str) -> dict[str, Any]:
    """Parse a Set-Cookie header into components."""
    cookie: dict[str, Any] = {
        "name": "",
        "value": "",
        "attributes": {},
        "security_flags": {},
    }

    parts = header.split(";")

    # First part is name=value
    if parts:
        name_value = parts[0].strip()
        if "=" in name_value:
            name, _, value = name_value.partition("=")
            cookie["name"] = name.strip()
            cookie["value"] = value.strip()
        else:
            cookie["name"] = name_value

    # Parse attributes
    for raw_part in parts[1:]:
        part = raw_part.strip()
        if not part:
            continue

        if "=" in part:
            attr_name, _, attr_value = part.partition("=")
            attr_name = attr_name.strip().lower()
            attr_value = attr_value.strip()
            cookie["attributes"][attr_name] = attr_value
        else:
            attr_name = part.lower()
            cookie["attributes"][attr_name] = True

    # Extract security-relevant flags
    cookie["security_flags"] = {
        "secure": "secure" in cookie["attributes"],
        "httponly": "httponly" in cookie["attributes"],
        "samesite": cookie["attributes"].get("samesite", "Not Set"),
        "path": cookie["attributes"].get("path", "/"),
        "domain": cookie["attributes"].get("domain", ""),
        "expires": cookie["attributes"].get("expires", ""),
        "max-age": cookie["attributes"].get("max-age", ""),
    }

    return cookie


def _analyze_cookie_security(cookie: dict[str, Any]) -> dict[str, Any]:
    """Analyze a cookie for security issues."""
    issues: list[dict[str, str]] = []
    recommendations: list[str] = []
    flags = cookie.get("security_flags", {})
    name = cookie.get("name", "").lower()

    # Check Secure flag
    if not flags.get("secure"):
        issues.append({
            "severity": "high",
            "issue": "Missing Secure flag - cookie sent over HTTP",
        })
        recommendations.append("Add Secure flag to prevent transmission over HTTP")

    # Check HttpOnly flag
    if not flags.get("httponly"):
        issues.append({
            "severity": "medium",
            "issue": "Missing HttpOnly flag - accessible to JavaScript",
        })
        recommendations.append("Add HttpOnly flag to prevent XSS cookie theft")

    # Check SameSite
    samesite = flags.get("samesite", "Not Set")
    if samesite == "Not Set" or samesite is True:
        issues.append({
            "severity": "medium",
            "issue": "SameSite attribute not set or invalid",
        })
        recommendations.append("Set SameSite=Strict or SameSite=Lax")
    elif str(samesite).lower() == "none" and not flags.get("secure"):
        issues.append({
            "severity": "high",
            "issue": "SameSite=None requires Secure flag",
        })

    # Check for session cookie indicators
    session_indicators = ["session", "sess", "sid", "jsessionid", "phpsessid", "aspsessionid"]
    is_session = any(ind in name for ind in session_indicators)

    if is_session:
        cookie["is_session_cookie"] = True
        if not flags.get("httponly"):
            issues.append({
                "severity": "critical",
                "issue": "Session cookie without HttpOnly - high XSS risk",
            })

    # Check for auth token indicators
    auth_indicators = ["auth", "token", "jwt", "access", "bearer", "api"]
    is_auth = any(ind in name for ind in auth_indicators)

    if is_auth:
        cookie["is_auth_cookie"] = True
        if not flags.get("secure"):
            issues.append({
                "severity": "critical",
                "issue": "Authentication cookie without Secure flag",
            })

    # Check path scope
    path = flags.get("path", "/")
    if path != "/":
        cookie["path_scoped"] = True
    else:
        cookie["path_scoped"] = False

    # Check domain scope
    domain = flags.get("domain", "")
    if domain and domain.startswith("."):
        issues.append({
            "severity": "low",
            "issue": f"Cookie domain includes subdomains: {domain}",
        })

    # Check expiration
    max_age = flags.get("max-age", "")

    if max_age:
        try:
            age_seconds = int(max_age)
            if age_seconds > 31536000:  # More than 1 year
                issues.append({
                    "severity": "low",
                    "issue": "Cookie has very long expiration (>1 year)",
                })
        except ValueError:
            # Ignore invalid max-age values; treat as no expiration set.
            pass

    return {
        "cookie": cookie,
        "issues": issues,
        "issue_count": len(issues),
        "recommendations": recommendations,
        "security_score": "secure" if not issues else (
            "critical" if any(i["severity"] == "critical" for i in issues) else "insecure"
        ),
    }


def _analyze_url_cookies(url: str) -> dict[str, Any]:
    """Fetch and analyze cookies from a URL."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)

        set_cookie_headers = response.headers.get("Set-Cookie", "")

        # Handle multiple Set-Cookie headers
        cookies = []
        if hasattr(response.raw, "headers"):
            # Get all Set-Cookie headers
            for header in response.raw.headers.getlist("Set-Cookie"):
                cookies.append(_parse_set_cookie(header))
        elif set_cookie_headers:
            cookies.append(_parse_set_cookie(set_cookie_headers))

        # Also check response.cookies
        for cookie in response.cookies:
            cookie_dict = {
                "name": cookie.name,
                "value": cookie.value[:50] + "..." if len(cookie.value) > 50 else cookie.value,
                "attributes": {},
                "security_flags": {
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("httponly"),
                    "samesite": cookie.get_nonstandard_attr("samesite", "Not Set"),
                    "path": cookie.path,
                    "domain": cookie.domain,
                    "expires": cookie.expires,
                },
            }
            # Avoid duplicates
            if not any(c["name"] == cookie.name for c in cookies):
                cookies.append(cookie_dict)

        # Analyze each cookie
        analyzed = []
        total_issues = 0
        critical_issues = 0

        for cookie in cookies:
            analysis = _analyze_cookie_security(cookie)
            analyzed.append(analysis)
            total_issues += analysis["issue_count"]
            if analysis["security_score"] == "critical":
                critical_issues += 1

        return {
            "url": url,
            "cookies_found": len(cookies),
            "total_issues": total_issues,
            "critical_issues": critical_issues,
            "analyzed_cookies": analyzed,
        }

    except requests.exceptions.RequestException as e:
        return {
            "url": url,
            "error": f"Request failed: {e!s}",
        }


def _check_attributes(
    url: str,
    cookie_name: str | None = None,
) -> dict[str, Any]:
    """Check specific cookie attributes."""
    result = _analyze_url_cookies(url)

    if "error" in result:
        return result

    analyzed = result.get("analyzed_cookies", [])

    if cookie_name:
        analyzed = [
            a for a in analyzed
            if a.get("cookie", {}).get("name", "").lower() == cookie_name.lower()
        ]

    summary = {
        "url": url,
        "cookies_checked": len(analyzed),
        "attribute_summary": {
            "with_secure": 0,
            "with_httponly": 0,
            "with_samesite_strict": 0,
            "with_samesite_lax": 0,
            "with_samesite_none": 0,
            "session_cookies": 0,
            "auth_cookies": 0,
        },
        "details": [],
    }

    for analysis in analyzed:
        cookie = analysis.get("cookie", {})
        flags = cookie.get("security_flags", {})

        if flags.get("secure"):
            summary["attribute_summary"]["with_secure"] += 1
        if flags.get("httponly"):
            summary["attribute_summary"]["with_httponly"] += 1

        samesite = str(flags.get("samesite", "")).lower()
        if samesite == "strict":
            summary["attribute_summary"]["with_samesite_strict"] += 1
        elif samesite == "lax":
            summary["attribute_summary"]["with_samesite_lax"] += 1
        elif samesite == "none":
            summary["attribute_summary"]["with_samesite_none"] += 1

        if cookie.get("is_session_cookie"):
            summary["attribute_summary"]["session_cookies"] += 1
        if cookie.get("is_auth_cookie"):
            summary["attribute_summary"]["auth_cookies"] += 1

        summary["details"].append({
            "name": cookie.get("name", ""),
            "secure": flags.get("secure"),
            "httponly": flags.get("httponly"),
            "samesite": flags.get("samesite"),
            "issues": len(analysis.get("issues", [])),
        })

    return summary


def _list_cookies(url: str) -> dict[str, Any]:
    """List all cookies from a URL."""
    result = _analyze_url_cookies(url)

    if "error" in result:
        return result

    cookies = []
    for analysis in result.get("analyzed_cookies", []):
        cookie = analysis.get("cookie", {})
        cookies.append({
            "name": cookie.get("name", ""),
            "value_preview": cookie.get("value", "")[:20] + "..." if len(
                cookie.get("value", ""),
            ) > 20 else cookie.get("value", ""),
            "flags": cookie.get("security_flags", {}),
        })

    return {
        "url": url,
        "cookie_count": len(cookies),
        "cookies": cookies,
    }


@register_tool
def cookie_analyzer(
    action: CookieAction,
    url: str,
    cookie_name: str | None = None,
) -> dict[str, Any]:
    """Analyze cookie security for web applications.

    This tool checks cookie attributes for security best practices
    including Secure, HttpOnly, SameSite flags, path/domain scope,
    and identifies session and authentication cookies.

    Args:
        action: The analysis action to perform:
            - analyze: Full security analysis of all cookies
            - check_attributes: Check specific security attributes
            - list: List all cookies from a URL
        url: Target URL to analyze
        cookie_name: Specific cookie to analyze (optional)

    Returns:
        Cookie security analysis with issues and recommendations
    """
    try:
        if action == "analyze":
            return _analyze_url_cookies(url)

        if action == "check_attributes":
            return _check_attributes(url, cookie_name)

        if action == "list":
            return _list_cookies(url)

        return {"error": f"Unknown action: {action}"}

    except (ValueError, KeyError) as e:
        return {"error": f"Cookie analysis failed: {e!s}"}
