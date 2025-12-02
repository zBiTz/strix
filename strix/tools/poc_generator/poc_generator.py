"""PoC Generator tool for generating proof of concept scripts."""

from __future__ import annotations

import json
from typing import Any, Literal

from strix.tools.registry import register_tool


PoCFormat = Literal["curl", "python", "javascript", "html", "burp", "httpie"]
PoCGeneratorAction = Literal["generate", "generate_all"]


def _generate_curl(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    cookies: dict[str, str] | None,
) -> str:
    """Generate curl command."""
    parts = ["curl", "-X", method]

    # Add headers
    for name, value in headers.items():
        parts.append("-H")
        parts.append(f"'{name}: {value}'")

    # Add cookies
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        parts.append("-H")
        parts.append(f"'Cookie: {cookie_str}'")

    # Add body
    if body:
        parts.append("-d")
        # Escape single quotes in body
        escaped_body = body.replace("'", "'\\''")
        parts.append(f"'{escaped_body}'")

    # Add URL (quoted)
    parts.append(f"'{url}'")

    return " \\\n  ".join(parts)


def _generate_python(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    cookies: dict[str, str] | None,
) -> str:
    """Generate Python requests code."""
    lines = [
        "import requests",
        "",
        f'url = "{url}"',
        "",
    ]

    # Headers
    if headers:
        lines.append("headers = {")
        for name, value in headers.items():
            lines.append(f'    "{name}": "{value}",')
        lines.append("}")
    else:
        lines.append("headers = {}")

    # Cookies
    if cookies:
        lines.append("")
        lines.append("cookies = {")
        for name, value in cookies.items():
            lines.append(f'    "{name}": "{value}",')
        lines.append("}")
    else:
        lines.append("")
        lines.append("cookies = {}")

    # Body
    if body:
        lines.append("")
        # Try to parse as JSON for pretty formatting
        try:
            json_body = json.loads(body)
            lines.append(f"data = {json.dumps(json_body, indent=4)}")
        except json.JSONDecodeError:
            escaped_body = body.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'data = "{escaped_body}"')
    else:
        lines.append("")
        lines.append("data = None")

    # Request
    lines.append("")
    lines.append(f"response = requests.{method.lower()}(")
    lines.append("    url,")
    lines.append("    headers=headers,")
    lines.append("    cookies=cookies,")
    if body:
        if "application/json" in str(headers.get("Content-Type", "")):
            lines.append("    json=data,")
        else:
            lines.append("    data=data,")
    lines.append(")")
    lines.append("")
    lines.append("print(f'Status: {response.status_code}')")
    lines.append("print(response.text)")

    return "\n".join(lines)


def _generate_javascript(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    cookies: dict[str, str] | None,
) -> str:
    """Generate JavaScript fetch code."""
    lines = [
        "// JavaScript PoC using fetch",
        "",
        f'const url = "{url}";',
        "",
        "const options = {",
        f'  method: "{method}",',
        "  headers: {",
    ]

    for name, value in headers.items():
        lines.append(f'    "{name}": "{value}",')

    lines.append("  },")

    if body:
        try:
            json_body = json.loads(body)
            lines.append(f"  body: JSON.stringify({json.dumps(json_body)}),")
        except json.JSONDecodeError:
            escaped_body = body.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'  body: "{escaped_body}",')

    if cookies:
        lines.append('  credentials: "include",  // Include cookies')

    lines.append("};")
    lines.append("")
    lines.append("fetch(url, options)")
    lines.append("  .then(response => response.text())")
    lines.append("  .then(data => console.log(data))")
    lines.append("  .catch(error => console.error('Error:', error));")

    return "\n".join(lines)


def _generate_html(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    cookies: dict[str, str] | None,
    vulnerability_type: str = "generic",
) -> str:
    """Generate HTML PoC page."""
    lines = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        f"    <title>PoC - {vulnerability_type}</title>",
        "</head>",
        "<body>",
        f"    <h1>Proof of Concept: {vulnerability_type}</h1>",
    ]

    if method.upper() == "GET":
        lines.append(f'    <a href="{url}">Click to trigger</a>')
    elif vulnerability_type.lower() in ["csrf", "xss"]:
        # Auto-submit form for CSRF
        lines.append('    <form id="poc-form" method="POST" action="' + url + '">')
        if body:
            try:
                json_body = json.loads(body)
                for key, value in json_body.items():
                    lines.append(f'        <input type="hidden" name="{key}" value="{value}" />')
            except json.JSONDecodeError:
                # URL-encoded body
                pairs = body.split("&")
                for pair in pairs:
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        lines.append(f'        <input type="hidden" name="{key}" value="{value}" />')
        lines.append('        <input type="submit" value="Submit" />')
        lines.append("    </form>")
        lines.append("    <script>")
        lines.append("        // Auto-submit for PoC demonstration")
        lines.append("        // document.getElementById('poc-form').submit();")
        lines.append("    </script>")
    else:
        # Generic form
        lines.append(f'    <form method="{method}" action="{url}">')
        lines.append('        <input type="submit" value="Submit" />')
        lines.append("    </form>")

    lines.append("</body>")
    lines.append("</html>")

    return "\n".join(lines)


def _generate_burp(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    cookies: dict[str, str] | None,
) -> str:
    """Generate raw HTTP request for Burp Suite."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    lines = [f"{method} {path} HTTP/1.1"]
    lines.append(f"Host: {parsed.netloc}")

    for name, value in headers.items():
        if name.lower() != "host":
            lines.append(f"{name}: {value}")

    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        lines.append(f"Cookie: {cookie_str}")

    if body:
        lines.append(f"Content-Length: {len(body)}")

    lines.append("")

    if body:
        lines.append(body)

    return "\r\n".join(lines)


def _generate_httpie(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    cookies: dict[str, str] | None,
) -> str:
    """Generate HTTPie command."""
    parts = ["http", method.upper(), f'"{url}"']

    # Add headers
    for name, value in headers.items():
        parts.append(f'"{name}:{value}"')

    # Add cookies as header
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        parts.append(f'"Cookie:{cookie_str}"')

    # Add body parameters
    if body:
        try:
            json_body = json.loads(body)
            for key, value in json_body.items():
                if isinstance(value, str):
                    parts.append(f'{key}="{value}"')
                else:
                    parts.append(f"{key}:={json.dumps(value)}")
        except json.JSONDecodeError:
            # Raw body
            parts.append(f"<<<'{body}'")

    return " \\\n  ".join(parts)


@register_tool
def poc_generator(
    action: PoCGeneratorAction,
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    cookies: dict[str, str] | None = None,
    poc_format: PoCFormat | None = None,
    vulnerability_type: str = "generic",
    description: str = "",
) -> dict[str, Any]:
    """Generate Proof of Concept scripts in multiple formats.

    This tool generates PoC code for demonstrating vulnerabilities
    in various formats including curl, Python, JavaScript, and HTML.

    Args:
        action: The generation action:
            - generate: Generate PoC in specified format
            - generate_all: Generate PoC in all formats
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        url: Target URL
        headers: HTTP headers dictionary
        body: Request body (for POST/PUT)
        cookies: Cookies dictionary
        poc_format: Output format (curl, python, javascript, html, burp, httpie)
        vulnerability_type: Type of vulnerability (for documentation)
        description: Description of the vulnerability

    Returns:
        Generated PoC code in requested format(s)
    """
    try:
        if not url:
            return {"error": "url parameter required"}

        headers = headers or {}
        cookies = cookies or {}

        # Ensure Content-Type for body requests
        if body and "Content-Type" not in headers and "content-type" not in headers:
            try:
                json.loads(body)
                headers["Content-Type"] = "application/json"
            except json.JSONDecodeError:
                headers["Content-Type"] = "application/x-www-form-urlencoded"

        generators = {
            "curl": _generate_curl,
            "python": _generate_python,
            "javascript": _generate_javascript,
            "html": lambda m, u, h, b, c: _generate_html(m, u, h, b, c, vulnerability_type),
            "burp": _generate_burp,
            "httpie": _generate_httpie,
        }

        if action == "generate":
            if not poc_format:
                return {"error": "poc_format required for generate action"}

            if poc_format not in generators:
                return {
                    "error": f"Unknown format: {poc_format}",
                    "available_formats": list(generators.keys()),
                }

            generator = generators[poc_format]
            code = generator(method, url, headers, body, cookies)

            return {
                "format": poc_format,
                "code": code,
                "vulnerability_type": vulnerability_type,
                "description": description,
                "request_info": {
                    "method": method,
                    "url": url,
                    "has_body": bool(body),
                },
            }

        if action == "generate_all":
            all_pocs: dict[str, str] = {}

            for fmt, generator in generators.items():
                try:
                    all_pocs[fmt] = generator(method, url, headers, body, cookies)
                except (TypeError, ValueError) as e:
                    all_pocs[fmt] = f"Error generating {fmt}: {e}"

            return {
                "pocs": all_pocs,
                "formats_generated": list(all_pocs.keys()),
                "vulnerability_type": vulnerability_type,
                "description": description,
                "request_info": {
                    "method": method,
                    "url": url,
                    "has_body": bool(body),
                },
            }

        return {"error": f"Unknown action: {action}"}

    except (TypeError, ValueError) as e:
        return {"error": f"PoC generation failed: {e!s}"}
