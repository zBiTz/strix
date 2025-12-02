"""Tech Fingerprinter tool for identifying technologies and frameworks."""

from __future__ import annotations

import re
from typing import Any, Literal

from strix.tools.registry import register_tool


TechFingerprinterAction = Literal["analyze_headers", "analyze_body", "full_analysis", "identify_framework"]


# Technology signatures
HEADER_SIGNATURES: dict[str, dict[str, Any]] = {
    "server": {
        "nginx": {"name": "Nginx", "type": "web_server"},
        "apache": {"name": "Apache", "type": "web_server"},
        "iis": {"name": "Microsoft IIS", "type": "web_server"},
        "cloudflare": {"name": "Cloudflare", "type": "cdn"},
        "kestrel": {"name": "Kestrel (.NET)", "type": "web_server"},
        "gunicorn": {"name": "Gunicorn (Python)", "type": "web_server"},
        "uvicorn": {"name": "Uvicorn (Python)", "type": "web_server"},
        "openresty": {"name": "OpenResty", "type": "web_server"},
        "litespeed": {"name": "LiteSpeed", "type": "web_server"},
        "vercel": {"name": "Vercel", "type": "platform"},
    },
    "x-powered-by": {
        "php": {"name": "PHP", "type": "language"},
        "asp.net": {"name": "ASP.NET", "type": "framework"},
        "express": {"name": "Express.js", "type": "framework"},
        "next.js": {"name": "Next.js", "type": "framework"},
        "nuxt": {"name": "Nuxt.js", "type": "framework"},
    },
}

COOKIE_SIGNATURES: dict[str, dict[str, Any]] = {
    "phpsessid": {"name": "PHP", "type": "language"},
    "jsessionid": {"name": "Java (Servlet)", "type": "language"},
    "asp.net_sessionid": {"name": "ASP.NET", "type": "framework"},
    "aspsessionid": {"name": "Classic ASP", "type": "framework"},
    "laravel_session": {"name": "Laravel", "type": "framework"},
    "django": {"name": "Django", "type": "framework"},
    "rack.session": {"name": "Ruby (Rack)", "type": "framework"},
    "_rails": {"name": "Ruby on Rails", "type": "framework"},
    "connect.sid": {"name": "Express.js", "type": "framework"},
    "next-auth": {"name": "NextAuth.js", "type": "library"},
    "cf_": {"name": "Cloudflare", "type": "cdn"},
}

BODY_SIGNATURES: dict[str, dict[str, Any]] = {
    r"wp-content|wp-includes|wordpress": {"name": "WordPress", "type": "cms"},
    r"drupal|sites/default": {"name": "Drupal", "type": "cms"},
    r"joomla": {"name": "Joomla", "type": "cms"},
    r"__next|_next/static": {"name": "Next.js", "type": "framework"},
    r"__nuxt|_nuxt/": {"name": "Nuxt.js", "type": "framework"},
    r"ng-version|angular": {"name": "Angular", "type": "framework"},
    r"data-reactroot|react": {"name": "React", "type": "library"},
    r"data-v-[a-f0-9]|vue": {"name": "Vue.js", "type": "library"},
    r"ember-view|ember": {"name": "Ember.js", "type": "framework"},
    r"__sveltekit|svelte": {"name": "Svelte/SvelteKit", "type": "framework"},
    r"laravel|csrf-token.*laravel": {"name": "Laravel", "type": "framework"},
    r"rails|csrf-token.*rails": {"name": "Ruby on Rails", "type": "framework"},
    r"django|csrfmiddlewaretoken": {"name": "Django", "type": "framework"},
    r"flask": {"name": "Flask", "type": "framework"},
    r"spring|springframework": {"name": "Spring Framework", "type": "framework"},
    r"struts": {"name": "Apache Struts", "type": "framework"},
    r"graphql|__schema": {"name": "GraphQL", "type": "api"},
    r"swagger|openapi|api-docs": {"name": "OpenAPI/Swagger", "type": "api"},
}

ERROR_SIGNATURES: dict[str, dict[str, Any]] = {
    r"traceback.*python|django|flask": {"name": "Python", "type": "language"},
    r"at .*\.java|\.jsp": {"name": "Java", "type": "language"},
    r"\.php on line|parse error": {"name": "PHP", "type": "language"},
    r"\.rb:|ruby": {"name": "Ruby", "type": "language"},
    r"\.cs:|\.aspx|asp\.net": {"name": "ASP.NET", "type": "framework"},
    r"node_modules|at Module\._compile": {"name": "Node.js", "type": "runtime"},
    r"prisma|@prisma/client": {"name": "Prisma", "type": "orm"},
    r"sequelize": {"name": "Sequelize", "type": "orm"},
    r"typeorm": {"name": "TypeORM", "type": "orm"},
    r"mongoose|mongodb": {"name": "MongoDB", "type": "database"},
    r"postgresql|psycopg": {"name": "PostgreSQL", "type": "database"},
    r"mysql|mariadb": {"name": "MySQL/MariaDB", "type": "database"},
}


def _analyze_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Analyze HTTP headers for technology signatures."""
    detected: list[dict[str, Any]] = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check known header signatures
    for header_name, signatures in HEADER_SIGNATURES.items():
        if header_name in headers_lower:
            value = headers_lower[header_name].lower()
            for sig_pattern, tech_info in signatures.items():
                if sig_pattern in value:
                    detected.append({
                        **tech_info,
                        "source": f"header:{header_name}",
                        "value": headers_lower[header_name],
                        "confidence": "high",
                    })

    # Check for version information
    for header, value in headers_lower.items():
        # Version patterns
        version_match = re.search(r"(\d+\.[\d.]+)", value)
        if version_match and any(tech in value.lower() for tech in ["php", "nginx", "apache"]):
            for item in detected:
                if any(tech in item.get("name", "").lower() for tech in ["php", "nginx", "apache"]):
                    item["version"] = version_match.group(1)

    # Check cookies for signatures
    if "set-cookie" in headers_lower:
        cookies = headers_lower["set-cookie"].lower()
        for sig_pattern, tech_info in COOKIE_SIGNATURES.items():
            if sig_pattern.lower() in cookies:
                detected.append({
                    **tech_info,
                    "source": "cookie",
                    "confidence": "high",
                })

    # Check for security headers that indicate technologies
    security_indicators = {
        "x-aspnet-version": {"name": "ASP.NET", "type": "framework"},
        "x-aspnetmvc-version": {"name": "ASP.NET MVC", "type": "framework"},
        "x-drupal-cache": {"name": "Drupal", "type": "cms"},
        "x-generator": {"name": "CMS/Generator", "type": "cms"},
        "x-powered-cms": {"name": "CMS", "type": "cms"},
        "x-vercel-id": {"name": "Vercel", "type": "platform"},
        "x-amz-": {"name": "AWS", "type": "cloud"},
        "x-goog-": {"name": "Google Cloud", "type": "cloud"},
        "x-azure-": {"name": "Azure", "type": "cloud"},
    }

    for header_prefix, tech_info in security_indicators.items():
        for header in headers_lower:
            if header.startswith(header_prefix):
                detected.append({
                    **tech_info,
                    "source": f"header:{header}",
                    "value": headers_lower[header],
                    "confidence": "high",
                })
                break

    return detected


def _analyze_body(body: str) -> list[dict[str, Any]]:
    """Analyze response body for technology signatures."""
    detected: list[dict[str, Any]] = []

    for pattern, tech_info in BODY_SIGNATURES.items():
        if re.search(pattern, body, re.IGNORECASE):
            detected.append({
                **tech_info,
                "source": "body",
                "confidence": "medium",
            })

    # Check for error messages revealing technologies
    for pattern, tech_info in ERROR_SIGNATURES.items():
        if re.search(pattern, body, re.IGNORECASE):
            detected.append({
                **tech_info,
                "source": "error_message",
                "confidence": "high",
            })

    # Check for meta generator tag
    generator_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.IGNORECASE)
    if generator_match:
        detected.append({
            "name": generator_match.group(1),
            "type": "cms/generator",
            "source": "meta_generator",
            "confidence": "high",
        })

    # Check for JavaScript library versions
    js_libs = [
        (r"jquery[.-]?([\d.]+)?\.(?:min\.)?js", "jQuery"),
        (r"bootstrap[.-]?([\d.]+)?\.(?:min\.)?js", "Bootstrap"),
        (r"react[.-]?([\d.]+)?\.(?:min\.)?js", "React"),
        (r"vue[.-]?([\d.]+)?\.(?:min\.)?js", "Vue.js"),
        (r"angular[.-]?([\d.]+)?\.(?:min\.)?js", "Angular"),
    ]

    for pattern, lib_name in js_libs:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex and match.group(1) else "unknown"
            detected.append({
                "name": lib_name,
                "type": "javascript_library",
                "version": version,
                "source": "script_reference",
                "confidence": "high",
            })

    return detected


def _deduplicate_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate technology detections."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []

    for item in results:
        key = f"{item['name']}:{item['type']}"
        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique


@register_tool
def tech_fingerprinter(
    action: TechFingerprinterAction,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    url: str | None = None,
) -> dict[str, Any]:
    """Identify technologies, frameworks, and versions from HTTP responses.

    This tool analyzes HTTP response headers and body content to identify
    the technology stack, frameworks, and versions in use.

    Args:
        action: The fingerprinting action to perform:
            - analyze_headers: Analyze HTTP headers only
            - analyze_body: Analyze response body only
            - full_analysis: Complete analysis of headers and body
            - identify_framework: Focus on framework identification
        headers: HTTP response headers as a dictionary
        body: HTTP response body content
        url: URL being analyzed (for context)

    Returns:
        Detected technologies with confidence levels and sources
    """
    try:
        detected: list[dict[str, Any]] = []

        if action == "analyze_headers":
            if not headers:
                return {"error": "headers parameter required"}
            detected = _analyze_headers(headers)

        elif action == "analyze_body":
            if not body:
                return {"error": "body parameter required"}
            detected = _analyze_body(body)

        elif action == "full_analysis":
            if headers:
                detected.extend(_analyze_headers(headers))
            if body:
                detected.extend(_analyze_body(body))

            if not headers and not body:
                return {"error": "headers and/or body required"}

        elif action == "identify_framework":
            if headers:
                header_results = _analyze_headers(headers)
                detected.extend([r for r in header_results if r["type"] == "framework"])
            if body:
                body_results = _analyze_body(body)
                detected.extend([r for r in body_results if r["type"] == "framework"])

            if not headers and not body:
                return {"error": "headers and/or body required"}

        else:
            return {"error": f"Unknown action: {action}"}

        # Deduplicate results
        detected = _deduplicate_results(detected)

        # Sort by confidence
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        detected.sort(key=lambda x: confidence_order.get(x.get("confidence", "low"), 3))

        # Group by type
        by_type: dict[str, list[dict[str, Any]]] = {}
        for tech in detected:
            tech_type = tech.get("type", "unknown")
            if tech_type not in by_type:
                by_type[tech_type] = []
            by_type[tech_type].append(tech)

        return {
            "technologies": detected,
            "count": len(detected),
            "by_type": by_type,
            "url": url,
            "summary": [f"{t['name']} ({t['type']})" for t in detected[:10]],
        }

    except (TypeError, ValueError, KeyError) as e:
        return {"error": f"Fingerprinting failed: {e!s}"}
