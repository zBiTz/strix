"""Google dork query builder for security reconnaissance."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import quote_plus, urlparse

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


DorkAction = Literal["generate", "build_query", "list_templates"]

# Pre-defined dork templates for security testing
DORK_TEMPLATES = {
    "sensitive_files": [
        "site:{domain} ext:env",
        "site:{domain} ext:log",
        "site:{domain} ext:sql",
        "site:{domain} ext:bak",
        "site:{domain} ext:old",
        "site:{domain} ext:backup",
        "site:{domain} ext:conf",
        "site:{domain} ext:config",
        "site:{domain} filetype:xml",
        "site:{domain} filetype:json",
    ],
    "exposed_documents": [
        "site:{domain} filetype:pdf",
        "site:{domain} filetype:doc",
        "site:{domain} filetype:docx",
        "site:{domain} filetype:xls",
        "site:{domain} filetype:xlsx",
        "site:{domain} filetype:ppt",
        "site:{domain} filetype:pptx",
    ],
    "login_pages": [
        "site:{domain} inurl:login",
        "site:{domain} inurl:signin",
        "site:{domain} inurl:admin",
        "site:{domain} inurl:dashboard",
        "site:{domain} inurl:portal",
        'site:{domain} intitle:"login"',
        'site:{domain} intitle:"sign in"',
    ],
    "error_pages": [
        'site:{domain} "error" OR "exception"',
        'site:{domain} "stack trace"',
        'site:{domain} "Warning:" filetype:php',
        'site:{domain} "Fatal error"',
        'site:{domain} "mysql_" OR "mysqli_"',
        'site:{domain} "ORA-" OR "Oracle error"',
    ],
    "exposed_directories": [
        'site:{domain} intitle:"index of"',
        'site:{domain} intitle:"directory listing"',
        'site:{domain} "parent directory"',
        "site:{domain} inurl:/backup/",
        "site:{domain} inurl:/admin/",
        "site:{domain} inurl:/config/",
    ],
    "git_exposure": [
        "site:{domain} inurl:.git",
        'site:{domain} ".git/config"',
        'site:{domain} ".gitignore"',
        'site:{domain} inurl:".git/HEAD"',
    ],
    "credentials": [
        'site:{domain} "password" filetype:log',
        'site:{domain} "username" "password" filetype:txt',
        'site:{domain} "api_key" OR "apikey"',
        'site:{domain} "secret_key" OR "secretkey"',
        'site:{domain} "access_token"',
        'site:{domain} "private_key"',
    ],
    "api_endpoints": [
        "site:{domain} inurl:api",
        "site:{domain} inurl:/v1/ OR inurl:/v2/",
        "site:{domain} filetype:json inurl:api",
        'site:{domain} "swagger" OR "openapi"',
        "site:{domain} inurl:graphql",
    ],
    "wordpress": [
        "site:{domain} inurl:wp-content",
        "site:{domain} inurl:wp-admin",
        "site:{domain} inurl:wp-includes",
        'site:{domain} "powered by WordPress"',
        "site:{domain} inurl:xmlrpc.php",
    ],
    "cloud_storage": [
        'site:s3.amazonaws.com "{domain}"',
        'site:blob.core.windows.net "{domain}"',
        'site:storage.googleapis.com "{domain}"',
        'site:digitaloceanspaces.com "{domain}"',
    ],
    "subdomains": [
        "site:*.{domain}",
        "site:{domain} -www",
    ],
    "technology_detection": [
        'site:{domain} "powered by"',
        'site:{domain} "running on"',
        'site:{domain} "built with"',
        "site:{domain} ext:aspx",
        "site:{domain} ext:php",
        "site:{domain} ext:jsp",
    ],
}

# Dork operators explanation
DORK_OPERATORS = {
    "site:": "Limit results to a specific domain",
    "inurl:": "Search for keyword in URL",
    "intitle:": "Search for keyword in page title",
    "filetype:": "Search for specific file type",
    "ext:": "Same as filetype",
    "intext:": "Search for keyword in page body",
    "cache:": "Show cached version of page",
    "link:": "Find pages linking to URL",
    "related:": "Find similar sites",
    "info:": "Get information about a URL",
    "define:": "Get definitions",
    "OR": "Boolean OR operator",
    "AND": "Boolean AND operator (implicit)",
    "-": "Exclude keyword",
    '"..."': "Exact phrase match",
    "*": "Wildcard for unknown words",
    "..": "Number range (e.g., 1..100)",
}


def _normalize_domain(domain: str) -> str:
    """Normalize domain input."""
    domain = domain.lower().strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.netloc or domain
    domain = domain.split("/")[0].split(":")[0]

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def _generate_dorks(
    domain: str,
    categories: list[str] | None = None,
) -> dict[str, Any]:
    """Generate Google dork queries for a domain."""
    domain = _normalize_domain(domain)

    if categories is None:
        categories = list(DORK_TEMPLATES.keys())

    all_dorks: dict[str, list[dict[str, str]]] = {}

    for category in categories:
        if category not in DORK_TEMPLATES:
            continue

        dorks = []
        for template in DORK_TEMPLATES[category]:
            query = template.format(domain=domain)
            encoded = quote_plus(query)
            search_url = f"https://www.google.com/search?q={encoded}"

            dorks.append({
                "query": query,
                "search_url": search_url,
            })

        all_dorks[category] = dorks

    total_dorks = sum(len(d) for d in all_dorks.values())

    return {
        "domain": domain,
        "total_dorks": total_dorks,
        "categories_included": list(all_dorks.keys()),
        "dorks": all_dorks,
    }


def _build_custom_query(
    domain: str | None = None,
    keywords: list[str] | None = None,
    file_types: list[str] | None = None,
    inurl: list[str] | None = None,
    intitle: list[str] | None = None,
    exclude: list[str] | None = None,
) -> dict[str, Any]:
    """Build a custom Google dork query."""
    parts = []

    if domain:
        domain = _normalize_domain(domain)
        parts.append(f"site:{domain}")

    if keywords:
        for kw in keywords:
            if " " in kw:
                parts.append(f'"{kw}"')
            else:
                parts.append(kw)

    if file_types:
        if len(file_types) == 1:
            parts.append(f"filetype:{file_types[0]}")
        else:
            ft_parts = " OR ".join(f"filetype:{ft}" for ft in file_types)
            parts.append(f"({ft_parts})")

    if inurl:
        for url_part in inurl:
            parts.append(f"inurl:{url_part}")

    if intitle:
        for title_part in intitle:
            parts.append(f'intitle:"{title_part}"')

    if exclude:
        for ex in exclude:
            parts.append(f"-{ex}")

    query = " ".join(parts)
    encoded = quote_plus(query)
    search_url = f"https://www.google.com/search?q={encoded}"

    return {
        "query": query,
        "search_url": search_url,
        "components": {
            "domain": domain,
            "keywords": keywords,
            "file_types": file_types,
            "inurl": inurl,
            "intitle": intitle,
            "exclude": exclude,
        },
    }


def _list_templates() -> dict[str, Any]:
    """List available dork templates and operators."""
    template_info = {}
    for category, templates in DORK_TEMPLATES.items():
        template_info[category] = {
            "count": len(templates),
            "description": category.replace("_", " ").title(),
            "sample": templates[0] if templates else "",
        }

    return {
        "categories": template_info,
        "total_templates": sum(len(t) for t in DORK_TEMPLATES.values()),
        "operators": DORK_OPERATORS,
    }


@register_tool
def google_dorker(
    action: DorkAction,
    domain: str | None = None,
    categories: list[str] | None = None,
    keywords: list[str] | None = None,
    file_types: list[str] | None = None,
    inurl: list[str] | None = None,
    intitle: list[str] | None = None,
    exclude: list[str] | None = None,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Generate Google dork queries for security reconnaissance.

    This tool creates specialized Google search queries to discover
    exposed files, directories, credentials, error pages, and other
    security-relevant information indexed by search engines.

    Args:
        action: The action to perform:
            - generate: Generate dorks from predefined templates
            - build_query: Build a custom dork query
            - list_templates: List available dork templates
        domain: Target domain for dork queries
        categories: Specific categories to include (for generate)
        keywords: Search keywords (for build_query)
        file_types: File types to search for (for build_query)
        inurl: URL patterns to search for (for build_query)
        intitle: Title patterns to search for (for build_query)
        exclude: Keywords to exclude (for build_query)

    Returns:
        Generated dork queries with search URLs
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "domain", "categories", "keywords", "file_types", "inurl", "intitle", "exclude"}
    VALID_ACTIONS = ["generate", "build_query", "list_templates"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "google_dorker")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "google_dorker",
                "generate",
                {"domain": "example.com"},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "google_dorker")
    if action_error:
        action_error["usage_examples"] = {
            "generate": "google_dorker(action='generate', domain='example.com')",
            "build_query": "google_dorker(action='build_query', domain='example.com', keywords=['api', 'key'])",
            "list_templates": "google_dorker(action='list_templates')",
        }
        return action_error

    # Validate required parameters based on action
    if action == "generate":
        domain_error = validate_required_param(domain, "domain", action, "google_dorker")
        if domain_error:
            domain_error.update(
                generate_usage_hint(
                    "google_dorker",
                    action,
                    {"domain": "example.com"},
                )
            )
            return domain_error

    try:
        if action == "generate":
            if not domain:
                return {"error": "domain parameter required for generate action"}

            return _generate_dorks(domain, categories)

        if action == "build_query":
            return _build_custom_query(
                domain=domain,
                keywords=keywords,
                file_types=file_types,
                inurl=inurl,
                intitle=intitle,
                exclude=exclude,
            )

        if action == "list_templates":
            return _list_templates()

        return {"error": f"Unknown action: {action}"}

    except (ValueError, KeyError) as e:
        return {"error": f"Dork generation failed: {e!s}"}
