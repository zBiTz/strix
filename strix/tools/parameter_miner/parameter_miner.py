"""Parameter Miner tool for discovering hidden parameters."""

from __future__ import annotations

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


ParameterMinerAction = Literal["get_wordlist", "analyze_params", "suggest_params", "get_common_params"]


# Common parameter wordlists by category
COMMON_PARAMS: dict[str, list[str]] = {
    "authentication": [
        "username", "user", "login", "email", "password", "passwd", "pass",
        "token", "api_key", "apikey", "api-key", "auth", "authorization",
        "session", "sessionid", "session_id", "jwt", "bearer", "oauth",
        "access_token", "refresh_token", "secret", "key", "credentials",
    ],
    "user_management": [
        "id", "uid", "user_id", "userid", "account", "account_id", "profile",
        "admin", "role", "roles", "permissions", "group", "groups", "level",
        "is_admin", "isAdmin", "is_staff", "is_superuser", "privilege",
    ],
    "pagination": [
        "page", "p", "limit", "count", "size", "per_page", "perPage", "offset",
        "start", "end", "from", "to", "cursor", "after", "before", "skip", "take",
    ],
    "filtering": [
        "filter", "q", "query", "search", "keyword", "keywords", "term",
        "sort", "order", "orderby", "order_by", "sortby", "sort_by", "asc", "desc",
        "fields", "include", "exclude", "where", "condition", "status", "state",
    ],
    "file_operations": [
        "file", "filename", "path", "filepath", "dir", "directory", "folder",
        "upload", "download", "attachment", "document", "image", "photo",
        "url", "uri", "src", "source", "dest", "destination", "location",
    ],
    "debug": [
        "debug", "test", "testing", "dev", "development", "verbose", "trace",
        "log", "logging", "print", "dump", "show", "display", "raw", "internal",
    ],
    "callback": [
        "callback", "redirect", "return", "returnUrl", "return_url", "returnTo",
        "next", "goto", "forward", "continue", "success", "error", "cancel",
        "redirect_uri", "redirect_url", "callback_url", "target", "destination",
    ],
    "format": [
        "format", "type", "content_type", "contentType", "accept", "output",
        "response", "encoding", "charset", "lang", "language", "locale", "version",
    ],
    "injection_targets": [
        "cmd", "command", "exec", "execute", "run", "shell", "system",
        "sql", "query", "table", "column", "database", "db",
        "template", "render", "view", "include", "require", "import",
    ],
    "ssrf_targets": [
        "url", "uri", "host", "hostname", "domain", "server", "ip", "address",
        "proxy", "fetch", "load", "request", "get", "post", "webhook",
        "endpoint", "service", "remote", "external", "link", "href",
    ],
}


def _get_param_wordlist(categories: list[str] | None = None) -> list[str]:
    """Get parameter wordlist for specified categories."""
    if not categories:
        categories = list(COMMON_PARAMS.keys())

    wordlist: set[str] = set()
    for category in categories:
        if category in COMMON_PARAMS:
            wordlist.update(COMMON_PARAMS[category])

    return sorted(wordlist)


def _analyze_existing_params(params: list[str]) -> dict[str, Any]:
    """Analyze existing parameters and suggest related ones."""
    analysis: dict[str, Any] = {
        "detected_categories": [],
        "suggested_params": [],
        "patterns": [],
    }

    # Detect categories based on existing params
    for category, param_list in COMMON_PARAMS.items():
        for param in params:
            if param.lower() in [p.lower() for p in param_list]:
                if category not in analysis["detected_categories"]:
                    analysis["detected_categories"].append(category)
                break

    # Suggest additional params from detected categories
    for category in analysis["detected_categories"]:
        for param in COMMON_PARAMS[category]:
            if param.lower() not in [p.lower() for p in params]:
                analysis["suggested_params"].append({
                    "param": param,
                    "category": category,
                })

    # Detect naming patterns
    patterns: set[str] = set()
    for param in params:
        if "_" in param:
            patterns.add("snake_case")
        if "-" in param:
            patterns.add("kebab-case")
        if param != param.lower() and param != param.upper():
            if param[0].islower():
                patterns.add("camelCase")
            else:
                patterns.add("PascalCase")

    analysis["patterns"] = list(patterns)

    # Generate variations based on patterns
    variations: list[str] = []
    base_params = ["id", "admin", "debug", "token", "callback", "user"]
    for base in base_params:
        if base not in [p.lower() for p in params]:
            if "snake_case" in patterns:
                variations.append(f"{base}_id")
                variations.append(f"is_{base}")
            if "camelCase" in patterns:
                variations.append(f"{base}Id")
                variations.append(f"is{base.capitalize()}")

    analysis["pattern_based_suggestions"] = variations[:20]

    return analysis


def _get_context_params(context: str) -> list[str]:
    """Get parameters relevant to a specific context."""
    context_mappings: dict[str, list[str]] = {
        "api": [
            "api_key", "apiKey", "access_token", "format", "version", "v",
            "callback", "jsonp", "fields", "include", "expand", "limit", "offset",
        ],
        "graphql": [
            "query", "variables", "operationName", "operation", "extensions",
        ],
        "oauth": [
            "client_id", "client_secret", "redirect_uri", "response_type",
            "scope", "state", "code", "grant_type", "code_verifier", "nonce",
        ],
        "file_upload": [
            "file", "upload", "attachment", "filename", "filepath",
            "overwrite", "path", "directory", "type", "size", "chunk",
        ],
        "search": [
            "q", "query", "search", "keyword", "term", "filter",
            "sort", "order", "page", "limit", "offset", "fields",
        ],
        "admin": [
            "admin", "debug", "test", "internal", "bypass", "override",
            "force", "sudo", "root", "superuser", "privilege", "role",
        ],
    }

    return context_mappings.get(context.lower(), [])


@register_tool
def parameter_miner(
    action: ParameterMinerAction,
    categories: list[str] | None = None,
    existing_params: list[str] | None = None,
    context: str | None = None,
    include_variations: bool = True,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Discover hidden and undocumented parameters through analysis.

    This tool provides wordlists and suggestions for parameter discovery,
    helping identify hidden functionality and potential attack vectors.

    Args:
        action: The mining action to perform:
            - get_wordlist: Get parameter wordlist for fuzzing
            - analyze_params: Analyze existing parameters and suggest related ones
            - suggest_params: Get context-aware parameter suggestions
            - get_common_params: Get common parameters by category
        categories: Categories to include (authentication, user_management, etc.)
        existing_params: List of already known parameters
        context: Context for suggestions (api, graphql, oauth, file_upload, search, admin)
        include_variations: Include case and format variations

    Returns:
        Parameter lists, suggestions, and analysis results
    """
    try:
        if action == "get_wordlist":
            wordlist = _get_param_wordlist(categories)

            if include_variations:
                variations: set[str] = set(wordlist)
                for param in wordlist:
                    # Add common variations
                    variations.add(param.lower())
                    variations.add(param.upper())
                    variations.add(param.replace("_", "-"))
                    variations.add(param.replace("-", "_"))
                    if "_" in param:
                        # snake_case to camelCase
                        parts = param.split("_")
                        camel = parts[0] + "".join(p.capitalize() for p in parts[1:])
                        variations.add(camel)
                wordlist = sorted(variations)

            return {
                "wordlist": wordlist,
                "count": len(wordlist),
                "categories_included": categories or list(COMMON_PARAMS.keys()),
            }

        if action == "analyze_params":
            if not existing_params:
                return {"error": "existing_params required for analyze action"}

            analysis = _analyze_existing_params(existing_params)

            return {
                "existing_count": len(existing_params),
                "detected_categories": analysis["detected_categories"],
                "naming_patterns": analysis["patterns"],
                "suggested_params": analysis["suggested_params"][:30],
                "pattern_variations": analysis["pattern_based_suggestions"],
            }

        if action == "suggest_params":
            suggestions: list[dict[str, Any]] = []

            # Context-based suggestions
            if context:
                context_params = _get_context_params(context)
                for param in context_params:
                    suggestions.append({
                        "param": param,
                        "source": f"context:{context}",
                        "priority": "high",
                    })

            # Category-based suggestions
            if categories:
                for category in categories:
                    if category in COMMON_PARAMS:
                        for param in COMMON_PARAMS[category][:10]:
                            if not any(s["param"] == param for s in suggestions):
                                suggestions.append({
                                    "param": param,
                                    "source": f"category:{category}",
                                    "priority": "medium",
                                })

            # Remove already known params
            if existing_params:
                existing_lower = [p.lower() for p in existing_params]
                suggestions = [s for s in suggestions if s["param"].lower() not in existing_lower]

            return {
                "suggestions": suggestions[:50],
                "count": len(suggestions[:50]),
                "context": context,
            }

        if action == "get_common_params":
            if categories:
                result = {cat: COMMON_PARAMS.get(cat, []) for cat in categories}
            else:
                result = COMMON_PARAMS

            return {
                "categories": result,
                "available_categories": list(COMMON_PARAMS.keys()),
            }

        return {"error": f"Unknown action: {action}"}

    except (TypeError, ValueError, KeyError) as e:
        return {"error": f"Parameter mining failed: {e!s}"}
