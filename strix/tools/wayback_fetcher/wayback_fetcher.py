"""Wayback Machine URL fetcher for historical URL discovery."""

from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import urlparse

import requests

from strix.tools.registry import register_tool


WaybackAction = Literal["fetch", "search", "snapshots"]

# Common file type filters
FILE_TYPE_FILTERS = {
    "all": "",
    "js": r"\.js($|\?)",
    "json": r"\.json($|\?)",
    "xml": r"\.xml($|\?)",
    "php": r"\.php($|\?)",
    "asp": r"\.(asp|aspx)($|\?)",
    "jsp": r"\.jsp($|\?)",
    "api": r"/(api|v[0-9]+)/",
    "config": r"(config|settings|\.env)",
    "backup": r"\.(bak|backup|old|orig)",
}


def _normalize_domain(domain: str) -> str:
    """Normalize domain input."""
    domain = domain.lower().strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.netloc or domain
    return domain.split("/")[0]


def _fetch_wayback_urls(
    domain: str,
    file_type: str | None = None,
    limit: int = 1000,
) -> dict[str, Any]:
    """Fetch URLs from Wayback Machine CDX API."""
    base_url = "https://web.archive.org/cdx/search/cdx"

    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original,timestamp,statuscode,mimetype",
        "collapse": "urlkey",
        "limit": limit,
    }

    try:
        response = requests.get(base_url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to fetch from Wayback Machine: {e!s}"}
    except (ValueError, KeyError) as e:
        return {"error": f"Invalid response from Wayback Machine: {e!s}"}

    if not data or len(data) < 2:
        return {
            "domain": domain,
            "urls_found": 0,
            "urls": [],
            "message": "No archived URLs found",
        }

    # First row is headers
    headers = data[0]
    urls = []

    for row in data[1:]:
        url_data = dict(zip(headers, row, strict=False))
        url = url_data.get("original", "")

        # Apply file type filter
        if file_type and file_type in FILE_TYPE_FILTERS:
            pattern = FILE_TYPE_FILTERS[file_type]
            if pattern and not re.search(pattern, url, re.IGNORECASE):
                continue

        urls.append({
            "url": url,
            "timestamp": url_data.get("timestamp", ""),
            "status": url_data.get("statuscode", ""),
            "mime_type": url_data.get("mimetype", ""),
        })

    # Deduplicate by URL
    seen = set()
    unique_urls = []
    for u in urls:
        if u["url"] not in seen:
            seen.add(u["url"])
            unique_urls.append(u)

    return {
        "domain": domain,
        "urls_found": len(unique_urls),
        "file_type_filter": file_type,
        "urls": unique_urls[:limit],
    }


def _search_wayback_pattern(
    domain: str,
    pattern: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Search for specific URL patterns in archived URLs."""
    result = _fetch_wayback_urls(domain, limit=5000)

    if "error" in result:
        return result

    matching_urls = []
    for url_data in result.get("urls", []):
        url = url_data.get("url", "")
        if re.search(pattern, url, re.IGNORECASE):
            matching_urls.append(url_data)

    return {
        "domain": domain,
        "pattern": pattern,
        "matches_found": len(matching_urls),
        "urls": matching_urls[:limit],
    }


def _get_snapshots(
    url: str,
    limit: int = 50,
) -> dict[str, Any]:
    """Get available snapshots for a specific URL."""
    base_url = "https://web.archive.org/cdx/search/cdx"

    params = {
        "url": url,
        "output": "json",
        "fl": "timestamp,original,statuscode,digest",
        "limit": limit,
    }

    try:
        response = requests.get(base_url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to fetch snapshots: {e!s}"}
    except (ValueError, KeyError) as e:
        return {"error": f"Invalid response: {e!s}"}

    if not data or len(data) < 2:
        return {
            "url": url,
            "snapshots_found": 0,
            "snapshots": [],
        }

    headers = data[0]
    snapshots = []

    for row in data[1:]:
        snapshot_data = dict(zip(headers, row, strict=False))
        timestamp = snapshot_data.get("timestamp", "")
        snapshots.append({
            "timestamp": timestamp,
            "archive_url": f"https://web.archive.org/web/{timestamp}/{url}",
            "status": snapshot_data.get("statuscode", ""),
            "digest": snapshot_data.get("digest", ""),
        })

    return {
        "url": url,
        "snapshots_found": len(snapshots),
        "snapshots": snapshots,
    }


@register_tool
def wayback_fetcher(
    action: WaybackAction,
    domain: str | None = None,
    url: str | None = None,
    file_type: str | None = None,
    pattern: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Fetch historical URLs from the Wayback Machine.

    This tool queries the Internet Archive's Wayback Machine to discover
    historical URLs, old endpoints, removed functionality, and archived
    versions of web pages.

    Args:
        action: The action to perform:
            - fetch: Get archived URLs for a domain
            - search: Search for URLs matching a pattern
            - snapshots: Get available snapshots for a specific URL
        domain: Target domain to fetch URLs for (for fetch/search)
        url: Specific URL to get snapshots for (for snapshots action)
        file_type: Filter by file type (js, json, xml, php, asp, jsp, api, config, backup)
        pattern: Regex pattern to search for (for search action)
        limit: Maximum number of results to return (default: 100)

    Returns:
        Discovered URLs, snapshots, and metadata from the Wayback Machine
    """
    try:
        if action == "fetch":
            if not domain:
                return {"error": "domain parameter required for fetch action"}

            normalized_domain = _normalize_domain(domain)
            return _fetch_wayback_urls(normalized_domain, file_type, limit)

        if action == "search":
            if not domain:
                return {"error": "domain parameter required for search action"}
            if not pattern:
                return {"error": "pattern parameter required for search action"}

            normalized_domain = _normalize_domain(domain)
            return _search_wayback_pattern(normalized_domain, pattern, limit)

        if action == "snapshots":
            if not url:
                return {"error": "url parameter required for snapshots action"}

            return _get_snapshots(url, limit)

        return {"error": f"Unknown action: {action}"}

    except (ValueError, re.error) as e:
        return {"error": f"Wayback fetcher failed: {e!s}"}
