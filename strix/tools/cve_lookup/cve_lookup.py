"""CVE database lookup tool for vulnerability research."""

from __future__ import annotations

import re
from typing import Any, Literal

from strix.tools.registry import register_tool


CVEAction = Literal["lookup", "search", "by_product"]


# Sample CVE patterns and data structure
# In production, this would query actual NVD API
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def _parse_cve_id(cve_id: str) -> str | None:
    """Parse and validate CVE ID format."""
    cve_id = cve_id.upper().strip()
    if CVE_PATTERN.match(cve_id):
        return cve_id
    return None


def _search_nvd_database(query: str) -> list[dict[str, Any]]:
    """Search NVD database (simulated - would use real API in production)."""
    # This is a placeholder. Real implementation would:
    # 1. Query NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
    # 2. Parse response
    # 3. Return results
    
    results = []
    
    # Sample data for common vulnerabilities
    sample_cves = {
        "CVE-2021-44228": {
            "id": "CVE-2021-44228",
            "description": "Apache Log4j2 Remote Code Execution (Log4Shell)",
            "cvss_v3": 10.0,
            "severity": "CRITICAL",
            "published": "2021-12-10",
            "products": ["Apache Log4j", "log4j-core"],
            "versions_affected": ["2.0-beta9 to 2.14.1"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://logging.apache.org/log4j/2.x/security.html"
            ],
            "exploit_available": True,
            "exploit_maturity": "Functional"
        },
        "CVE-2014-0160": {
            "id": "CVE-2014-0160",
            "description": "Heartbleed - OpenSSL TLS heartbeat information disclosure",
            "cvss_v2": 5.0,
            "cvss_v3": 7.5,
            "severity": "HIGH",
            "published": "2014-04-07",
            "products": ["OpenSSL"],
            "versions_affected": ["1.0.1 through 1.0.1f", "1.0.2-beta through 1.0.2-beta1"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
                "http://heartbleed.com/"
            ],
            "exploit_available": True,
            "exploit_maturity": "Functional"
        }
    }
    
    # Simple search simulation
    query_lower = query.lower()
    for cve_id, data in sample_cves.items():
        if (query_lower in cve_id.lower() or
            query_lower in data.get("description", "").lower() or
            any(query_lower in prod.lower() for prod in data.get("products", []))):
            results.append(data)
    
    return results


def _get_cpe_matches(product: str, version: str | None = None) -> list[dict[str, Any]]:
    """Get CPE matches for product and version (simulated)."""
    # CPE (Common Platform Enumeration) matching
    # Real implementation would query NVD CPE match feed
    
    matches = []
    product_lower = product.lower()
    
    # Sample CPE matching logic
    if "log4j" in product_lower:
        matches.append({
            "cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
            "cve": "CVE-2021-44228",
            "version_start": "2.0",
            "version_end": "2.14.1"
        })
    
    if "openssl" in product_lower:
        matches.append({
            "cpe": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "cve": "CVE-2014-0160",
            "version_start": "1.0.1",
            "version_end": "1.0.1f"
        })
    
    # Filter by version if provided
    if version and matches:
        # Version comparison logic would go here
        pass
    
    return matches


@register_tool
def cve_lookup(
    action: CVEAction,
    cve_id: str | None = None,
    query: str | None = None,
    product: str | None = None,
    version: str | None = None
) -> dict[str, Any]:
    """Query CVE databases and match vulnerabilities against technologies.
    
    This tool looks up Common Vulnerabilities and Exposures (CVE) information from
    the National Vulnerability Database (NVD) and other sources. It can search for
    specific CVEs, search by keywords, or match products against known vulnerabilities.
    
    Args:
        action: The lookup action to perform:
            - lookup: Look up specific CVE by ID
            - search: Search CVEs by keyword
            - by_product: Find CVEs for a specific product/version
        cve_id: CVE ID to look up (e.g., "CVE-2021-44228") for lookup action
        query: Search query for keywords (for search action)
        product: Product name for CPE matching (for by_product action)
        version: Optional product version for more specific matching
    
    Returns:
        CVE information including description, CVSS scores, affected versions,
        exploit availability, and references
    
    Example:
        # Look up specific CVE:
        cve_lookup(action="lookup", cve_id="CVE-2021-44228")
        
        # Search for vulnerabilities:
        cve_lookup(action="search", query="log4j")
        
        # Find CVEs by product:
        cve_lookup(action="by_product", product="Apache Log4j", version="2.14.0")
    """
    try:
        if action == "lookup":
            if not cve_id:
                return {"error": "cve_id parameter required for lookup action"}
            
            parsed_cve = _parse_cve_id(cve_id)
            if not parsed_cve:
                return {"error": f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNN"}
            
            # Search for the specific CVE
            results = _search_nvd_database(parsed_cve)
            
            if not results:
                return {
                    "cve_id": parsed_cve,
                    "found": False,
                    "message": "CVE not found in database. This may be a recently published CVE.",
                    "suggestions": [
                        "Check NVD directly: https://nvd.nist.gov/vuln/detail/" + parsed_cve,
                        "Verify CVE ID is correct",
                        "Search MITRE CVE list: https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + parsed_cve
                    ]
                }
            
            return {
                "cve_id": parsed_cve,
                "found": True,
                "data": results[0],
                "recommendations": [
                    "Verify if this version is in use in your environment",
                    "Check for available patches or mitigations",
                    "Review exploit availability and prioritize accordingly",
                    "Consult vendor security advisories for specific guidance"
                ]
            }
        
        if action == "search":
            if not query:
                return {"error": "query parameter required for search action"}
            
            results = _search_nvd_database(query)
            
            return {
                "query": query,
                "total_results": len(results),
                "results": results,
                "note": "This is a simulated search. Production version would query actual NVD API.",
                "next_steps": [
                    "Review each CVE for applicability to your environment",
                    "Check CVSS scores to prioritize high-severity issues",
                    "Verify affected versions match your deployment",
                    "Look for exploit availability indicators"
                ]
            }
        
        if action == "by_product":
            if not product:
                return {"error": "product parameter required for by_product action"}
            
            # Get CPE matches
            cpe_matches = _get_cpe_matches(product, version)
            
            if not cpe_matches:
                return {
                    "product": product,
                    "version": version,
                    "matches": [],
                    "message": "No known vulnerabilities found for this product.",
                    "recommendations": [
                        "Verify product name spelling and format",
                        "Check vendor security advisories directly",
                        "Consider searching with alternative product names",
                        "This may be a secure version or newly released product"
                    ]
                }
            
            # Get CVE details for each match
            cve_details = []
            for match in cpe_matches:
                cve_results = _search_nvd_database(match["cve"])
                if cve_results:
                    cve_data = cve_results[0]
                    cve_data["cpe_match"] = match
                    cve_details.append(cve_data)
            
            return {
                "product": product,
                "version": version,
                "total_vulnerabilities": len(cve_details),
                "vulnerabilities": cve_details,
                "summary": {
                    "critical": len([c for c in cve_details if c.get("severity") == "CRITICAL"]),
                    "high": len([c for c in cve_details if c.get("severity") == "HIGH"]),
                    "with_exploits": len([c for c in cve_details if c.get("exploit_available")])
                },
                "recommendations": [
                    "Prioritize CRITICAL and HIGH severity vulnerabilities",
                    "Address CVEs with known exploits immediately",
                    "Update to patched versions where available",
                    "Implement compensating controls if patches unavailable"
                ]
            }
        
        return {"error": f"Unknown action: {action}"}
    
    except (KeyError, ValueError, TypeError) as e:
        return {
            "error": f"CVE lookup failed: {e!s}",
            "help": "Valid actions: lookup (with cve_id), search (with query), by_product (with product)"
        }
