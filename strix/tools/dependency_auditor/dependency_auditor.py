"""Dependency Auditor for checking known vulnerabilities in project dependencies."""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


DependencyAction = Literal["audit_package", "audit_file", "check_version", "list_ecosystems"]


# Known vulnerable versions (simplified database - in production, use CVE database)
KNOWN_VULNERABILITIES = {
    "express": {
        "< 4.17.3": {
            "cve": "CVE-2022-24999",
            "severity": "high",
            "description": "Open redirect vulnerability in express",
        },
    },
    "lodash": {
        "< 4.17.21": {
            "cve": "CVE-2021-23337",
            "severity": "high",
            "description": "Command injection in lodash template",
        },
        "< 4.17.12": {
            "cve": "CVE-2019-10744",
            "severity": "critical",
            "description": "Prototype pollution in lodash",
        },
    },
    "django": {
        "< 3.2.13": {
            "cve": "CVE-2022-28346",
            "severity": "high",
            "description": "SQL injection in QuerySet.annotate(),aggregate() and extra()",
        },
        "< 2.2.28": {
            "cve": "CVE-2022-22818",
            "severity": "medium",
            "description": "Possible XSS via {% debug %} template tag",
        },
    },
    "flask": {
        "< 2.0.0": {
            "cve": "CVE-2023-30861",
            "severity": "high",
            "description": "Cookie parsing vulnerability",
        },
    },
    "requests": {
        "< 2.31.0": {
            "cve": "CVE-2023-32681",
            "severity": "medium",
            "description": "Unintended leak of Proxy-Authorization header",
        },
    },
    "pyyaml": {
        "< 6.0": {
            "cve": "CVE-2020-14343",
            "severity": "critical",
            "description": "Arbitrary code execution via unsafe loading",
        },
    },
    "pillow": {
        "< 9.0.0": {
            "cve": "CVE-2022-22817",
            "severity": "high",
            "description": "Buffer overflow in ImagePath.Path",
        },
    },
    "axios": {
        "< 0.21.3": {
            "cve": "CVE-2021-3749",
            "severity": "medium",
            "description": "Server-Side Request Forgery",
        },
    },
    "spring-core": {
        "5.3.0 - 5.3.17": {
            "cve": "CVE-2022-22965",
            "severity": "critical",
            "description": "Spring4Shell RCE vulnerability",
        },
    },
    "log4j-core": {
        "2.0 - 2.16.0": {
            "cve": "CVE-2021-44228",
            "severity": "critical",
            "description": "Log4Shell RCE vulnerability",
        },
    },
}


def _parse_version(version: str) -> tuple[int, ...]:
    """Parse version string into tuple of integers."""
    # Remove common prefixes and clean version
    version = version.lstrip("v^~>=<")
    # Extract numeric parts
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts) if parts else (0,)


def _compare_versions(version: str, constraint: str) -> bool:
    """Compare if version matches constraint."""
    try:
        ver = _parse_version(version)

        # Handle different constraint formats
        if constraint.startswith("< "):
            max_ver = _parse_version(constraint[2:])
            return ver < max_ver
        if constraint.startswith("<= "):
            max_ver = _parse_version(constraint[3:])
            return ver <= max_ver
        if constraint.startswith("> "):
            min_ver = _parse_version(constraint[2:])
            return ver > min_ver
        if constraint.startswith(">= "):
            min_ver = _parse_version(constraint[3:])
            return ver >= min_ver
        if " - " in constraint:
            # Range: "2.0 - 2.16.0"
            min_ver_str, max_ver_str = constraint.split(" - ")
            min_ver = _parse_version(min_ver_str)
            max_ver = _parse_version(max_ver_str)
            return min_ver <= ver <= max_ver
        # Exact match
        return ver == _parse_version(constraint)
    except (ValueError, IndexError):
        return False


def _check_package_vulnerabilities(
    package_name: str,
    version: str,
) -> list[dict[str, Any]]:
    """Check if package version has known vulnerabilities."""
    vulnerabilities: list[dict[str, Any]] = []

    if package_name.lower() not in KNOWN_VULNERABILITIES:
        return vulnerabilities

    package_vulns = KNOWN_VULNERABILITIES[package_name.lower()]

    for constraint, vuln_info in package_vulns.items():
        if _compare_versions(version, constraint):
            vulnerabilities.append({
                "package": package_name,
                "version": version,
                "cve": vuln_info["cve"],
                "severity": vuln_info["severity"],
                "description": vuln_info["description"],
                "affected_versions": constraint,
            })

    return vulnerabilities


def _parse_package_json(content: str) -> list[dict[str, str]]:
    """Parse package.json dependencies."""
    try:
        data = json.loads(content)
        packages = []

        for dep_type in ["dependencies", "devDependencies"]:
            if dep_type in data:
                for name, version in data[dep_type].items():
                    packages.append({
                        "name": name,
                        "version": version.lstrip("^~"),
                        "type": dep_type,
                    })

        return packages
    except (json.JSONDecodeError, KeyError):
        return []


def _parse_requirements_txt(content: str) -> list[dict[str, str]]:
    """Parse requirements.txt dependencies."""
    packages = []
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Parse: package==version or package>=version
        match = re.match(r"([a-zA-Z0-9_-]+)\s*([><=!]+)\s*([0-9.]+)", line)
        if match:
            name, operator, version = match.groups()
            packages.append({
                "name": name,
                "version": version,
                "type": "dependency",
            })

    return packages


def _parse_pom_xml(content: str) -> list[dict[str, str]]:
    """Parse pom.xml dependencies."""
    packages = []
    # Simple regex parsing (in production, use XML parser)
    pattern = r"<dependency>.*?<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>.*?</dependency>"
    matches = re.findall(pattern, content, re.DOTALL)

    for name, version in matches:
        packages.append({
            "name": name.strip(),
            "version": version.strip(),
            "type": "dependency",
        })

    return packages


@register_tool
def dependency_auditor(
    action: DependencyAction,
    package_name: str | None = None,
    version: str | None = None,
    file_content: str | None = None,
    file_type: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Audit project dependencies for known security vulnerabilities.

    This tool checks dependencies against a database of known vulnerabilities
    (CVEs) to identify security issues in project dependencies.

    Args:
        action: The audit action to perform:
            - audit_package: Check a specific package version
            - audit_file: Audit dependencies from a file (package.json, requirements.txt)
            - check_version: Check if a specific version is vulnerable
            - list_ecosystems: List supported package ecosystems
        package_name: Name of the package to audit
        version: Version of the package
        file_content: Content of dependency file to audit
        file_type: Type of file (package.json, requirements.txt, pom.xml)

    Returns:
        Audit results including vulnerabilities found with CVE IDs and severity
    """
    # Define valid parameters and actions
    VALID_PARAMS = {
        "action",
        "package_name",
        "version",
        "file_content",
        "file_type",
    }
    VALID_ACTIONS = ["audit_package", "audit_file", "check_version", "list_ecosystems"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "dependency_auditor")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("dependency_auditor", "audit_package", {"package_name": "express", "version": "4.17.0"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "dependency_auditor")
    if action_error:
        action_error["usage_examples"] = {
            "audit_package": "dependency_auditor(action='audit_package', package_name='express', version='4.17.0')",
            "audit_file": "dependency_auditor(action='audit_file', file_content='...', file_type='package.json')",
            "check_version": "dependency_auditor(action='check_version', package_name='lodash', version='4.17.0')",
            "list_ecosystems": "dependency_auditor(action='list_ecosystems')",
        }
        return action_error

    # Validate required parameters based on action
    if action in ["audit_package", "check_version"]:
        param_error = validate_required_param(package_name, "package_name", action, "dependency_auditor")
        if param_error:
            param_error.update(
                generate_usage_hint("dependency_auditor", action, {"package_name": "express", "version": "4.17.0"})
            )
            return param_error
        param_error = validate_required_param(version, "version", action, "dependency_auditor")
        if param_error:
            param_error.update(
                generate_usage_hint("dependency_auditor", action, {"package_name": "express", "version": "4.17.0"})
            )
            return param_error

    if action == "audit_file":
        param_error = validate_required_param(file_content, "file_content", action, "dependency_auditor")
        if param_error:
            param_error.update(
                generate_usage_hint("dependency_auditor", action, {"file_content": "...", "file_type": "package.json"})
            )
            return param_error
        param_error = validate_required_param(file_type, "file_type", action, "dependency_auditor")
        if param_error:
            param_error.update(
                generate_usage_hint("dependency_auditor", action, {"file_content": "...", "file_type": "package.json"})
            )
            return param_error

    try:
        if action == "list_ecosystems":
            return {
                "ecosystems": [
                    {
                        "name": "npm",
                        "file_types": ["package.json", "package-lock.json"],
                        "description": "Node.js / JavaScript ecosystem",
                    },
                    {
                        "name": "pip",
                        "file_types": ["requirements.txt", "Pipfile"],
                        "description": "Python ecosystem",
                    },
                    {
                        "name": "maven",
                        "file_types": ["pom.xml"],
                        "description": "Java Maven ecosystem",
                    },
                    {
                        "name": "rubygems",
                        "file_types": ["Gemfile"],
                        "description": "Ruby ecosystem",
                    },
                ],
                "tracked_packages": len(KNOWN_VULNERABILITIES),
            }

        if action == "audit_package":
            if not package_name or not version:
                return {
                    "error": "package_name and version required for audit_package action"
                }

            vulnerabilities = _check_package_vulnerabilities(package_name, version)

            return {
                "package": package_name,
                "version": version,
                "vulnerable": len(vulnerabilities) > 0,
                "vulnerabilities": vulnerabilities,
                "vulnerability_count": len(vulnerabilities),
                "recommendations": [
                    f"Upgrade {package_name} to a patched version",
                    "Review the CVE details for each vulnerability",
                    "Test the upgrade in a staging environment",
                    "Check release notes for breaking changes",
                ] if vulnerabilities else [f"{package_name}@{version} has no known vulnerabilities"],
            }

        if action == "check_version":
            if not package_name or not version:
                return {"error": "package_name and version required for check_version action"}

            vulnerabilities = _check_package_vulnerabilities(package_name, version)

            if vulnerabilities:
                return {
                    "package": package_name,
                    "version": version,
                    "status": "vulnerable",
                    "vulnerabilities": vulnerabilities,
                    "count": len(vulnerabilities),
                }

            return {
                "package": package_name,
                "version": version,
                "status": "safe",
                "message": "No known vulnerabilities in this version",
            }

        if action == "audit_file":
            if not file_content:
                return {"error": "file_content required for audit_file action"}

            # Parse file based on type
            packages: list[dict[str, str]] = []
            if file_type == "package.json" or (file_content.strip().startswith("{")):
                packages = _parse_package_json(file_content)
            elif file_type == "requirements.txt":
                packages = _parse_requirements_txt(file_content)
            elif file_type == "pom.xml":
                packages = _parse_pom_xml(file_content)
            else:
                # Try to auto-detect
                if file_content.strip().startswith("{"):
                    packages = _parse_package_json(file_content)
                elif "<project>" in file_content:
                    packages = _parse_pom_xml(file_content)
                else:
                    packages = _parse_requirements_txt(file_content)

            # Check each package
            all_vulnerabilities: list[dict[str, Any]] = []
            for pkg in packages:
                vulns = _check_package_vulnerabilities(pkg["name"], pkg["version"])
                all_vulnerabilities.extend(vulns)

            # Categorize by severity
            critical = [v for v in all_vulnerabilities if v["severity"] == "critical"]
            high = [v for v in all_vulnerabilities if v["severity"] == "high"]
            medium = [v for v in all_vulnerabilities if v["severity"] == "medium"]
            low = [v for v in all_vulnerabilities if v["severity"] == "low"]

            return {
                "total_packages": len(packages),
                "vulnerable_packages": len(
                    {v["package"] for v in all_vulnerabilities}
                ),
                "total_vulnerabilities": len(all_vulnerabilities),
                "vulnerabilities": all_vulnerabilities,
                "summary": {
                    "critical": len(critical),
                    "high": len(high),
                    "medium": len(medium),
                    "low": len(low),
                },
                "recommendations": [
                    "Upgrade all packages with critical vulnerabilities immediately",
                    "Review and plan upgrades for high severity vulnerabilities",
                    "Enable automated dependency scanning in CI/CD",
                    "Use dependency lock files to ensure consistent versions",
                    "Regularly update dependencies to latest secure versions",
                ] if all_vulnerabilities else ["All dependencies are secure"],
            }

        return {"error": f"Unknown action: {action}"}

    except (ValueError, KeyError) as e:
        return {"error": f"Dependency audit failed: {e!s}"}
