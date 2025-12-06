"""Service version detection through banner grabbing and fingerprinting."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


ServiceVersionAction = Literal[
    "grab_banner",
    "detect_version",
    "fingerprint_http",
    "check_vulnerabilities",
    "full_scan",
]

# Service detection patterns
SERVICE_PATTERNS = {
    "ssh": {
        "patterns": [
            (r"SSH-(\d+\.\d+)-OpenSSH[_-](\d+\.\d+(?:p\d+)?)", "OpenSSH"),
            (r"SSH-(\d+\.\d+)-dropbear[_-]?(\d+\.\d+)?", "Dropbear SSH"),
            (r"SSH-(\d+\.\d+)-libssh[_-]?(\d+\.\d+\.\d+)?", "libssh"),
            (r"SSH-(\d+\.\d+)-([^\s]+)", "Generic SSH"),
        ],
        "probes": [b""],  # SSH sends banner immediately
    },
    "http": {
        "patterns": [
            (r"Server:\s*Apache/(\d+\.\d+(?:\.\d+)?)", "Apache"),
            (r"Server:\s*nginx/(\d+\.\d+(?:\.\d+)?)", "nginx"),
            (r"Server:\s*Microsoft-IIS/(\d+\.\d+)", "Microsoft IIS"),
            (r"Server:\s*LiteSpeed", "LiteSpeed"),
            (r"Server:\s*cloudflare", "Cloudflare"),
            (r"X-Powered-By:\s*PHP/(\d+\.\d+(?:\.\d+)?)", "PHP"),
            (r"X-Powered-By:\s*ASP\.NET", "ASP.NET"),
            (r"X-AspNet-Version:\s*(\d+\.\d+(?:\.\d+)?)", "ASP.NET"),
        ],
        "probes": [b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"],
    },
    "ftp": {
        "patterns": [
            (r"220[- ].*vsftpd[_ ](\d+\.\d+\.\d+)", "vsftpd"),
            (r"220[- ].*ProFTPD[_ ](\d+\.\d+\.\d+)", "ProFTPD"),
            (r"220[- ].*Pure-FTPd", "Pure-FTPd"),
            (r"220[- ].*FileZilla Server[_ ](\d+\.\d+\.\d+)", "FileZilla Server"),
            (r"220[- ].*Microsoft FTP Service", "Microsoft FTP"),
        ],
        "probes": [b""],
    },
    "smtp": {
        "patterns": [
            (r"220[- ].*Postfix", "Postfix"),
            (r"220[- ].*Sendmail[/ ](\d+\.\d+\.\d+)", "Sendmail"),
            (r"220[- ].*Exim[_ ](\d+\.\d+)", "Exim"),
            (r"220[- ].*Microsoft ESMTP MAIL Service", "Microsoft Exchange"),
        ],
        "probes": [b""],
    },
    "mysql": {
        "patterns": [
            (r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB"),
            (r"(\d+\.\d+\.\d+(?:-\w+)?)", "MySQL"),
        ],
        "probes": [b""],
    },
    "postgresql": {
        "patterns": [
            (r"PostgreSQL (\d+\.\d+(?:\.\d+)?)", "PostgreSQL"),
        ],
        "probes": [b"\x00\x00\x00\x08\x04\xd2\x16\x2f"],  # SSL request
    },
    "redis": {
        "patterns": [
            (r"redis_version:(\d+\.\d+\.\d+)", "Redis"),
        ],
        "probes": [b"INFO\r\n"],
    },
    "mongodb": {
        "patterns": [
            (r'"version"\s*:\s*"(\d+\.\d+\.\d+)"', "MongoDB"),
        ],
        "probes": [b""],
    },
    "telnet": {
        "patterns": [
            (r"Linux\s+(\d+\.\d+\.\d+-\S+)", "Linux Telnet"),
            (r"FreeBSD[/ ](\d+\.\d+)", "FreeBSD Telnet"),
        ],
        "probes": [b""],
    },
}

# Known vulnerable versions (simplified database)
VULNERABLE_VERSIONS = {
    "OpenSSH": [
        {"version_range": "<7.0", "cve": "CVE-2016-0777", "severity": "high", "description": "Roaming buffer overflow"},
        {"version_range": "<8.3", "cve": "CVE-2020-15778", "severity": "medium", "description": "SCP command injection"},
        {"version_range": "<9.3", "cve": "CVE-2023-38408", "severity": "high", "description": "Remote code execution via PKCS#11"},
    ],
    "Apache": [
        {"version_range": "<2.4.50", "cve": "CVE-2021-41773", "severity": "critical", "description": "Path traversal and RCE"},
        {"version_range": "<2.4.52", "cve": "CVE-2021-44790", "severity": "critical", "description": "mod_lua buffer overflow"},
        {"version_range": "<2.4.55", "cve": "CVE-2022-37436", "severity": "medium", "description": "mod_proxy_ajp smuggling"},
    ],
    "nginx": [
        {"version_range": "<1.16.1", "cve": "CVE-2019-9516", "severity": "high", "description": "HTTP/2 DoS"},
        {"version_range": "<1.17.3", "cve": "CVE-2019-9511", "severity": "medium", "description": "HTTP/2 resource consumption"},
    ],
    "vsftpd": [
        {"version_range": "=2.3.4", "cve": "CVE-2011-2523", "severity": "critical", "description": "Backdoor command execution"},
    ],
    "ProFTPD": [
        {"version_range": "<1.3.5a", "cve": "CVE-2015-3306", "severity": "critical", "description": "mod_copy arbitrary file access"},
        {"version_range": "<1.3.6", "cve": "CVE-2019-12815", "severity": "high", "description": "mod_copy file overwrite"},
    ],
    "MySQL": [
        {"version_range": "<5.7.31", "cve": "CVE-2020-14812", "severity": "medium", "description": "Optimizer DoS"},
        {"version_range": "<8.0.21", "cve": "CVE-2020-14765", "severity": "medium", "description": "FTS DoS"},
    ],
    "MariaDB": [
        {"version_range": "<10.5.8", "cve": "CVE-2020-28912", "severity": "medium", "description": "wsrep security bypass"},
    ],
    "PostgreSQL": [
        {"version_range": "<12.3", "cve": "CVE-2020-14350", "severity": "high", "description": "Arbitrary SQL execution"},
        {"version_range": "<13.8", "cve": "CVE-2022-2625", "severity": "high", "description": "Extension script replacement"},
    ],
    "Redis": [
        {"version_range": "<5.0.10", "cve": "CVE-2020-14147", "severity": "high", "description": "Integer overflow"},
        {"version_range": "<6.0.5", "cve": "CVE-2021-29477", "severity": "medium", "description": "Integer overflow in STRALGO"},
        {"version_range": "<7.0.0", "cve": "CVE-2022-24736", "severity": "medium", "description": "Lua script heap overflow"},
    ],
    "PHP": [
        {"version_range": "<7.4.28", "cve": "CVE-2022-31625", "severity": "high", "description": "Use after free in pdo"},
        {"version_range": "<8.0.16", "cve": "CVE-2022-31626", "severity": "high", "description": "Buffer overflow in mysqlnd"},
        {"version_range": "<8.1.0", "cve": "CVE-2024-4577", "severity": "critical", "description": "CGI argument injection (Windows)"},
    ],
    "Microsoft IIS": [
        {"version_range": "<10.0", "cve": "CVE-2017-7269", "severity": "critical", "description": "WebDAV buffer overflow"},
    ],
}

# HTTP fingerprinting headers
HTTP_FINGERPRINT_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via",
    "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection",
    "Strict-Transport-Security", "Content-Security-Policy",
]


def _parse_version(version_str: str) -> tuple:
    """Parse version string into comparable tuple."""
    match = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version_str)
    if match:
        return tuple(int(x) if x else 0 for x in match.groups())
    return (0, 0, 0)


def _version_matches_range(version: str, version_range: str) -> bool:
    """Check if version matches a version range specification."""
    version_tuple = _parse_version(version)

    if version_range.startswith("<"):
        target = _parse_version(version_range[1:])
        return version_tuple < target
    elif version_range.startswith("<="):
        target = _parse_version(version_range[2:])
        return version_tuple <= target
    elif version_range.startswith(">"):
        target = _parse_version(version_range[1:])
        return version_tuple > target
    elif version_range.startswith(">="):
        target = _parse_version(version_range[2:])
        return version_tuple >= target
    elif version_range.startswith("="):
        target = _parse_version(version_range[1:])
        return version_tuple == target

    return False


async def _grab_banner_async(host: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    """Grab banner from a service asynchronously."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        # Try to receive initial banner
        banner = b""
        try:
            banner = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        except asyncio.TimeoutError:
            pass

        # If no immediate banner, try sending probes
        if not banner:
            # Determine likely service by port
            probes = SERVICE_PATTERNS.get("http", {}).get("probes", [b""])
            if port in [22, 2222]:
                probes = SERVICE_PATTERNS.get("ssh", {}).get("probes", [b""])
            elif port in [21]:
                probes = SERVICE_PATTERNS.get("ftp", {}).get("probes", [b""])
            elif port in [25, 587, 465]:
                probes = SERVICE_PATTERNS.get("smtp", {}).get("probes", [b""])
            elif port in [6379]:
                probes = SERVICE_PATTERNS.get("redis", {}).get("probes", [b"INFO\r\n"])

            for probe in probes:
                if probe:
                    writer.write(probe)
                    await writer.drain()
                    try:
                        banner = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                        if banner:
                            break
                    except asyncio.TimeoutError:
                        continue

        writer.close()
        await writer.wait_closed()

        if banner:
            try:
                decoded = banner.decode("utf-8", errors="replace").strip()
            except Exception:
                decoded = banner[:200].hex()

            return {
                "success": True,
                "banner": decoded[:500],
                "raw_length": len(banner),
            }

        return {"success": True, "banner": None, "note": "No banner received"}

    except asyncio.TimeoutError:
        return {"success": False, "error": "Connection timed out"}
    except ConnectionRefusedError:
        return {"success": False, "error": "Connection refused"}
    except OSError as e:
        return {"success": False, "error": str(e)}


def _detect_service_version(banner: str, port: int) -> dict[str, Any]:
    """Detect service type and version from banner."""
    result = {
        "service": "unknown",
        "product": None,
        "version": None,
        "extra_info": [],
    }

    if not banner:
        return result

    # Try to identify service based on port hints first
    services_to_check = list(SERVICE_PATTERNS.keys())
    port_hints = {
        22: ["ssh"], 2222: ["ssh"],
        21: ["ftp"],
        25: ["smtp"], 465: ["smtp"], 587: ["smtp"],
        80: ["http"], 443: ["http"], 8080: ["http"], 8443: ["http"],
        3306: ["mysql"],
        5432: ["postgresql"],
        6379: ["redis"],
        27017: ["mongodb"],
        23: ["telnet"],
    }

    if port in port_hints:
        services_to_check = port_hints[port] + [s for s in services_to_check if s not in port_hints[port]]

    for service in services_to_check:
        patterns = SERVICE_PATTERNS.get(service, {}).get("patterns", [])
        for pattern, product_name in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                result["service"] = service
                result["product"] = product_name
                if match.groups():
                    # Get the last non-None group as version
                    version = next((g for g in reversed(match.groups()) if g), None)
                    result["version"] = version
                return result

    # Generic detection fallbacks
    if "SSH-" in banner:
        result["service"] = "ssh"
    elif "HTTP/" in banner or "Server:" in banner:
        result["service"] = "http"
    elif "220" in banner and ("FTP" in banner.upper() or "ready" in banner.lower()):
        result["service"] = "ftp"
    elif "220" in banner and ("SMTP" in banner.upper() or "ESMTP" in banner.upper()):
        result["service"] = "smtp"

    return result


async def _fingerprint_http_async(host: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    """Fingerprint HTTP server and detect frameworks."""
    results = {
        "server": None,
        "technologies": [],
        "headers": {},
        "security_headers": {},
        "cookies": [],
    }

    use_ssl = port in [443, 8443]

    try:
        if use_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_context),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )

        # Send HTTP request
        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        writer.close()
        await writer.wait_closed()

        response_text = response.decode("utf-8", errors="replace")
        lines = response_text.split("\r\n")

        # Parse headers
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                if key.lower() == "server":
                    results["server"] = value
                    # Extract version info
                    for service_patterns in SERVICE_PATTERNS["http"]["patterns"]:
                        pattern, product = service_patterns
                        match = re.search(pattern.replace("Server:\\s*", ""), value, re.IGNORECASE)
                        if match:
                            results["technologies"].append({
                                "name": product,
                                "version": match.group(1) if match.groups() else None,
                            })

                elif key.lower() == "x-powered-by":
                    results["technologies"].append({
                        "name": value.split("/")[0],
                        "version": value.split("/")[1] if "/" in value else None,
                        "header": "X-Powered-By",
                    })

                elif key.lower() in ["x-aspnet-version", "x-aspnetmvc-version"]:
                    results["technologies"].append({
                        "name": "ASP.NET",
                        "version": value,
                        "header": key,
                    })

                elif key.lower() == "set-cookie":
                    results["cookies"].append(value[:100])

                # Security headers
                security_headers = [
                    "x-frame-options", "x-content-type-options", "x-xss-protection",
                    "strict-transport-security", "content-security-policy",
                    "x-permitted-cross-domain-policies", "referrer-policy",
                ]
                if key.lower() in security_headers:
                    results["security_headers"][key] = value

                # Store interesting headers
                if key in HTTP_FINGERPRINT_HEADERS:
                    results["headers"][key] = value

        # Framework detection from cookies and headers
        cookie_str = " ".join(results["cookies"])
        if "PHPSESSID" in cookie_str:
            if not any(t["name"] == "PHP" for t in results["technologies"]):
                results["technologies"].append({"name": "PHP", "source": "cookie"})
        if "JSESSIONID" in cookie_str:
            results["technologies"].append({"name": "Java", "source": "cookie"})
        if "ASP.NET_SessionId" in cookie_str:
            if not any(t["name"] == "ASP.NET" for t in results["technologies"]):
                results["technologies"].append({"name": "ASP.NET", "source": "cookie"})
        if "csrftoken" in cookie_str.lower():
            results["technologies"].append({"name": "Django (likely)", "source": "cookie"})
        if "_rails_" in cookie_str.lower():
            results["technologies"].append({"name": "Ruby on Rails", "source": "cookie"})

        # Missing security headers check
        expected_security = ["x-frame-options", "x-content-type-options", "strict-transport-security"]
        results["missing_security_headers"] = [
            h for h in expected_security if h not in [k.lower() for k in results["security_headers"]]
        ]

        return {"success": True, **results}

    except Exception as e:
        return {"success": False, "error": str(e)}


def _check_vulnerabilities(product: str, version: str) -> list[dict[str, Any]]:
    """Check version against known vulnerabilities."""
    vulnerabilities = []

    if not product or not version:
        return vulnerabilities

    vuln_list = VULNERABLE_VERSIONS.get(product, [])
    for vuln in vuln_list:
        if _version_matches_range(version, vuln["version_range"]):
            vulnerabilities.append({
                "cve": vuln["cve"],
                "severity": vuln["severity"],
                "description": vuln["description"],
                "affected_range": vuln["version_range"],
            })

    return vulnerabilities


@register_tool
def service_version_detector(
    action: ServiceVersionAction,
    target: str | None = None,
    port: int | None = None,
    ports: str | None = None,
    timeout: float = 5.0,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Detect service versions through banner grabbing and fingerprinting.

    Args:
        action: The detection action to perform:
            - grab_banner: Grab service banner from a port
            - detect_version: Identify service version from banner
            - fingerprint_http: Fingerprint HTTP server and frameworks
            - check_vulnerabilities: Check version against known CVEs
            - full_scan: Complete version detection and vulnerability check
        target: Target host IP address or hostname
        port: Target port number (required for most actions)
        ports: Multiple ports for full_scan (comma-separated)
        timeout: Connection timeout in seconds (default: 5.0)

    Returns:
        Service version information, fingerprints, and vulnerabilities
    """
    VALID_PARAMS = {"action", "target", "port", "ports", "timeout"}
    VALID_ACTIONS = ["grab_banner", "detect_version", "fingerprint_http", "check_vulnerabilities", "full_scan"]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "service_version_detector"):
        unknown_error.update(
            generate_usage_hint("service_version_detector", "grab_banner", {"target": "192.168.1.1", "port": 22})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "service_version_detector"):
        action_error["usage_examples"] = {
            "grab_banner": 'service_version_detector(action="grab_banner", target="192.168.1.1", port=22)',
            "fingerprint_http": 'service_version_detector(action="fingerprint_http", target="example.com", port=443)',
            "full_scan": 'service_version_detector(action="full_scan", target="192.168.1.1", ports="22,80,443")',
        }
        return action_error

    if param_error := validate_required_param(target, "target", action, "service_version_detector"):
        param_error.update(generate_usage_hint("service_version_detector", action, {"target": "192.168.1.1"}))
        return param_error

    try:
        if action == "grab_banner":
            if port is None:
                return {
                    "error": "port parameter required for grab_banner action",
                    "hint": "Specify the port to scan",
                    "tool_name": "service_version_detector",
                }

            result = asyncio.run(_grab_banner_async(target, port, timeout))
            return {
                "action": "grab_banner",
                "target": target,
                "port": port,
                **result,
            }

        elif action == "detect_version":
            if port is None:
                return {
                    "error": "port parameter required for detect_version action",
                    "hint": "Specify the port to scan",
                    "tool_name": "service_version_detector",
                }

            banner_result = asyncio.run(_grab_banner_async(target, port, timeout))
            if not banner_result.get("success"):
                return {
                    "action": "detect_version",
                    "target": target,
                    "port": port,
                    "error": banner_result.get("error", "Could not grab banner"),
                }

            version_info = _detect_service_version(banner_result.get("banner", ""), port)
            return {
                "action": "detect_version",
                "target": target,
                "port": port,
                "banner": banner_result.get("banner", "")[:200],
                **version_info,
            }

        elif action == "fingerprint_http":
            if port is None:
                port = 80  # Default to HTTP

            result = asyncio.run(_fingerprint_http_async(target, port, timeout))
            return {
                "action": "fingerprint_http",
                "target": target,
                "port": port,
                **result,
            }

        elif action == "check_vulnerabilities":
            if port is None:
                return {
                    "error": "port parameter required for check_vulnerabilities action",
                    "hint": "Specify the port to scan",
                    "tool_name": "service_version_detector",
                }

            # First detect version
            banner_result = asyncio.run(_grab_banner_async(target, port, timeout))
            if not banner_result.get("success") or not banner_result.get("banner"):
                return {
                    "action": "check_vulnerabilities",
                    "target": target,
                    "port": port,
                    "error": "Could not grab banner for version detection",
                }

            version_info = _detect_service_version(banner_result.get("banner", ""), port)

            # Check for vulnerabilities
            vulns = _check_vulnerabilities(version_info.get("product"), version_info.get("version"))

            return {
                "action": "check_vulnerabilities",
                "target": target,
                "port": port,
                "service": version_info.get("service"),
                "product": version_info.get("product"),
                "version": version_info.get("version"),
                "vulnerabilities": vulns,
                "vulnerability_count": len(vulns),
                "critical_count": len([v for v in vulns if v["severity"] == "critical"]),
                "high_count": len([v for v in vulns if v["severity"] == "high"]),
            }

        elif action == "full_scan":
            port_list = []
            if ports:
                try:
                    port_list = [int(p.strip()) for p in ports.split(",")]
                except ValueError:
                    return {
                        "error": f"Invalid ports specification: {ports}",
                        "hint": "Use comma-separated port numbers: '22,80,443'",
                        "tool_name": "service_version_detector",
                    }
            elif port:
                port_list = [port]
            else:
                port_list = [22, 80, 443]  # Default ports

            results = []
            total_vulns = 0

            for p in port_list[:20]:  # Limit to 20 ports
                banner_result = asyncio.run(_grab_banner_async(target, p, timeout))

                if not banner_result.get("success"):
                    results.append({
                        "port": p,
                        "state": "filtered" if "timeout" in banner_result.get("error", "").lower() else "closed",
                    })
                    continue

                version_info = _detect_service_version(banner_result.get("banner", ""), p)

                # HTTP fingerprinting for web ports
                http_info = None
                if p in [80, 443, 8080, 8443] or version_info.get("service") == "http":
                    http_result = asyncio.run(_fingerprint_http_async(target, p, timeout))
                    if http_result.get("success"):
                        http_info = {
                            "server": http_result.get("server"),
                            "technologies": http_result.get("technologies", []),
                            "missing_security_headers": http_result.get("missing_security_headers", []),
                        }

                # Check vulnerabilities
                vulns = _check_vulnerabilities(version_info.get("product"), version_info.get("version"))
                total_vulns += len(vulns)

                results.append({
                    "port": p,
                    "state": "open",
                    "banner": banner_result.get("banner", "")[:100],
                    "service": version_info.get("service"),
                    "product": version_info.get("product"),
                    "version": version_info.get("version"),
                    "http_fingerprint": http_info,
                    "vulnerabilities": vulns if vulns else None,
                })

            return {
                "action": "full_scan",
                "target": target,
                "ports_scanned": len(port_list),
                "open_ports": len([r for r in results if r.get("state") == "open"]),
                "total_vulnerabilities": total_vulns,
                "results": results,
            }

    except socket.gaierror:
        return {
            "error": f"Could not resolve hostname: {target}",
            "hint": "Verify the target hostname or use an IP address",
            "tool_name": "service_version_detector",
        }
    except Exception as e:
        return {
            "error": f"Scan failed: {e!s}",
            "tool_name": "service_version_detector",
        }

    return {"error": "Unknown action", "tool_name": "service_version_detector"}
