"""TCP/UDP port scanning and service detection for network reconnaissance."""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


PortScanAction = Literal["scan_tcp", "scan_udp", "scan_common", "detect_service"]

# Common port definitions
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

TOP_1000_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
    # Additional common ports
    1, 7, 9, 13, 17, 19, 20, 26, 37, 49, 79, 81, 82, 88, 100, 106, 113,
    119, 120, 123, 144, 161, 179, 199, 254, 255, 280, 311, 389, 427, 443,
    444, 465, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 548, 554,
    587, 593, 625, 631, 636, 646, 787, 808, 873, 902, 990, 1000, 1024,
    1025, 1026, 1027, 1028, 1029, 1030, 1110, 1111, 1194, 1214, 1234,
    1241, 1352, 1400, 1434, 1500, 1580, 1583, 1720, 1723, 1755, 1761,
    1801, 1900, 1935, 1998, 2000, 2001, 2002, 2003, 2049, 2103, 2105,
    2107, 2121, 2161, 2301, 2383, 2401, 2601, 2717, 2869, 2967, 3000,
    3001, 3052, 3128, 3260, 3268, 3283, 3372, 3460, 3689, 3690, 4000,
    4001, 4045, 4443, 4444, 4567, 4899, 5000, 5001, 5003, 5009, 5050,
    5051, 5060, 5101, 5190, 5222, 5357, 5500, 5544, 5631, 5632, 5666,
    5800, 5901, 5902, 5984, 5985, 5986, 6000, 6001, 6002, 6004, 6112,
    6443, 6543, 6667, 6789, 7000, 7001, 7002, 7070, 7100, 7199, 7443,
    7777, 7778, 8000, 8001, 8002, 8008, 8009, 8010, 8081, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8181, 8222, 8333,
    8400, 8500, 8800, 8834, 8880, 8888, 8899, 9000, 9001, 9002, 9080,
    9090, 9091, 9100, 9200, 9300, 9418, 9443, 9500, 9900, 9999, 10000,
    10001, 10010, 10443, 11211, 12000, 12345, 15672, 16992, 17988, 18264,
    20000, 20005, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
    49152, 49153, 49154, 49155, 49156, 49157,
]

# Service banners and signatures
SERVICE_SIGNATURES = {
    "SSH": [b"SSH-", b"OpenSSH"],
    "HTTP": [b"HTTP/", b"<!DOCTYPE", b"<html", b"<HTML"],
    "FTP": [b"220 ", b"FTP"],
    "SMTP": [b"220 ", b"ESMTP", b"Postfix"],
    "MySQL": [b"\x00\x00\x00\x0a", b"mysql"],
    "PostgreSQL": [b"FATAL", b"PostgreSQL"],
    "Redis": [b"-ERR", b"+PONG", b"redis"],
    "MongoDB": [b"MongoDB"],
}


async def _scan_tcp_port(host: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
    """Scan a single TCP port."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return {"port": port, "state": "open", "protocol": "tcp"}
    except asyncio.TimeoutError:
        return {"port": port, "state": "filtered", "protocol": "tcp"}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "protocol": "tcp"}
    except OSError:
        return {"port": port, "state": "filtered", "protocol": "tcp"}


async def _scan_udp_port(host: str, port: int, timeout: float = 3.0) -> dict[str, Any]:
    """Scan a single UDP port (less reliable than TCP)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.settimeout(timeout)

        # Send empty UDP packet
        sock.sendto(b"", (host, port))

        try:
            # Try to receive response
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.sock_recv(sock, 1024),
                timeout=timeout,
            )
            sock.close()
            return {"port": port, "state": "open", "protocol": "udp"}
        except asyncio.TimeoutError:
            sock.close()
            # No response could mean open or filtered
            return {"port": port, "state": "open|filtered", "protocol": "udp"}
    except OSError:
        return {"port": port, "state": "closed", "protocol": "udp"}


async def _grab_banner(host: str, port: int, timeout: float = 3.0) -> str | None:
    """Attempt to grab service banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        # Some services send banner immediately
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        except asyncio.TimeoutError:
            # Try sending newline to prompt response
            writer.write(b"\r\n")
            await writer.drain()
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            except asyncio.TimeoutError:
                banner = b""

        writer.close()
        await writer.wait_closed()

        if banner:
            # Try to decode as UTF-8, fallback to raw bytes representation
            try:
                return banner.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                return banner[:100].hex()
        return None
    except Exception:
        return None


def _identify_service(banner: str | None, port: int) -> str:
    """Identify service from banner and port."""
    if banner:
        banner_bytes = banner.encode() if isinstance(banner, str) else banner
        for service, signatures in SERVICE_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in banner_bytes.lower():
                    return service

    # Fallback to port-based identification
    return COMMON_PORTS.get(port, "unknown")


async def _scan_ports_batch(
    host: str,
    ports: list[int],
    protocol: str = "tcp",
    timeout: float = 2.0,
    concurrency: int = 100,
) -> list[dict[str, Any]]:
    """Scan multiple ports concurrently."""
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_with_semaphore(port: int) -> dict[str, Any]:
        async with semaphore:
            if protocol == "tcp":
                return await _scan_tcp_port(host, port, timeout)
            return await _scan_udp_port(host, port, timeout)

    tasks = [scan_with_semaphore(port) for port in ports]
    results = await asyncio.gather(*tasks)
    return list(results)


@register_tool
def port_scanner(
    action: PortScanAction,
    target: str | None = None,
    ports: str | None = None,
    timeout: float = 2.0,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Scan TCP/UDP ports and detect services on target hosts.

    Args:
        action: The scanning action to perform:
            - scan_tcp: TCP port scan
            - scan_udp: UDP port scan (less reliable)
            - scan_common: Scan common ports (top 1000)
            - detect_service: Scan and identify services with banner grabbing
        target: Target host (IP address or hostname)
        ports: Ports to scan (e.g., "22,80,443" or "1-1000" or "22,80,100-200")
        timeout: Connection timeout in seconds (default: 2.0)

    Returns:
        Scan results with open ports and service information
    """
    VALID_PARAMS = {"action", "target", "ports", "timeout"}
    VALID_ACTIONS = ["scan_tcp", "scan_udp", "scan_common", "detect_service"]

    # Validate parameters
    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "port_scanner"):
        unknown_error.update(
            generate_usage_hint("port_scanner", "scan_tcp", {"target": "192.168.1.1", "ports": "22,80,443"})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "port_scanner"):
        action_error["usage_examples"] = {
            "scan_tcp": "port_scanner(action='scan_tcp', target='192.168.1.1', ports='22,80,443')",
            "scan_common": "port_scanner(action='scan_common', target='192.168.1.1')",
            "detect_service": "port_scanner(action='detect_service', target='192.168.1.1', ports='22,80,443')",
        }
        return action_error

    if param_error := validate_required_param(target, "target", action, "port_scanner"):
        param_error.update(
            generate_usage_hint("port_scanner", action, {"target": "192.168.1.1"})
        )
        return param_error

    # Parse ports
    port_list: list[int] = []
    if action == "scan_common":
        port_list = TOP_1000_PORTS[:100]  # Limit to top 100 for speed
    elif ports:
        try:
            for part in ports.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    port_list.extend(range(start, min(end + 1, start + 1000)))  # Limit range
                else:
                    port_list.append(int(part))
        except ValueError:
            return {
                "error": f"Invalid port specification: {ports}",
                "hint": "Use format: '22,80,443' or '1-1000' or '22,80,100-200'",
                "tool_name": "port_scanner",
            }
    else:
        port_list = list(COMMON_PORTS.keys())

    # Limit total ports to prevent excessive scanning
    if len(port_list) > 1000:
        port_list = port_list[:1000]

    # Run the scan
    try:
        if action == "scan_tcp":
            results = asyncio.run(_scan_ports_batch(target, port_list, "tcp", timeout))
            open_ports = [r for r in results if r["state"] == "open"]

            return {
                "action": "scan_tcp",
                "target": target,
                "total_ports_scanned": len(port_list),
                "open_ports": len(open_ports),
                "results": open_ports,
                "common_services": {
                    r["port"]: COMMON_PORTS.get(r["port"], "unknown")
                    for r in open_ports
                },
            }

        elif action == "scan_udp":
            results = asyncio.run(_scan_ports_batch(target, port_list[:50], "udp", timeout))  # Limit UDP
            open_ports = [r for r in results if "open" in r["state"]]

            return {
                "action": "scan_udp",
                "target": target,
                "total_ports_scanned": len(port_list[:50]),
                "results": open_ports,
                "note": "UDP scanning is less reliable - open|filtered means no response received",
            }

        elif action == "scan_common":
            results = asyncio.run(_scan_ports_batch(target, port_list, "tcp", timeout))
            open_ports = [r for r in results if r["state"] == "open"]

            return {
                "action": "scan_common",
                "target": target,
                "total_ports_scanned": len(port_list),
                "open_ports": len(open_ports),
                "results": [
                    {**r, "service": COMMON_PORTS.get(r["port"], "unknown")}
                    for r in open_ports
                ],
            }

        elif action == "detect_service":
            # First scan for open ports
            results = asyncio.run(_scan_ports_batch(target, port_list, "tcp", timeout))
            open_ports = [r for r in results if r["state"] == "open"]

            # Then grab banners for open ports
            service_results = []
            for port_info in open_ports:
                port = port_info["port"]
                banner = asyncio.run(_grab_banner(target, port, timeout))
                service = _identify_service(banner, port)
                service_results.append({
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner[:100] if banner else None,
                })

            return {
                "action": "detect_service",
                "target": target,
                "total_ports_scanned": len(port_list),
                "services_detected": len(service_results),
                "results": service_results,
            }

    except socket.gaierror:
        return {
            "error": f"Could not resolve hostname: {target}",
            "hint": "Verify the target hostname or use an IP address",
            "tool_name": "port_scanner",
        }
    except OSError as e:
        return {
            "error": f"Network error: {e!s}",
            "hint": "Check network connectivity and target accessibility",
            "tool_name": "port_scanner",
        }

    return {"error": "Unknown action", "tool_name": "port_scanner"}
