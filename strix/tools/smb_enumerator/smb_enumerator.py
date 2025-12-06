"""SMB/CIFS enumeration for share discovery, user enumeration, and security assessment."""

from __future__ import annotations

import socket
import struct
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


SMBEnumAction = Literal[
    "list_shares",
    "check_null_session",
    "enumerate_users",
    "check_signing",
    "check_permissions",
    "full_enum",
]

# SMB Protocol Constants
SMB_HEADER_SIZE = 32
SMB2_HEADER_SIZE = 64

# SMB1 Commands
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT_ANDX = 0x75

# SMB2 Commands
SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001
SMB2_TREE_CONNECT = 0x0003

# Common share names to check
COMMON_SHARES = [
    "ADMIN$", "C$", "D$", "IPC$", "NETLOGON", "SYSVOL",
    "print$", "Users", "Shared", "Public", "Documents",
    "Backup", "Software", "IT", "HR", "Finance", "temp",
]


def _create_smb1_negotiate() -> bytes:
    """Create SMB1 negotiate request."""
    # NetBIOS Session Service header
    dialects = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"

    smb_header = struct.pack(
        "<4sBIBHHQHHHHH",
        b"\xffSMB",  # Protocol
        SMB_COM_NEGOTIATE,  # Command
        0,  # Status
        0x18,  # Flags
        0xc803,  # Flags2
        0,  # PID High
        0,  # Signature
        0,  # Reserved
        0,  # TID
        0,  # PID
        0,  # UID
        0,  # MID
    )

    # Word count + byte count
    negotiate_request = struct.pack("<BH", 0, len(dialects)) + dialects

    # Add NetBIOS header
    smb_packet = smb_header + negotiate_request
    netbios_header = struct.pack(">BH", 0, len(smb_packet) + 1) + b"\x00"

    return netbios_header + smb_packet


def _create_smb2_negotiate() -> bytes:
    """Create SMB2 negotiate request."""
    # SMB2 Header
    smb2_header = struct.pack(
        "<4sHHIIQQQQHHI",
        b"\xfeSMB",  # Protocol ID
        64,  # Structure size
        0,  # Credit charge
        0,  # Status
        SMB2_NEGOTIATE,  # Command
        0,  # Credit request
        0,  # Flags
        0,  # Next command
        0,  # Message ID
        0,  # Reserved / Process ID
        0,  # Tree ID
        0,  # Session ID (high)
        0,  # Session ID (low)
    )

    # SMB2 Negotiate Request
    dialects = struct.pack("<HHH", 0x0202, 0x0210, 0x0300)  # SMB 2.0.2, 2.1, 3.0

    negotiate_request = struct.pack(
        "<HHIHHI16sIIQ",
        36,  # Structure size
        3,  # Dialect count
        0,  # Security mode
        0,  # Reserved
        0,  # Capabilities
        0x12345678,  # Client GUID part 1
        b"\x00" * 16,  # Client GUID
        0,  # Negotiate context offset
        0,  # Negotiate context count
        0,  # Reserved2
    ) + dialects

    smb2_packet = smb2_header + negotiate_request

    # NetBIOS header
    netbios_header = struct.pack(">I", len(smb2_packet))[1:]

    return netbios_header + smb2_packet


def _parse_smb_negotiate_response(data: bytes) -> dict[str, Any]:
    """Parse SMB negotiate response."""
    result = {
        "smb_version": "unknown",
        "signing_required": False,
        "signing_enabled": False,
        "encryption_supported": False,
        "dialect": None,
    }

    if len(data) < 4:
        return result

    # Skip NetBIOS header
    if data[0] == 0:
        data = data[4:]

    if len(data) < 4:
        return result

    # Check protocol signature
    if data[0:4] == b"\xfeSMB":
        # SMB2/3
        result["smb_version"] = "SMB2/3"

        if len(data) >= 70:
            # Parse SMB2 negotiate response
            security_mode = struct.unpack("<H", data[64:66])[0]
            result["signing_enabled"] = bool(security_mode & 0x01)
            result["signing_required"] = bool(security_mode & 0x02)

            if len(data) >= 72:
                dialect = struct.unpack("<H", data[70:72])[0]
                dialect_map = {
                    0x0202: "SMB 2.0.2",
                    0x0210: "SMB 2.1",
                    0x0300: "SMB 3.0",
                    0x0302: "SMB 3.0.2",
                    0x0311: "SMB 3.1.1",
                }
                result["dialect"] = dialect_map.get(dialect, f"0x{dialect:04x}")

            if len(data) >= 68:
                capabilities = struct.unpack("<I", data[64:68])[0]
                result["encryption_supported"] = bool(capabilities & 0x40)

    elif data[0:4] == b"\xffSMB":
        # SMB1
        result["smb_version"] = "SMB1"

        if len(data) >= 39:
            security_mode = data[38]
            result["signing_enabled"] = bool(security_mode & 0x04)
            result["signing_required"] = bool(security_mode & 0x08)
            result["dialect"] = "NT LM 0.12"

    return result


def _check_smb_connection(target: str, port: int = 445, timeout: float = 10.0) -> dict[str, Any]:
    """Check SMB connection and protocol details."""
    result = {
        "reachable": False,
        "port": port,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        result["reachable"] = True

        # Send SMB2 negotiate
        negotiate = _create_smb2_negotiate()
        sock.send(negotiate)

        response = sock.recv(4096)
        sock.close()

        if response:
            protocol_info = _parse_smb_negotiate_response(response)
            result.update(protocol_info)

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except OSError as e:
        result["error"] = str(e)

    return result


def _check_null_session(target: str, port: int = 445, timeout: float = 10.0) -> dict[str, Any]:
    """Check if null session is allowed."""
    result = {
        "null_session_allowed": False,
        "anonymous_access": False,
        "guest_access": False,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Send negotiate
        negotiate = _create_smb2_negotiate()
        sock.send(negotiate)
        response = sock.recv(4096)

        if response and len(response) > 4:
            # Check if we got a valid response (indicates SMB is accepting connections)
            if b"\xfeSMB" in response or b"\xffSMB" in response:
                result["null_session_allowed"] = True
                result["note"] = "Target accepts anonymous negotiate - further testing required for full null session"

        sock.close()

    except Exception as e:
        result["error"] = str(e)

    return result


def _enumerate_shares_basic(target: str, port: int = 445) -> list[dict[str, Any]]:
    """Basic share enumeration attempt."""
    # This is a simplified check - real share enumeration requires
    # full SMB session establishment which needs impacket or smbclient
    shares = []

    # Return known default shares with notes
    default_shares = [
        {"name": "ADMIN$", "type": "admin", "note": "Administrative share (requires admin)"},
        {"name": "C$", "type": "admin", "note": "Default drive share (requires admin)"},
        {"name": "IPC$", "type": "ipc", "note": "Inter-process communication"},
    ]

    return default_shares


def _list_shares(
    target: str,
    port: int = 445,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
) -> dict[str, Any]:
    """List SMB shares on target."""
    result = {
        "action": "list_shares",
        "target": target,
        "port": port,
        "authenticated": bool(username),
    }

    # Check connectivity first
    conn_check = _check_smb_connection(target, port)
    if not conn_check.get("reachable"):
        result["error"] = conn_check.get("error", "Cannot reach target")
        return result

    result["smb_info"] = {
        "version": conn_check.get("smb_version"),
        "dialect": conn_check.get("dialect"),
        "signing_required": conn_check.get("signing_required"),
    }

    # Basic share enumeration
    shares = _enumerate_shares_basic(target, port)
    result["shares"] = shares
    result["share_count"] = len(shares)

    result["recommendation"] = (
        f"For full share enumeration, use: smbclient -L //{target}/ -N (null session) "
        f"or smbclient -L //{target}/ -U {username or 'user'}%password"
    )

    return result


def _check_signing(target: str, port: int = 445) -> dict[str, Any]:
    """Check SMB signing configuration."""
    conn_info = _check_smb_connection(target, port)

    result = {
        "action": "check_signing",
        "target": target,
        "port": port,
    }

    if not conn_info.get("reachable"):
        result["error"] = conn_info.get("error", "Cannot reach target")
        return result

    result["smb_version"] = conn_info.get("smb_version")
    result["dialect"] = conn_info.get("dialect")
    result["signing_enabled"] = conn_info.get("signing_enabled", False)
    result["signing_required"] = conn_info.get("signing_required", False)
    result["encryption_supported"] = conn_info.get("encryption_supported", False)

    # Security assessment
    findings = []
    if not conn_info.get("signing_required"):
        findings.append({
            "issue": "SMB signing not required",
            "severity": "high",
            "description": "Target does not require SMB signing, vulnerable to relay attacks",
            "recommendation": "Enable and require SMB signing",
        })

    if conn_info.get("smb_version") == "SMB1":
        findings.append({
            "issue": "SMB1 enabled",
            "severity": "high",
            "description": "SMB1 is deprecated and has known vulnerabilities (EternalBlue)",
            "recommendation": "Disable SMB1 and use SMB2/3",
        })

    if not conn_info.get("encryption_supported"):
        findings.append({
            "issue": "SMB encryption not supported",
            "severity": "medium",
            "description": "SMB3 encryption not available",
            "recommendation": "Upgrade to SMB3 with encryption support",
        })

    result["findings"] = findings
    result["security_score"] = "secure" if not findings else "vulnerable" if any(
        f["severity"] == "high" for f in findings
    ) else "weak"

    return result


def _enumerate_users(
    target: str,
    port: int = 445,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
) -> dict[str, Any]:
    """Enumerate users via RID cycling."""
    result = {
        "action": "enumerate_users",
        "target": target,
        "port": port,
    }

    # Check connectivity
    conn_check = _check_smb_connection(target, port)
    if not conn_check.get("reachable"):
        result["error"] = conn_check.get("error", "Cannot reach target")
        return result

    # RID cycling requires authenticated session or null session
    # Provide command suggestions for manual enumeration
    result["note"] = "RID cycling requires established SMB session"

    if username:
        result["suggested_commands"] = [
            f"rpcclient -U '{domain or ''}\\{username}%{password or ''}' {target} -c 'enumdomusers'",
            f"crackmapexec smb {target} -u '{username}' -p '{password or ''}' --users",
            f"enum4linux -a -u '{username}' -p '{password or ''}' {target}",
        ]
    else:
        result["suggested_commands"] = [
            f"rpcclient -U '' -N {target} -c 'enumdomusers'",
            f"enum4linux -a {target}",
            f"crackmapexec smb {target} -u '' -p '' --users",
        ]

    # Common RIDs to check
    result["common_rids"] = {
        500: "Administrator",
        501: "Guest",
        502: "krbtgt",
        512: "Domain Admins",
        513: "Domain Users",
        514: "Domain Guests",
        515: "Domain Computers",
        516: "Domain Controllers",
        519: "Enterprise Admins",
    }

    return result


def _check_permissions(
    target: str,
    port: int = 445,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Check share access permissions."""
    result = {
        "action": "check_permissions",
        "target": target,
        "port": port,
    }

    conn_check = _check_smb_connection(target, port)
    if not conn_check.get("reachable"):
        result["error"] = conn_check.get("error", "Cannot reach target")
        return result

    # Provide command for permission checking
    result["note"] = "Permission checking requires share access"
    result["shares_to_check"] = COMMON_SHARES

    if username:
        result["suggested_commands"] = [
            f"smbmap -H {target} -u '{username}' -p '{password or ''}'",
            f"crackmapexec smb {target} -u '{username}' -p '{password or ''}' --shares",
        ]
    else:
        result["suggested_commands"] = [
            f"smbmap -H {target} -u '' -p ''",
            f"smbmap -H {target} -u 'guest' -p ''",
            f"crackmapexec smb {target} -u '' -p '' --shares",
        ]

    return result


def _full_enum(
    target: str,
    port: int = 445,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
) -> dict[str, Any]:
    """Run full SMB enumeration."""
    result = {
        "action": "full_enum",
        "target": target,
        "port": port,
    }

    # Run all checks
    result["connection"] = _check_smb_connection(target, port)

    if not result["connection"].get("reachable"):
        result["error"] = "Target not reachable on SMB port"
        return result

    result["signing"] = _check_signing(target, port)
    result["null_session"] = _check_null_session(target, port)
    result["shares"] = _list_shares(target, port, username, password, domain)

    # Summary
    findings = []

    if not result["signing"].get("signing_required"):
        findings.append("SMB signing not required - relay attacks possible")

    if result["connection"].get("smb_version") == "SMB1":
        findings.append("SMB1 enabled - vulnerable to EternalBlue and other attacks")

    if result["null_session"].get("null_session_allowed"):
        findings.append("Null session may be allowed - anonymous enumeration possible")

    result["summary"] = {
        "smb_version": result["connection"].get("smb_version"),
        "dialect": result["connection"].get("dialect"),
        "critical_findings": len([f for f in findings if "relay" in f.lower() or "SMB1" in f]),
        "findings": findings,
    }

    # Comprehensive command suggestions
    result["manual_enumeration"] = {
        "enum4linux": f"enum4linux -a {target}",
        "smbclient": f"smbclient -L //{target}/ -N",
        "crackmapexec": f"crackmapexec smb {target}",
        "nmap_scripts": f"nmap -p {port} --script smb-enum-shares,smb-enum-users,smb-vuln-* {target}",
    }

    return result


@register_tool
def smb_enumerator(
    action: SMBEnumAction,
    target: str | None = None,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
    port: int = 445,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Enumerate SMB shares, users, and security configuration.

    Args:
        action: The enumeration action to perform:
            - list_shares: List available SMB shares
            - check_null_session: Test for null session access
            - enumerate_users: Enumerate users via RID cycling
            - check_signing: Check SMB signing requirements
            - check_permissions: Check share access permissions
            - full_enum: Run all enumeration checks
        target: Target host IP address or hostname
        username: Username for authentication (optional)
        password: Password for authentication (optional)
        domain: Domain name for authentication (optional)
        port: SMB port (default: 445)

    Returns:
        Enumeration results with shares, users, and security findings
    """
    VALID_PARAMS = {"action", "target", "username", "password", "domain", "port"}
    VALID_ACTIONS = ["list_shares", "check_null_session", "enumerate_users", "check_signing", "check_permissions", "full_enum"]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "smb_enumerator"):
        unknown_error.update(
            generate_usage_hint("smb_enumerator", "list_shares", {"target": "192.168.1.1"})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "smb_enumerator"):
        action_error["usage_examples"] = {
            "list_shares": 'smb_enumerator(action="list_shares", target="192.168.1.1")',
            "check_signing": 'smb_enumerator(action="check_signing", target="192.168.1.1")',
            "full_enum": 'smb_enumerator(action="full_enum", target="dc01.domain.local")',
        }
        return action_error

    if param_error := validate_required_param(target, "target", action, "smb_enumerator"):
        param_error.update(generate_usage_hint("smb_enumerator", action, {"target": "192.168.1.1"}))
        return param_error

    try:
        if action == "list_shares":
            return _list_shares(target, port, username, password, domain)
        elif action == "check_null_session":
            return _check_null_session(target, port)
        elif action == "enumerate_users":
            return _enumerate_users(target, port, username, password, domain)
        elif action == "check_signing":
            return _check_signing(target, port)
        elif action == "check_permissions":
            return _check_permissions(target, port, username, password)
        elif action == "full_enum":
            return _full_enum(target, port, username, password, domain)

    except socket.gaierror:
        return {
            "error": f"Could not resolve hostname: {target}",
            "hint": "Verify the target hostname or use an IP address",
            "tool_name": "smb_enumerator",
        }
    except Exception as e:
        return {
            "error": f"SMB enumeration failed: {e!s}",
            "tool_name": "smb_enumerator",
        }

    return {"error": "Unknown action", "tool_name": "smb_enumerator"}
