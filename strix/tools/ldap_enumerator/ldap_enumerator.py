"""LDAP enumeration for Active Directory reconnaissance and user/group discovery."""

from __future__ import annotations

import socket
import ssl
import struct
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


LDAPEnumAction = Literal[
    "anonymous_bind",
    "enumerate_users",
    "enumerate_groups",
    "find_computers",
    "find_spns",
    "get_domain_info",
    "full_enum",
]

# LDAP Constants
LDAP_BIND_REQUEST = 0x60
LDAP_BIND_RESPONSE = 0x61
LDAP_SEARCH_REQUEST = 0x63
LDAP_SEARCH_RESULT_ENTRY = 0x64
LDAP_SEARCH_RESULT_DONE = 0x65

# Common LDAP attributes
USER_ATTRIBUTES = [
    "sAMAccountName", "cn", "displayName", "mail", "memberOf",
    "userPrincipalName", "description", "lastLogon", "pwdLastSet",
    "userAccountControl", "adminCount",
]

GROUP_ATTRIBUTES = [
    "cn", "sAMAccountName", "description", "member", "memberOf",
    "groupType", "adminCount",
]

COMPUTER_ATTRIBUTES = [
    "cn", "sAMAccountName", "dNSHostName", "operatingSystem",
    "operatingSystemVersion", "lastLogon", "userAccountControl",
]


def _encode_length(length: int) -> bytes:
    """Encode BER length."""
    if length < 128:
        return struct.pack("B", length)
    elif length < 256:
        return struct.pack("BB", 0x81, length)
    elif length < 65536:
        return struct.pack(">BH", 0x82, length)
    else:
        return struct.pack(">BI", 0x84, length)


def _encode_string(s: str) -> bytes:
    """Encode LDAP string (octet string)."""
    encoded = s.encode("utf-8")
    return b"\x04" + _encode_length(len(encoded)) + encoded


def _encode_sequence(data: bytes) -> bytes:
    """Encode LDAP sequence."""
    return b"\x30" + _encode_length(len(data)) + data


def _encode_integer(value: int) -> bytes:
    """Encode LDAP integer."""
    if value == 0:
        return b"\x02\x01\x00"
    elif value < 128:
        return struct.pack("BBB", 0x02, 1, value)
    elif value < 32768:
        return struct.pack(">BBH", 0x02, 2, value)
    else:
        return struct.pack(">BBI", 0x02, 4, value)


def _create_bind_request(message_id: int, username: str = "", password: str = "") -> bytes:
    """Create LDAP bind request."""
    # Version (3)
    version = _encode_integer(3)

    # Name (DN)
    name = _encode_string(username)

    # Simple authentication
    auth = b"\x80" + _encode_length(len(password)) + password.encode("utf-8")

    # Bind request
    bind_request = version + name + auth
    bind_request = b"\x60" + _encode_length(len(bind_request)) + bind_request

    # Message ID
    msg_id = _encode_integer(message_id)

    # Complete message
    message = msg_id + bind_request
    return _encode_sequence(message)


def _create_search_request(
    message_id: int,
    base_dn: str,
    filter_str: str = "(objectClass=*)",
    attributes: list[str] | None = None,
    scope: int = 2,  # 0=base, 1=one, 2=sub
    size_limit: int = 100,
) -> bytes:
    """Create LDAP search request."""
    # Base DN
    base = _encode_string(base_dn)

    # Scope
    scope_enc = b"\x0a\x01" + struct.pack("B", scope)

    # Deref aliases (never)
    deref = b"\x0a\x01\x00"

    # Size limit
    size = _encode_integer(size_limit)

    # Time limit
    time_limit = _encode_integer(0)

    # Types only
    types_only = b"\x01\x01\x00"

    # Filter (simplified - just supports basic filters)
    filter_data = _encode_ldap_filter(filter_str)

    # Attributes
    attr_list = b""
    if attributes:
        for attr in attributes:
            attr_list += _encode_string(attr)
    attributes_seq = _encode_sequence(attr_list)

    # Search request
    search_request = base + scope_enc + deref + size + time_limit + types_only + filter_data + attributes_seq
    search_request = b"\x63" + _encode_length(len(search_request)) + search_request

    # Message ID
    msg_id = _encode_integer(message_id)

    # Complete message
    message = msg_id + search_request
    return _encode_sequence(message)


def _encode_ldap_filter(filter_str: str) -> bytes:
    """Encode a simple LDAP filter."""
    # This is a simplified implementation for common filters
    if filter_str.startswith("(") and filter_str.endswith(")"):
        filter_str = filter_str[1:-1]

    if filter_str.startswith("&"):
        # AND filter
        return b"\xa0" + _encode_length(0)  # Simplified
    elif filter_str.startswith("|"):
        # OR filter
        return b"\xa1" + _encode_length(0)  # Simplified
    elif "=" in filter_str:
        # Equality filter
        attr, value = filter_str.split("=", 1)
        if value == "*":
            # Present filter
            attr_enc = attr.encode("utf-8")
            return b"\x87" + _encode_length(len(attr_enc)) + attr_enc
        else:
            # Equality match
            attr_enc = _encode_string(attr)
            val_enc = _encode_string(value)
            content = attr_enc + val_enc
            return b"\xa3" + _encode_length(len(content)) + content

    # Default: present filter for objectClass
    return b"\x87\x0bobjectClass"


def _parse_bind_response(data: bytes) -> dict[str, Any]:
    """Parse LDAP bind response."""
    result = {
        "success": False,
        "result_code": -1,
        "message": "",
    }

    try:
        # Skip sequence header and message ID
        idx = 0
        if data[idx] == 0x30:
            idx += 1
            length = data[idx]
            if length & 0x80:
                length_bytes = length & 0x7f
                idx += 1 + length_bytes
            else:
                idx += 1

        # Skip message ID
        if data[idx] == 0x02:
            idx += 1
            id_len = data[idx]
            idx += 1 + id_len

        # Check for bind response
        if data[idx] == 0x61:
            idx += 1
            resp_len = data[idx]
            if resp_len & 0x80:
                resp_len_bytes = resp_len & 0x7f
                idx += 1 + resp_len_bytes
            else:
                idx += 1

            # Result code
            if data[idx] == 0x0a:
                idx += 1
                code_len = data[idx]
                idx += 1
                result["result_code"] = data[idx]
                result["success"] = result["result_code"] == 0

    except (IndexError, ValueError):
        pass

    return result


def _check_ldap_connection(target: str, port: int = 389, use_ssl: bool = False, timeout: float = 10.0) -> dict[str, Any]:
    """Check LDAP connection."""
    result = {
        "reachable": False,
        "port": port,
        "ssl": use_ssl,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=target)

        sock.connect((target, port))
        result["reachable"] = True
        sock.close()

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except OSError as e:
        result["error"] = str(e)

    return result


def _test_anonymous_bind(target: str, port: int = 389, use_ssl: bool = False, timeout: float = 10.0) -> dict[str, Any]:
    """Test anonymous LDAP bind."""
    result = {
        "action": "anonymous_bind",
        "target": target,
        "port": port,
        "anonymous_allowed": False,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=target)

        sock.connect((target, port))

        # Send anonymous bind request
        bind_request = _create_bind_request(1, "", "")
        sock.send(bind_request)

        response = sock.recv(4096)
        sock.close()

        if response:
            bind_result = _parse_bind_response(response)
            result["anonymous_allowed"] = bind_result.get("success", False)
            result["result_code"] = bind_result.get("result_code")

            if result["anonymous_allowed"]:
                result["severity"] = "high"
                result["finding"] = "Anonymous LDAP bind is allowed"
                result["recommendation"] = "Disable anonymous LDAP binds to prevent information disclosure"
            else:
                result["note"] = "Anonymous bind rejected (this is the secure configuration)"

    except Exception as e:
        result["error"] = str(e)

    return result


def _enumerate_users(
    target: str,
    base_dn: str,
    port: int = 389,
    username: str | None = None,
    password: str | None = None,
    use_ssl: bool = False,
) -> dict[str, Any]:
    """Enumerate domain users."""
    result = {
        "action": "enumerate_users",
        "target": target,
        "base_dn": base_dn,
        "users": [],
    }

    # Provide command suggestions for manual enumeration
    result["note"] = "Full LDAP enumeration requires ldap3 library or ldapsearch"

    if username:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target}:{port} -D '{username}' -w '{password or ''}' -b '{base_dn}' '(objectCategory=person)' sAMAccountName",
            f"GetADUsers.py -dc-ip {target} '{username}:{password or ''}'",
            f"ldapdomaindump -u '{username}' -p '{password or ''}' ldap://{target}",
        ]
    else:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target}:{port} -b '{base_dn}' '(objectCategory=person)' sAMAccountName",
            f"ldapdomaindump -u '' -p '' ldap://{target}",
        ]

    result["common_filters"] = {
        "all_users": "(objectCategory=person)",
        "enabled_users": "(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        "admin_users": "(&(objectCategory=person)(adminCount=1))",
        "service_accounts": "(&(objectCategory=person)(servicePrincipalName=*))",
    }

    return result


def _enumerate_groups(
    target: str,
    base_dn: str,
    port: int = 389,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Enumerate domain groups."""
    result = {
        "action": "enumerate_groups",
        "target": target,
        "base_dn": base_dn,
    }

    result["note"] = "Full LDAP enumeration requires ldap3 library or ldapsearch"

    if username:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target}:{port} -D '{username}' -w '{password or ''}' -b '{base_dn}' '(objectCategory=group)' cn member",
        ]
    else:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target}:{port} -b '{base_dn}' '(objectCategory=group)' cn member",
        ]

    result["privileged_groups"] = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DnsAdmins",
    ]

    return result


def _find_computers(
    target: str,
    base_dn: str,
    port: int = 389,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Find domain computers."""
    result = {
        "action": "find_computers",
        "target": target,
        "base_dn": base_dn,
    }

    result["note"] = "Full LDAP enumeration requires ldap3 library or ldapsearch"

    if username:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target}:{port} -D '{username}' -w '{password or ''}' -b '{base_dn}' '(objectCategory=computer)' cn dNSHostName operatingSystem",
            f"GetADComputers.py -dc-ip {target} '{username}:{password or ''}'",
        ]
    else:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target}:{port} -b '{base_dn}' '(objectCategory=computer)' cn dNSHostName",
        ]

    result["common_filters"] = {
        "all_computers": "(objectCategory=computer)",
        "domain_controllers": "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        "servers": "(&(objectCategory=computer)(operatingSystem=*server*))",
        "workstations": "(&(objectCategory=computer)(!(operatingSystem=*server*)))",
    }

    return result


def _find_spns(
    target: str,
    base_dn: str,
    port: int = 389,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Find Service Principal Names for Kerberoasting."""
    result = {
        "action": "find_spns",
        "target": target,
        "base_dn": base_dn,
    }

    result["note"] = "SPN enumeration is critical for Kerberoasting attacks"

    if username:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target}:{port} -D '{username}' -w '{password or ''}' -b '{base_dn}' '(&(objectCategory=person)(servicePrincipalName=*))' sAMAccountName servicePrincipalName",
            f"GetUserSPNs.py -dc-ip {target} '{username}:{password or ''}'",
            f"impacket-GetUserSPNs -dc-ip {target} -request '{username}:{password or ''}'",
        ]
    else:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target}:{port} -b '{base_dn}' '(&(objectCategory=person)(servicePrincipalName=*))' sAMAccountName servicePrincipalName",
        ]

    result["kerberoasting_info"] = {
        "description": "Accounts with SPNs can be Kerberoasted to obtain their TGS tickets for offline cracking",
        "filter": "(&(objectCategory=person)(servicePrincipalName=*))",
        "next_steps": [
            "Request TGS tickets for discovered SPNs",
            "Crack tickets offline with hashcat/john",
            "Target accounts with weak passwords",
        ],
    }

    return result


def _get_domain_info(
    target: str,
    base_dn: str,
    port: int = 389,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Get domain configuration information."""
    result = {
        "action": "get_domain_info",
        "target": target,
        "base_dn": base_dn,
    }

    result["note"] = "Domain information requires LDAP access"

    if username:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target}:{port} -D '{username}' -w '{password or ''}' -b '{base_dn}' -s base '(objectClass=*)' *",
            f"ldapsearch -x -H ldap://{target}:{port} -D '{username}' -w '{password or ''}' -b 'CN=Policies,CN=System,{base_dn}' '(objectClass=*)' cn gPCFileSysPath",
        ]

    result["interesting_attributes"] = {
        "domain": ["objectSid", "ms-DS-MachineAccountQuota", "minPwdLength", "lockoutThreshold"],
        "password_policy": ["minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge", "lockoutDuration", "lockoutThreshold"],
        "trusts": ["trustPartner", "trustDirection", "trustType", "trustAttributes"],
    }

    return result


def _full_enum(
    target: str,
    base_dn: str | None,
    port: int = 389,
    username: str | None = None,
    password: str | None = None,
    use_ssl: bool = False,
) -> dict[str, Any]:
    """Run full LDAP enumeration."""
    result = {
        "action": "full_enum",
        "target": target,
        "port": port,
    }

    # Check connectivity
    conn_check = _check_ldap_connection(target, port, use_ssl)
    result["connection"] = conn_check

    if not conn_check.get("reachable"):
        result["error"] = "Cannot connect to LDAP server"
        return result

    # Test anonymous bind
    result["anonymous_bind"] = _test_anonymous_bind(target, port, use_ssl)

    # If no base_dn provided, suggest how to find it
    if not base_dn:
        result["base_dn_discovery"] = {
            "note": "Base DN not provided. Use these commands to discover it:",
            "commands": [
                f"ldapsearch -x -H ldap://{target}:{port} -s base '(objectClass=*)' namingContexts",
                f"nmap -p {port} --script ldap-rootdse {target}",
            ],
        }
        base_dn = "DC=domain,DC=local"  # Placeholder

    result["base_dn"] = base_dn

    # Run enumeration checks
    result["users"] = _enumerate_users(target, base_dn, port, username, password, use_ssl)
    result["groups"] = _enumerate_groups(target, base_dn, port, username, password)
    result["computers"] = _find_computers(target, base_dn, port, username, password)
    result["spns"] = _find_spns(target, base_dn, port, username, password)
    result["domain_info"] = _get_domain_info(target, base_dn, port, username, password)

    # Summary
    findings = []
    if result["anonymous_bind"].get("anonymous_allowed"):
        findings.append({
            "issue": "Anonymous LDAP bind allowed",
            "severity": "high",
            "description": "Anyone can enumerate directory information",
        })

    result["summary"] = {
        "findings": findings,
        "enumeration_tools": [
            f"ldapdomaindump ldap://{target}",
            f"bloodhound-python -d domain.local -u user -p pass -c All -ns {target}",
            f"enum4linux-ng -A {target}",
        ],
    }

    return result


@register_tool
def ldap_enumerator(
    action: LDAPEnumAction,
    target: str | None = None,
    base_dn: str | None = None,
    username: str | None = None,
    password: str | None = None,
    port: int = 389,
    use_ssl: bool = False,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Enumerate LDAP/Active Directory for users, groups, and domain information.

    Args:
        action: The enumeration action to perform:
            - anonymous_bind: Test for anonymous LDAP access
            - enumerate_users: List domain users
            - enumerate_groups: List domain groups
            - find_computers: Find domain computers
            - find_spns: Find service principal names
            - get_domain_info: Get domain configuration
            - full_enum: Run all enumeration checks
        target: Target LDAP server (domain controller)
        base_dn: Base DN for LDAP queries (e.g., DC=domain,DC=local)
        username: Username for authentication
        password: Password for authentication
        port: LDAP port (default: 389, use 636 for LDAPS)
        use_ssl: Use LDAPS (SSL/TLS) connection

    Returns:
        Enumeration results with users, groups, and domain information
    """
    VALID_PARAMS = {"action", "target", "base_dn", "username", "password", "port", "use_ssl"}
    VALID_ACTIONS = ["anonymous_bind", "enumerate_users", "enumerate_groups", "find_computers", "find_spns", "get_domain_info", "full_enum"]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "ldap_enumerator"):
        unknown_error.update(
            generate_usage_hint("ldap_enumerator", "anonymous_bind", {"target": "dc01.domain.local"})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "ldap_enumerator"):
        action_error["usage_examples"] = {
            "anonymous_bind": 'ldap_enumerator(action="anonymous_bind", target="dc01.domain.local")',
            "enumerate_users": 'ldap_enumerator(action="enumerate_users", target="10.0.0.1", base_dn="DC=domain,DC=local")',
            "full_enum": 'ldap_enumerator(action="full_enum", target="dc01.domain.local")',
        }
        return action_error

    if param_error := validate_required_param(target, "target", action, "ldap_enumerator"):
        param_error.update(generate_usage_hint("ldap_enumerator", action, {"target": "dc01.domain.local"}))
        return param_error

    try:
        if action == "anonymous_bind":
            return _test_anonymous_bind(target, port, use_ssl)
        elif action == "enumerate_users":
            if not base_dn:
                return {
                    "error": "base_dn parameter required for user enumeration",
                    "hint": "Provide base DN like 'DC=domain,DC=local'",
                    "tool_name": "ldap_enumerator",
                }
            return _enumerate_users(target, base_dn, port, username, password, use_ssl)
        elif action == "enumerate_groups":
            if not base_dn:
                return {
                    "error": "base_dn parameter required for group enumeration",
                    "hint": "Provide base DN like 'DC=domain,DC=local'",
                    "tool_name": "ldap_enumerator",
                }
            return _enumerate_groups(target, base_dn, port, username, password)
        elif action == "find_computers":
            if not base_dn:
                return {
                    "error": "base_dn parameter required for computer enumeration",
                    "hint": "Provide base DN like 'DC=domain,DC=local'",
                    "tool_name": "ldap_enumerator",
                }
            return _find_computers(target, base_dn, port, username, password)
        elif action == "find_spns":
            if not base_dn:
                return {
                    "error": "base_dn parameter required for SPN enumeration",
                    "hint": "Provide base DN like 'DC=domain,DC=local'",
                    "tool_name": "ldap_enumerator",
                }
            return _find_spns(target, base_dn, port, username, password)
        elif action == "get_domain_info":
            if not base_dn:
                return {
                    "error": "base_dn parameter required for domain info",
                    "hint": "Provide base DN like 'DC=domain,DC=local'",
                    "tool_name": "ldap_enumerator",
                }
            return _get_domain_info(target, base_dn, port, username, password)
        elif action == "full_enum":
            return _full_enum(target, base_dn, port, username, password, use_ssl)

    except socket.gaierror:
        return {
            "error": f"Could not resolve hostname: {target}",
            "hint": "Verify the target hostname or use an IP address",
            "tool_name": "ldap_enumerator",
        }
    except Exception as e:
        return {
            "error": f"LDAP enumeration failed: {e!s}",
            "tool_name": "ldap_enumerator",
        }

    return {"error": "Unknown action", "tool_name": "ldap_enumerator"}
