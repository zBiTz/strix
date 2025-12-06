"""Validate credentials across multiple protocols and services."""

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


CredentialAction = Literal[
    "validate_ssh",
    "validate_smb",
    "validate_rdp",
    "validate_ldap",
    "validate_ftp",
    "validate_mysql",
    "validate_all",
]

# Default ports
DEFAULT_PORTS = {
    "ssh": 22,
    "smb": 445,
    "rdp": 3389,
    "ldap": 389,
    "ldaps": 636,
    "ftp": 21,
    "mysql": 3306,
}


def _check_port_open(host: str, port: int, timeout: float = 5.0) -> bool:
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _validate_ssh(
    target: str,
    username: str,
    password: str,
    port: int = 22,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Validate SSH credentials."""
    result = {
        "action": "validate_ssh",
        "target": target,
        "port": port,
        "username": username,
        "valid": False,
    }

    if not _check_port_open(target, port, timeout):
        result["error"] = f"Port {port} is not open"
        return result

    # SSH validation requires paramiko or similar library
    # Provide command for manual validation
    result["note"] = "Full SSH validation requires paramiko library"
    result["suggested_commands"] = [
        f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{target} -p {port} 'whoami'",
        f"hydra -l {username} -p '{password}' ssh://{target}:{port}",
        f"crackmapexec ssh {target} -u {username} -p '{password}'",
    ]

    # Try basic connection to verify service is running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        banner = sock.recv(256).decode("utf-8", errors="replace")
        sock.close()

        if "SSH" in banner:
            result["service_detected"] = True
            result["banner"] = banner.strip()
    except Exception as e:
        result["connection_error"] = str(e)

    return result


def _validate_smb(
    target: str,
    username: str,
    password: str,
    domain: str | None = None,
    port: int = 445,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Validate SMB credentials."""
    result = {
        "action": "validate_smb",
        "target": target,
        "port": port,
        "username": username,
        "domain": domain,
        "valid": False,
    }

    if not _check_port_open(target, port, timeout):
        result["error"] = f"Port {port} is not open"
        return result

    result["note"] = "Full SMB validation requires impacket or smbclient"

    domain_str = f"{domain}\\" if domain else ""
    result["suggested_commands"] = [
        f"smbclient -L //{target}/ -U '{domain_str}{username}%{password}'",
        f"crackmapexec smb {target} -u '{username}' -p '{password}'" + (f" -d '{domain}'" if domain else ""),
        f"rpcclient -U '{domain_str}{username}%{password}' {target}",
        f"smbmap -H {target} -u '{username}' -p '{password}'" + (f" -d '{domain}'" if domain else ""),
    ]

    result["post_auth_commands"] = {
        "list_shares": f"smbclient -L //{target}/ -U '{domain_str}{username}%{password}'",
        "check_admin": f"crackmapexec smb {target} -u '{username}' -p '{password}'" + (f" -d '{domain}'" if domain else ""),
        "dump_secrets": f"secretsdump.py '{domain_str}{username}:{password}'@{target}",
    }

    return result


def _validate_rdp(
    target: str,
    username: str,
    password: str,
    domain: str | None = None,
    port: int = 3389,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Validate RDP credentials."""
    result = {
        "action": "validate_rdp",
        "target": target,
        "port": port,
        "username": username,
        "domain": domain,
        "valid": False,
    }

    if not _check_port_open(target, port, timeout):
        result["error"] = f"Port {port} is not open"
        return result

    result["note"] = "RDP validation requires rdp-sec-check or similar tools"

    domain_str = f"{domain}\\" if domain else ""
    result["suggested_commands"] = [
        f"xfreerdp /v:{target}:{port} /u:{username} /p:'{password}'" + (f" /d:{domain}" if domain else "") + " +auth-only",
        f"crackmapexec rdp {target} -u '{username}' -p '{password}'" + (f" -d '{domain}'" if domain else ""),
        f"hydra -l {username} -p '{password}' rdp://{target}:{port}",
    ]

    # Check if RDP is running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        # Send RDP connection request
        sock.send(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
        response = sock.recv(256)
        sock.close()

        if response and len(response) > 0:
            result["service_detected"] = True
            result["rdp_available"] = True
    except Exception as e:
        result["connection_error"] = str(e)

    return result


def _validate_ldap(
    target: str,
    username: str,
    password: str,
    domain: str | None = None,
    port: int = 389,
    use_ssl: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Validate LDAP/AD credentials."""
    result = {
        "action": "validate_ldap",
        "target": target,
        "port": port,
        "username": username,
        "domain": domain,
        "valid": False,
    }

    actual_port = 636 if use_ssl else port
    if not _check_port_open(target, actual_port, timeout):
        result["error"] = f"Port {actual_port} is not open"
        return result

    result["note"] = "Full LDAP validation requires ldap3 library"

    # Format username for AD
    if domain:
        upn = f"{username}@{domain}"
        dn = f"{domain}\\{username}"
    else:
        upn = username
        dn = username

    ldap_uri = f"ldaps://{target}:{actual_port}" if use_ssl else f"ldap://{target}:{actual_port}"

    result["suggested_commands"] = [
        f"ldapwhoami -x -H {ldap_uri} -D '{upn}' -w '{password}'",
        f"ldapsearch -x -H {ldap_uri} -D '{upn}' -w '{password}' -b '' -s base",
        f"crackmapexec ldap {target} -u '{username}' -p '{password}'" + (f" -d '{domain}'" if domain else ""),
    ]

    # Try simple bind
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=target)

        sock.connect((target, actual_port))
        result["service_detected"] = True
        sock.close()
    except Exception as e:
        result["connection_error"] = str(e)

    return result


def _validate_ftp(
    target: str,
    username: str,
    password: str,
    port: int = 21,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Validate FTP credentials."""
    result = {
        "action": "validate_ftp",
        "target": target,
        "port": port,
        "username": username,
        "valid": False,
    }

    if not _check_port_open(target, port, timeout):
        result["error"] = f"Port {port} is not open"
        return result

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Receive banner
        banner = sock.recv(1024).decode("utf-8", errors="replace")
        result["banner"] = banner.strip()

        # Send USER
        sock.send(f"USER {username}\r\n".encode())
        user_response = sock.recv(1024).decode("utf-8", errors="replace")

        if user_response.startswith("331"):
            # Send PASS
            sock.send(f"PASS {password}\r\n".encode())
            pass_response = sock.recv(1024).decode("utf-8", errors="replace")

            if pass_response.startswith("230"):
                result["valid"] = True
                result["response"] = pass_response.strip()

                # Try to get current directory
                sock.send(b"PWD\r\n")
                pwd_response = sock.recv(1024).decode("utf-8", errors="replace")
                result["current_dir"] = pwd_response.strip()

            elif pass_response.startswith("530"):
                result["valid"] = False
                result["response"] = "Login incorrect"
            else:
                result["response"] = pass_response.strip()

        elif user_response.startswith("230"):
            # Anonymous login
            result["valid"] = True
            result["anonymous"] = True
            result["response"] = user_response.strip()

        sock.send(b"QUIT\r\n")
        sock.close()

    except socket.timeout:
        result["error"] = "Connection timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


def _validate_mysql(
    target: str,
    username: str,
    password: str,
    port: int = 3306,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Validate MySQL credentials."""
    result = {
        "action": "validate_mysql",
        "target": target,
        "port": port,
        "username": username,
        "valid": False,
    }

    if not _check_port_open(target, port, timeout):
        result["error"] = f"Port {port} is not open"
        return result

    result["note"] = "Full MySQL validation requires mysql-connector or similar"

    result["suggested_commands"] = [
        f"mysql -h {target} -P {port} -u {username} -p'{password}' -e 'SELECT USER();'",
        f"hydra -l {username} -p '{password}' mysql://{target}:{port}",
        f"crackmapexec mysql {target} -u '{username}' -p '{password}'",
    ]

    # Check if MySQL is running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # MySQL sends initial handshake
        handshake = sock.recv(1024)
        sock.close()

        if handshake and len(handshake) > 4:
            result["service_detected"] = True
            # Try to parse version
            if len(handshake) > 5:
                # Skip packet header
                version_end = handshake.find(b"\x00", 5)
                if version_end > 5:
                    try:
                        version = handshake[5:version_end].decode("utf-8", errors="replace")
                        result["version"] = version
                    except Exception:
                        pass

    except Exception as e:
        result["connection_error"] = str(e)

    return result


def _validate_all(
    target: str,
    username: str,
    password: str,
    domain: str | None = None,
) -> dict[str, Any]:
    """Validate credentials against all supported protocols."""
    result = {
        "action": "validate_all",
        "target": target,
        "username": username,
        "domain": domain,
        "results": {},
    }

    # Test each protocol
    protocols = [
        ("ssh", _validate_ssh, {"target": target, "username": username, "password": password}),
        ("smb", _validate_smb, {"target": target, "username": username, "password": password, "domain": domain}),
        ("rdp", _validate_rdp, {"target": target, "username": username, "password": password, "domain": domain}),
        ("ldap", _validate_ldap, {"target": target, "username": username, "password": password, "domain": domain}),
        ("ftp", _validate_ftp, {"target": target, "username": username, "password": password}),
        ("mysql", _validate_mysql, {"target": target, "username": username, "password": password}),
    ]

    valid_protocols = []
    for proto_name, validator, kwargs in protocols:
        try:
            proto_result = validator(**kwargs)
            result["results"][proto_name] = {
                "port_open": "error" not in proto_result or "Port" not in proto_result.get("error", ""),
                "valid": proto_result.get("valid", False),
                "service_detected": proto_result.get("service_detected", False),
            }
            if proto_result.get("valid"):
                valid_protocols.append(proto_name)
        except Exception as e:
            result["results"][proto_name] = {"error": str(e)}

    result["valid_protocols"] = valid_protocols
    result["summary"] = {
        "protocols_tested": len(protocols),
        "valid_credentials": len(valid_protocols),
    }

    if valid_protocols:
        result["next_steps"] = [
            f"Credentials valid for: {', '.join(valid_protocols)}",
            "Consider lateral movement opportunities",
            "Check for privilege escalation paths",
        ]

    return result


@register_tool
def credential_validator(
    action: CredentialAction,
    target: str | None = None,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
    port: int | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Validate credentials across multiple protocols and services.

    Args:
        action: The validation action to perform:
            - validate_ssh: Test SSH credentials
            - validate_smb: Test SMB credentials
            - validate_rdp: Test RDP credentials
            - validate_ldap: Test LDAP/AD credentials
            - validate_ftp: Test FTP credentials
            - validate_mysql: Test MySQL credentials
            - validate_all: Test against all protocols
        target: Target host IP address or hostname
        username: Username to validate
        password: Password to validate
        domain: Domain name for Windows/AD authentication
        port: Custom port (uses default if not specified)

    Returns:
        Validation results with access status and capabilities
    """
    VALID_PARAMS = {"action", "target", "username", "password", "domain", "port"}
    VALID_ACTIONS = ["validate_ssh", "validate_smb", "validate_rdp", "validate_ldap", "validate_ftp", "validate_mysql", "validate_all"]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "credential_validator"):
        unknown_error.update(
            generate_usage_hint("credential_validator", "validate_ssh", {"target": "192.168.1.1", "username": "admin", "password": "password"})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "credential_validator"):
        action_error["usage_examples"] = {
            "validate_ssh": 'credential_validator(action="validate_ssh", target="192.168.1.1", username="admin", password="pass")',
            "validate_smb": 'credential_validator(action="validate_smb", target="dc01", username="admin", password="pass", domain="DOMAIN")',
            "validate_all": 'credential_validator(action="validate_all", target="10.0.0.1", username="user", password="pass")',
        }
        return action_error

    # Validate required params
    for param, param_name in [(target, "target"), (username, "username"), (password, "password")]:
        if param_error := validate_required_param(param, param_name, action, "credential_validator"):
            return param_error

    try:
        action_map = {
            "validate_ssh": lambda: _validate_ssh(target, username, password, port or DEFAULT_PORTS["ssh"]),
            "validate_smb": lambda: _validate_smb(target, username, password, domain, port or DEFAULT_PORTS["smb"]),
            "validate_rdp": lambda: _validate_rdp(target, username, password, domain, port or DEFAULT_PORTS["rdp"]),
            "validate_ldap": lambda: _validate_ldap(target, username, password, domain, port or DEFAULT_PORTS["ldap"]),
            "validate_ftp": lambda: _validate_ftp(target, username, password, port or DEFAULT_PORTS["ftp"]),
            "validate_mysql": lambda: _validate_mysql(target, username, password, port or DEFAULT_PORTS["mysql"]),
            "validate_all": lambda: _validate_all(target, username, password, domain),
        }

        if action in action_map:
            return action_map[action]()

    except socket.gaierror:
        return {
            "error": f"Could not resolve hostname: {target}",
            "hint": "Verify the target hostname or use an IP address",
            "tool_name": "credential_validator",
        }
    except Exception as e:
        return {
            "error": f"Credential validation failed: {e!s}",
            "tool_name": "credential_validator",
        }

    return {"error": "Unknown action", "tool_name": "credential_validator"}
