"""
MFA Bypass Tester - Automated multi-factor authentication bypass detection.

Complements the mfa_bypass_techniques.jinja prompt module with automated testing capabilities.
"""

import json
import random
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Literal

import httpx

from strix.tools.registry import register_tool
from strix.tools.validation import (
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

MFABypassAction = Literal[
    "test_response_manipulation",
    "test_rate_limit",
    "test_backup_codes",
    "test_recovery_flow",
    "test_remember_device",
    "test_enrollment_bypass",
    "analyze",
    "generate_tests",
]

VALID_ACTIONS = [
    "test_response_manipulation",
    "test_rate_limit",
    "test_backup_codes",
    "test_recovery_flow",
    "test_remember_device",
    "test_enrollment_bypass",
    "analyze",
    "generate_tests",
]


@register_tool
def mfa_bypass_tester(
    action: MFABypassAction,
    url: str,
    mfa_endpoint: str | None = None,
    session_cookie: str | None = None,
    test_code: str = "000000",
    num_attempts: int = 10,
    protected_endpoint: str | None = None,
    recovery_endpoint: str | None = None,
    device_token: str | None = None,
    headers: str | None = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Test for MFA bypass vulnerabilities.

    Detects common MFA implementation flaws including response manipulation,
    rate limiting issues, backup code weaknesses, and recovery flow bypasses.

    Args:
        action: The testing action to perform
        url: Base URL of the target application
        mfa_endpoint: MFA verification endpoint path
        session_cookie: Session cookie for authenticated requests
        test_code: MFA code to use for testing
        num_attempts: Number of attempts for rate limit testing
        protected_endpoint: Protected resource to test access
        recovery_endpoint: Password reset/recovery endpoint
        device_token: Remember device token to test
        headers: Additional headers as JSON string
        timeout: Request timeout in seconds

    Returns:
        Dictionary containing test results
    """
    unknown = validate_unknown_params(
        kwargs,
        ["action", "url", "mfa_endpoint", "session_cookie", "test_code",
         "num_attempts", "protected_endpoint", "recovery_endpoint",
         "device_token", "headers", "timeout"],
    )
    if unknown:
        return {"error": f"Unknown parameters: {unknown}"}

    action_error = validate_action_param(action, VALID_ACTIONS)
    if action_error:
        return action_error

    url_error = validate_required_param(url, "url")
    if url_error:
        return url_error

    # Parse additional headers
    extra_headers = {}
    if headers:
        try:
            extra_headers = json.loads(headers)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format for headers"}

    # Add session cookie to headers
    if session_cookie:
        extra_headers["Cookie"] = session_cookie

    try:
        if action == "test_response_manipulation":
            return _test_response_manipulation(url, mfa_endpoint, extra_headers, test_code, timeout)
        elif action == "test_rate_limit":
            return _test_rate_limit(url, mfa_endpoint, extra_headers, num_attempts, timeout)
        elif action == "test_backup_codes":
            return _test_backup_codes(url, mfa_endpoint, extra_headers, num_attempts, timeout)
        elif action == "test_recovery_flow":
            return _test_recovery_flow(url, recovery_endpoint, protected_endpoint, extra_headers, timeout)
        elif action == "test_remember_device":
            return _test_remember_device(url, mfa_endpoint, protected_endpoint, device_token, extra_headers, timeout)
        elif action == "test_enrollment_bypass":
            return _test_enrollment_bypass(url, protected_endpoint, extra_headers, timeout)
        elif action == "analyze":
            return _analyze_mfa_implementation(url, mfa_endpoint, extra_headers, timeout)
        elif action == "generate_tests":
            return _generate_test_cases(url, mfa_endpoint, recovery_endpoint)
        else:
            return {"error": f"Unknown action: {action}"}
    except httpx.RequestError as e:
        return {"error": f"Request failed: {e!s}"}
    except Exception as e:
        return {"error": f"Test failed: {e!s}"}


def _test_response_manipulation(
    url: str,
    mfa_endpoint: str | None,
    headers: dict,
    test_code: str,
    timeout: int,
) -> dict[str, Any]:
    """Test for response manipulation bypass (client-side validation)."""
    results = {
        "url": url,
        "response_manipulation_vectors": [],
        "server_side_enforcement": True,
        "vulnerable": False,
    }

    endpoint = mfa_endpoint or "/api/mfa/verify"
    full_url = f"{url.rstrip('/')}{endpoint}"

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        # Test with invalid code
        payload = {"code": test_code}

        try:
            resp = client.post(full_url, json=payload, headers=headers)

            results["original_response"] = {
                "status_code": resp.status_code,
                "content_type": resp.headers.get("content-type", ""),
            }

            # Check response body for manipulation opportunities
            try:
                body = resp.json()
                results["original_response"]["body"] = body

                # Identify fields that might be manipulated
                manipulation_fields = []
                for key in ["success", "verified", "mfa_verified", "valid", "passed", "authenticated"]:
                    if key in body:
                        manipulation_fields.append({
                            "field": key,
                            "current_value": body[key],
                            "manipulation": f"Change {key} to true/True",
                        })

                if manipulation_fields:
                    results["response_manipulation_vectors"] = manipulation_fields
                    results["recommendation"] = "Test if changing these response values bypasses MFA"

            except (json.JSONDecodeError, ValueError):
                results["original_response"]["body_type"] = "non-json"

            # Check if 401 status but no server-side enforcement
            # Try accessing protected resource after failed MFA
            if resp.status_code in [401, 403]:
                results["status_based_rejection"] = True
                results["manipulation_test"] = "Intercept response and change status to 200"

        except Exception as e:
            results["error"] = str(e)

    return results


def _test_rate_limit(
    url: str,
    mfa_endpoint: str | None,
    headers: dict,
    num_attempts: int,
    timeout: int,
) -> dict[str, Any]:
    """Test for rate limiting on MFA verification."""
    results = {
        "url": url,
        "rate_limited": False,
        "attempts_before_limit": 0,
        "lockout_detected": False,
        "timing_analysis": [],
    }

    endpoint = mfa_endpoint or "/api/mfa/verify"
    full_url = f"{url.rstrip('/')}{endpoint}"

    with httpx.Client(timeout=timeout) as client:
        successful_attempts = 0
        response_times = []

        for i in range(num_attempts):
            # Generate random invalid code
            code = "".join(random.choices(string.digits, k=6))
            payload = {"code": code}

            start = time.time()
            try:
                resp = client.post(full_url, json=payload, headers=headers)
                elapsed = time.time() - start

                response_times.append(elapsed)

                if resp.status_code == 429:
                    results["rate_limited"] = True
                    results["attempts_before_limit"] = i
                    results["rate_limit_response"] = resp.headers.get("retry-after", "Not specified")
                    break
                elif resp.status_code in [423, 403] and "locked" in resp.text.lower():
                    results["lockout_detected"] = True
                    results["attempts_before_lockout"] = i
                    break
                else:
                    successful_attempts += 1

            except Exception as e:
                results.setdefault("errors", []).append(f"Attempt {i}: {e!s}")
                break

        results["successful_attempts"] = successful_attempts
        results["timing_analysis"] = {
            "avg_response_ms": round(sum(response_times) / len(response_times) * 1000, 2) if response_times else 0,
            "max_response_ms": round(max(response_times) * 1000, 2) if response_times else 0,
            "min_response_ms": round(min(response_times) * 1000, 2) if response_times else 0,
        }

        # Check for timing-based enumeration
        if response_times:
            variance = max(response_times) - min(response_times)
            if variance > 0.5:  # 500ms variance
                results["timing_variance_detected"] = True
                results["recommendation"] = "High timing variance may indicate valid vs invalid code differentiation"

    results["vulnerable"] = not results["rate_limited"] and successful_attempts >= num_attempts

    return results


def _test_backup_codes(
    url: str,
    mfa_endpoint: str | None,
    headers: dict,
    num_attempts: int,
    timeout: int,
) -> dict[str, Any]:
    """Test backup code verification for weaknesses."""
    results = {
        "url": url,
        "backup_code_endpoint": None,
        "rate_limited": False,
        "enumeration_possible": False,
        "findings": [],
    }

    # Common backup code endpoints
    backup_endpoints = [
        "/api/mfa/backup",
        "/api/mfa/verify-backup",
        "/api/mfa/recovery",
        "/api/auth/backup-code",
        "/api/2fa/backup",
    ]

    if mfa_endpoint:
        backup_endpoints.insert(0, mfa_endpoint)

    with httpx.Client(timeout=timeout) as client:
        # Find backup code endpoint
        for endpoint in backup_endpoints:
            full_url = f"{url.rstrip('/')}{endpoint}"
            try:
                resp = client.post(full_url, json={"code": "12345678"}, headers=headers)
                if resp.status_code != 404:
                    results["backup_code_endpoint"] = endpoint
                    break
            except Exception:
                continue

        if not results["backup_code_endpoint"]:
            results["backup_code_endpoint"] = backup_endpoints[0]
            results["note"] = "Endpoint not confirmed - using default"

        full_url = f"{url.rstrip('/')}{results['backup_code_endpoint']}"

        # Test for response differences (enumeration)
        responses = {}
        test_codes = [
            "00000000",  # All zeros
            "12345678",  # Sequential
            "AAAAAAAA",  # All letters
            "99999999",  # All nines
        ]

        for code in test_codes:
            try:
                resp = client.post(full_url, json={"code": code}, headers=headers)
                resp_key = (resp.status_code, len(resp.text), resp.text[:100] if resp.text else "")
                responses[code] = resp_key
            except Exception:
                continue

        # Check for response variance (enumeration indicator)
        if len(set(responses.values())) > 1:
            results["enumeration_possible"] = True
            results["findings"].append({
                "type": "response_variance",
                "description": "Different responses for different codes may indicate enumeration",
                "responses": {k: {"status": v[0], "length": v[1]} for k, v in responses.items()},
            })

        # Test rate limiting
        rate_test = _test_rate_limit(url, results["backup_code_endpoint"], headers, num_attempts, timeout)
        results["rate_limited"] = rate_test.get("rate_limited", False)

        if not results["rate_limited"]:
            results["findings"].append({
                "type": "no_rate_limit",
                "description": "Backup codes not rate limited - brute force may be possible",
                "attempts_tested": num_attempts,
            })

    results["vulnerable"] = results["enumeration_possible"] or not results["rate_limited"]

    return results


def _test_recovery_flow(
    url: str,
    recovery_endpoint: str | None,
    protected_endpoint: str | None,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test if recovery flows bypass MFA."""
    results = {
        "url": url,
        "recovery_endpoints_found": [],
        "mfa_bypass_possible": False,
        "findings": [],
    }

    # Common recovery endpoints
    recovery_endpoints = [
        "/api/password/reset",
        "/api/auth/forgot-password",
        "/api/user/recover",
        "/forgot-password",
        "/reset-password",
        "/api/mfa/disable",
        "/api/user/phone",
        "/api/user/email",
    ]

    if recovery_endpoint:
        recovery_endpoints.insert(0, recovery_endpoint)

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # Discover recovery endpoints
        for endpoint in recovery_endpoints:
            full_url = f"{url.rstrip('/')}{endpoint}"
            try:
                # Try GET and POST
                get_resp = client.get(full_url, headers=headers)
                if get_resp.status_code not in [404, 405]:
                    results["recovery_endpoints_found"].append({
                        "endpoint": endpoint,
                        "method": "GET",
                        "status": get_resp.status_code,
                    })

                post_resp = client.post(full_url, json={}, headers=headers)
                if post_resp.status_code not in [404, 405]:
                    results["recovery_endpoints_found"].append({
                        "endpoint": endpoint,
                        "method": "POST",
                        "status": post_resp.status_code,
                    })

            except Exception:
                continue

        # Test MFA disable endpoint
        disable_endpoints = [
            "/api/mfa/disable",
            "/api/2fa/disable",
            "/api/auth/mfa/remove",
        ]

        for endpoint in disable_endpoints:
            full_url = f"{url.rstrip('/')}{endpoint}"
            try:
                # Test if MFA can be disabled without MFA verification
                resp = client.post(
                    full_url,
                    json={"password": "test_password"},
                    headers=headers,
                )

                if resp.status_code in [200, 201]:
                    results["findings"].append({
                        "type": "mfa_disable_no_verification",
                        "endpoint": endpoint,
                        "description": "MFA may be disabled without MFA verification",
                    })
                    results["mfa_bypass_possible"] = True
                elif resp.status_code not in [404, 401, 403]:
                    results["findings"].append({
                        "type": "mfa_disable_accessible",
                        "endpoint": endpoint,
                        "status": resp.status_code,
                    })

            except Exception:
                continue

        # Test phone/email change without MFA
        change_endpoints = [
            ("/api/user/phone", {"phone": "+15555555555"}),
            ("/api/user/email", {"email": "test@test.com"}),
        ]

        for endpoint, payload in change_endpoints:
            full_url = f"{url.rstrip('/')}{endpoint}"
            try:
                resp = client.post(full_url, json=payload, headers=headers)

                if resp.status_code in [200, 201]:
                    results["findings"].append({
                        "type": "sensitive_change_no_mfa",
                        "endpoint": endpoint,
                        "description": f"Can change {endpoint.split('/')[-1]} without MFA",
                    })
                    results["mfa_bypass_possible"] = True

            except Exception:
                continue

    results["vulnerable"] = results["mfa_bypass_possible"]

    return results


def _test_remember_device(
    url: str,
    mfa_endpoint: str | None,
    protected_endpoint: str | None,
    device_token: str | None,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test remember device token vulnerabilities."""
    results = {
        "url": url,
        "token_reuse_possible": False,
        "token_not_device_bound": False,
        "findings": [],
    }

    protected = protected_endpoint or "/api/user/profile"
    full_protected_url = f"{url.rstrip('/')}{protected}"

    with httpx.Client(timeout=timeout) as client:
        # Test with provided device token
        if device_token:
            # Test token on different "device" (different User-Agent)
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1",
                "Mozilla/5.0 (Linux; Android 14) Chrome/120.0.0.0",
            ]

            token_headers = headers.copy()
            # Try common remember device cookie/header names
            token_names = ["remember_device", "device_token", "trusted_device", "mfa_remember"]

            for token_name in token_names:
                for ua in user_agents:
                    test_headers = token_headers.copy()
                    test_headers["User-Agent"] = ua

                    # Test as cookie
                    if "Cookie" in test_headers:
                        test_headers["Cookie"] += f"; {token_name}={device_token}"
                    else:
                        test_headers["Cookie"] = f"{token_name}={device_token}"

                    try:
                        resp = client.get(full_protected_url, headers=test_headers)

                        if resp.status_code == 200:
                            results["token_reuse_possible"] = True
                            results["findings"].append({
                                "type": "token_reuse",
                                "token_name": token_name,
                                "user_agent": ua[:50],
                                "description": "Device token works from different device/browser",
                            })
                            break

                    except Exception:
                        continue

        # Check for weak token patterns
        results["token_analysis"] = {
            "recommendations": [
                "Test if token survives password change",
                "Test if token expires",
                "Test if token is cryptographically random",
                "Test if token is bound to IP address",
            ]
        }

    results["vulnerable"] = results["token_reuse_possible"] or results["token_not_device_bound"]

    return results


def _test_enrollment_bypass(
    url: str,
    protected_endpoint: str | None,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Test if MFA enrollment can be bypassed."""
    results = {
        "url": url,
        "enrollment_skippable": False,
        "protected_access_without_mfa": False,
        "findings": [],
    }

    protected = protected_endpoint or "/api/user/profile"

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        # Test direct access to protected resources
        protected_urls = [
            protected,
            "/dashboard",
            "/admin",
            "/api/admin",
            "/api/user/settings",
            "/api/data",
        ]

        for endpoint in protected_urls:
            full_url = f"{url.rstrip('/')}{endpoint}"
            try:
                resp = client.get(full_url, headers=headers)

                if resp.status_code == 200:
                    results["findings"].append({
                        "type": "protected_accessible",
                        "endpoint": endpoint,
                        "description": "Protected resource accessible (verify MFA enforcement)",
                    })
                elif resp.status_code == 302:
                    redirect = resp.headers.get("location", "")
                    if "mfa" not in redirect.lower() and "2fa" not in redirect.lower():
                        results["findings"].append({
                            "type": "redirect_no_mfa",
                            "endpoint": endpoint,
                            "redirect": redirect,
                        })

            except Exception:
                continue

        # Test enrollment skip endpoints
        skip_endpoints = [
            "/api/mfa/skip",
            "/api/mfa/later",
            "/api/2fa/skip",
            "/setup/skip-mfa",
        ]

        for endpoint in skip_endpoints:
            full_url = f"{url.rstrip('/')}{endpoint}"
            try:
                resp = client.post(full_url, headers=headers)

                if resp.status_code in [200, 201, 302]:
                    results["enrollment_skippable"] = True
                    results["findings"].append({
                        "type": "mfa_skip_endpoint",
                        "endpoint": endpoint,
                        "status": resp.status_code,
                    })

            except Exception:
                continue

    results["vulnerable"] = results["enrollment_skippable"] or len(results["findings"]) > 0

    return results


def _analyze_mfa_implementation(
    url: str,
    mfa_endpoint: str | None,
    headers: dict,
    timeout: int,
) -> dict[str, Any]:
    """Comprehensive MFA implementation analysis."""
    results = {
        "url": url,
        "mfa_type": [],
        "endpoints_found": [],
        "security_issues": [],
        "recommendations": [],
    }

    # Common MFA endpoints
    mfa_endpoints = {
        "totp": ["/api/mfa/totp", "/api/2fa/verify", "/api/auth/otp"],
        "sms": ["/api/mfa/sms", "/api/auth/sms-verify", "/api/2fa/sms"],
        "push": ["/api/mfa/push", "/api/auth/push-verify"],
        "email": ["/api/mfa/email", "/api/auth/email-verify"],
        "backup": ["/api/mfa/backup", "/api/mfa/recovery"],
    }

    with httpx.Client(timeout=timeout) as client:
        for mfa_type, endpoints in mfa_endpoints.items():
            for endpoint in endpoints:
                full_url = f"{url.rstrip('/')}{endpoint}"
                try:
                    resp = client.post(full_url, json={"code": "000000"}, headers=headers)
                    if resp.status_code != 404:
                        results["mfa_type"].append(mfa_type)
                        results["endpoints_found"].append({
                            "type": mfa_type,
                            "endpoint": endpoint,
                            "status": resp.status_code,
                        })
                        break
                except Exception:
                    continue

        # Run targeted tests
        if mfa_endpoint or results["endpoints_found"]:
            test_endpoint = mfa_endpoint or results["endpoints_found"][0]["endpoint"]

            # Test rate limiting
            rate_result = _test_rate_limit(url, test_endpoint, headers, 5, timeout)
            if not rate_result.get("rate_limited"):
                results["security_issues"].append("No rate limiting detected on MFA verification")

            # Test response manipulation potential
            manip_result = _test_response_manipulation(url, test_endpoint, headers, "000000", timeout)
            if manip_result.get("response_manipulation_vectors"):
                results["security_issues"].append("Response contains fields that may be manipulated")

        # Generate recommendations
        if not results["mfa_type"]:
            results["recommendations"].append("Could not identify MFA endpoints - manual testing required")
        else:
            results["recommendations"] = [
                "Test response manipulation with proxy interception",
                "Test backup code brute force with longer attempt count",
                "Test race conditions with parallel requests",
                "Test if password reset bypasses MFA",
                "Test remember device token security",
            ]

    return results


def _generate_test_cases(
    url: str,
    mfa_endpoint: str | None,
    recovery_endpoint: str | None,
) -> dict[str, Any]:
    """Generate MFA bypass test cases."""
    endpoint = mfa_endpoint or "/api/mfa/verify"
    recovery = recovery_endpoint or "/api/password/reset"

    return {
        "response_manipulation": [
            {
                "name": "Status code manipulation",
                "steps": [
                    f"1. Send invalid MFA code to {endpoint}",
                    "2. Intercept 401/403 response",
                    "3. Change status code to 200",
                    "4. Forward modified response",
                    "5. Check if application grants access",
                ],
            },
            {
                "name": "JSON response manipulation",
                "steps": [
                    f"1. Send invalid MFA code to {endpoint}",
                    "2. Intercept JSON response",
                    '3. Change "success": false to "success": true',
                    '4. Change "verified": false to "verified": true',
                    "5. Forward modified response",
                ],
            },
        ],
        "direct_access": [
            {
                "name": "Skip MFA step",
                "steps": [
                    "1. Complete username/password authentication",
                    "2. Capture session token/cookie",
                    "3. Skip MFA endpoint entirely",
                    "4. Access protected resource directly",
                    "5. If successful: server doesn't enforce MFA",
                ],
            },
        ],
        "recovery_bypass": [
            {
                "name": "Password reset MFA bypass",
                "steps": [
                    f"1. Trigger password reset via {recovery}",
                    "2. Complete password reset flow",
                    "3. Check if MFA is still required",
                    "4. Check if MFA can be disabled during reset",
                ],
            },
        ],
        "race_conditions": [
            {
                "name": "Parallel verification race",
                "steps": [
                    "1. Obtain valid MFA code",
                    f"2. Send 10+ parallel requests to {endpoint}",
                    "3. Check if multiple sessions authenticated",
                    "4. Check if code consumed properly",
                ],
            },
        ],
        "totp_testing": [
            {
                "name": "Extended time window",
                "steps": [
                    "1. Generate TOTP code",
                    "2. Wait 30-60 seconds",
                    "3. Try code from previous time window",
                    "4. If accepted: extended window vulnerability",
                ],
            },
            {
                "name": "TOTP secret extraction",
                "steps": [
                    "1. Check MFA setup page source for otpauth:// URL",
                    "2. Check localStorage for TOTP secret",
                    "3. Check API responses during MFA setup",
                    "4. If secret exposed: can generate unlimited codes",
                ],
            },
        ],
    }
