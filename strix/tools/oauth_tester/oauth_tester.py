"""OAuth Tester tool for automated OAuth flow testing."""

from __future__ import annotations

import hashlib
import re
import secrets
from base64 import urlsafe_b64encode
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


OAuthTesterAction = Literal[
    "analyze_flow",
    "check_redirect_uri",
    "check_state",
    "check_pkce",
    "generate_tests",
    "analyze_token",
]


def _parse_oauth_url(url: str) -> dict[str, Any]:
    """Parse OAuth URL and extract parameters."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Flatten single-value params
    flat_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

    return {
        "base_url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
        "params": flat_params,
        "full_url": url,
    }


def _analyze_redirect_uri(redirect_uri: str, original_redirect: str) -> dict[str, Any]:
    """Analyze redirect URI for vulnerabilities."""
    findings: list[dict[str, str]] = []
    original_parsed = urlparse(original_redirect)

    # Check for open redirect patterns
    test_cases = [
        ("path_traversal", f"{original_redirect}/../../../attacker.com"),
        ("double_slash", f"{original_parsed.scheme}://{original_parsed.netloc}//attacker.com"),
        ("backslash", f"{original_redirect}\\attacker.com"),
        ("subdomain", f"https://attacker.{original_parsed.netloc}"),
        ("similar_domain", f"https://{original_parsed.netloc}.attacker.com"),
        ("fragment", f"{original_redirect}#@attacker.com"),
        ("userinfo", f"https://attacker.com@{original_parsed.netloc}"),
        ("null_byte", f"{original_redirect}%00.attacker.com"),
        ("param_pollution", f"{original_redirect}&redirect_uri=https://attacker.com"),
    ]

    return {
        "original": original_redirect,
        "test_cases": [{"name": name, "payload": payload} for name, payload in test_cases],
        "parsed": {
            "scheme": original_parsed.scheme,
            "netloc": original_parsed.netloc,
            "path": original_parsed.path,
        },
        "findings": findings,
    }


def _analyze_state_parameter(state: str | None) -> dict[str, Any]:
    """Analyze state parameter for security issues."""
    analysis: dict[str, Any] = {
        "present": state is not None,
        "issues": [],
        "recommendations": [],
    }

    if not state:
        analysis["issues"].append("State parameter missing - CSRF vulnerability")
        analysis["recommendations"].append("Always include a cryptographically random state parameter")
        return analysis

    analysis["value"] = state
    analysis["length"] = len(state)

    # Check for weak state values
    if len(state) < 16:
        analysis["issues"].append("State parameter too short - may be guessable")

    if state.isdigit():
        analysis["issues"].append("State is numeric only - likely predictable")

    if re.match(r"^[a-f0-9]+$", state.lower()) and len(state) == 32:
        analysis["issues"].append("State appears to be MD5 hash - check if predictable input")

    # Check for common weak patterns
    weak_patterns = ["test", "state", "12345", "random", "csrf"]
    if any(pattern in state.lower() for pattern in weak_patterns):
        analysis["issues"].append("State contains common weak pattern")

    if not analysis["issues"]:
        analysis["recommendations"].append("State parameter appears properly random")

    return analysis


def _analyze_pkce(code_challenge: str | None, code_challenge_method: str | None) -> dict[str, Any]:
    """Analyze PKCE implementation."""
    analysis: dict[str, Any] = {
        "pkce_present": code_challenge is not None,
        "issues": [],
        "recommendations": [],
    }

    if not code_challenge:
        analysis["issues"].append("PKCE not implemented - vulnerable to authorization code interception")
        analysis["recommendations"].append("Implement PKCE with S256 method for public clients")
        return analysis

    analysis["code_challenge"] = code_challenge
    analysis["method"] = code_challenge_method

    if code_challenge_method == "plain":
        analysis["issues"].append("PKCE using 'plain' method - no security benefit")
        analysis["recommendations"].append("Use S256 method instead of plain")
    elif code_challenge_method != "S256":
        analysis["issues"].append(f"Unknown PKCE method: {code_challenge_method}")

    # Check challenge length
    if len(code_challenge) < 43:
        analysis["issues"].append("Code challenge may be too short")

    if not analysis["issues"]:
        analysis["recommendations"].append("PKCE implementation appears correct")

    return analysis


def _generate_pkce_pair() -> dict[str, str]:
    """Generate PKCE code verifier and challenge pair."""
    # Generate 32 bytes of random data
    code_verifier = secrets.token_urlsafe(32)

    # Create S256 challenge
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = urlsafe_b64encode(digest).decode().rstrip("=")

    return {
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }


def _analyze_token(token: str) -> dict[str, Any]:
    """Analyze OAuth token structure and properties."""
    analysis: dict[str, Any] = {
        "token": token[:20] + "..." if len(token) > 20 else token,
        "length": len(token),
        "type": "unknown",
        "issues": [],
    }

    # Detect token type
    if token.startswith("eyJ"):
        analysis["type"] = "JWT"
        parts = token.split(".")
        if len(parts) == 3:
            analysis["jwt_parts"] = {
                "header": parts[0],
                "payload": parts[1],
                "signature": parts[2],
            }
            analysis["recommendations"] = ["Verify JWT signature", "Check exp/iat claims"]
    elif token.startswith("ghp_") or token.startswith("gho_"):
        analysis["type"] = "GitHub Token"
    elif token.startswith("sk_") or token.startswith("pk_"):
        analysis["type"] = "Stripe-style Token"
    elif len(token) == 40 and re.match(r"^[a-f0-9]+$", token):
        analysis["type"] = "Possible OAuth 1.0 Token"
    elif len(token) == 64 and re.match(r"^[A-Za-z0-9]+$", token):
        analysis["type"] = "Opaque Bearer Token"

    # Check for issues
    if len(token) < 16:
        analysis["issues"].append("Token unusually short")

    if token.isdigit():
        analysis["issues"].append("Token is numeric - likely predictable")

    return analysis


@register_tool
def oauth_tester(
    action: OAuthTesterAction,
    url: str | None = None,
    redirect_uri: str | None = None,
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    token: str | None = None,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Automated OAuth flow testing for security vulnerabilities.

    This tool analyzes OAuth implementations for common security issues
    including redirect URI validation, state parameter, and PKCE.

    Args:
        action: The testing action to perform:
            - analyze_flow: Analyze complete OAuth authorization URL
            - check_redirect_uri: Test redirect URI validation
            - check_state: Analyze state parameter security
            - check_pkce: Analyze PKCE implementation
            - generate_tests: Generate OAuth security test cases
            - analyze_token: Analyze OAuth token structure
        url: OAuth authorization URL to analyze
        redirect_uri: Redirect URI to test
        state: State parameter value
        code_challenge: PKCE code challenge
        code_challenge_method: PKCE method (plain or S256)
        token: OAuth token to analyze

    Returns:
        Security analysis results with findings and recommendations
    """
    # Define valid parameters and actions
    VALID_PARAMS = {
        "action",
        "url",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "token",
    }
    VALID_ACTIONS = [
        "analyze_flow",
        "check_redirect_uri",
        "check_state",
        "check_pkce",
        "generate_tests",
        "analyze_token",
    ]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "oauth_tester")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "oauth_tester", "analyze_flow", {"url": "https://auth.example.com/authorize?..."}
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "oauth_tester")
    if action_error:
        action_error["usage_examples"] = {
            "analyze_flow": "oauth_tester(action='analyze_flow', url='https://auth.example.com/authorize?...')",
            "check_redirect_uri": "oauth_tester(action='check_redirect_uri', redirect_uri='https://app.com/callback')",
            "check_state": "oauth_tester(action='check_state', state='random_state_value')",
            "check_pkce": "oauth_tester(action='check_pkce', code_challenge='challenge', code_challenge_method='S256')",
            "generate_tests": "oauth_tester(action='generate_tests')",
            "analyze_token": "oauth_tester(action='analyze_token', token='eyJ...')",
        }
        return action_error

    # Validate required parameters based on action
    if action == "analyze_flow":
        param_error = validate_required_param(url, "url", action, "oauth_tester")
        if param_error:
            param_error.update(
                generate_usage_hint(
                    "oauth_tester", action, {"url": "https://auth.example.com/authorize?..."}
                )
            )
            return param_error

    if action == "check_redirect_uri":
        param_error = validate_required_param(redirect_uri, "redirect_uri", action, "oauth_tester")
        if param_error:
            param_error.update(
                generate_usage_hint(
                    "oauth_tester", action, {"redirect_uri": "https://app.com/callback"}
                )
            )
            return param_error

    if action == "analyze_token":
        param_error = validate_required_param(token, "token", action, "oauth_tester")
        if param_error:
            param_error.update(
                generate_usage_hint("oauth_tester", action, {"token": "eyJ..."})
            )
            return param_error

    try:
        if action == "analyze_flow":
            if not url:
                return {"error": "url parameter required"}

            parsed = _parse_oauth_url(url)
            params = parsed["params"]

            analysis: dict[str, Any] = {
                "url_analysis": parsed,
                "flow_type": _detect_flow_type(params),
                "redirect_uri": _analyze_redirect_uri(
                    params.get("redirect_uri", ""),
                    params.get("redirect_uri", ""),
                ) if params.get("redirect_uri") else {"present": False},
                "state": _analyze_state_parameter(params.get("state")),
                "pkce": _analyze_pkce(
                    params.get("code_challenge"),
                    params.get("code_challenge_method"),
                ),
                "scope": params.get("scope", "").split() if params.get("scope") else [],
            }

            # Compile all issues
            all_issues = []
            all_issues.extend(analysis["state"].get("issues", []))
            all_issues.extend(analysis["pkce"].get("issues", []))

            analysis["summary"] = {
                "total_issues": len(all_issues),
                "issues": all_issues,
            }

            return analysis

        if action == "check_redirect_uri":
            if not redirect_uri:
                return {"error": "redirect_uri parameter required"}

            return _analyze_redirect_uri(redirect_uri, redirect_uri)

        if action == "check_state":
            return _analyze_state_parameter(state)

        if action == "check_pkce":
            analysis = _analyze_pkce(code_challenge, code_challenge_method)

            # Generate proper PKCE pair for reference
            if not code_challenge:
                analysis["reference_pkce"] = _generate_pkce_pair()

            return analysis

        if action == "generate_tests":
            tests: list[dict[str, Any]] = []

            # State parameter tests
            tests.append({
                "name": "missing_state",
                "description": "Test OAuth flow without state parameter",
                "vulnerability": "CSRF",
                "payload": "Remove state parameter from authorization request",
            })

            # Redirect URI tests
            redirect_tests = [
                ("Open Redirect - Path Traversal", "redirect_uri=https://legit.com/../attacker.com"),
                ("Open Redirect - Subdomain", "redirect_uri=https://attacker.legit.com"),
                ("Open Redirect - Similar Domain", "redirect_uri=https://legit.com.attacker.com"),
                ("Redirect URI Mismatch", "redirect_uri=https://different-domain.com/callback"),
            ]
            for name, payload in redirect_tests:
                tests.append({
                    "name": name.lower().replace(" ", "_"),
                    "description": name,
                    "vulnerability": "Open Redirect / Token Theft",
                    "payload": payload,
                })

            # PKCE tests
            tests.append({
                "name": "pkce_downgrade",
                "description": "Test if PKCE can be bypassed by omitting code_challenge",
                "vulnerability": "Authorization Code Interception",
                "payload": "Remove code_challenge parameter",
            })

            # Token tests
            tests.append({
                "name": "token_reuse",
                "description": "Test if authorization code can be reused",
                "vulnerability": "Replay Attack",
                "payload": "Submit same authorization code multiple times",
            })

            return {
                "tests": tests,
                "count": len(tests),
                "pkce_pair": _generate_pkce_pair(),
            }

        if action == "analyze_token":
            if not token:
                return {"error": "token parameter required"}

            return _analyze_token(token)

        return {"error": f"Unknown action: {action}"}

    except (TypeError, ValueError, KeyError) as e:
        return {"error": f"OAuth testing failed: {e!s}"}


def _detect_flow_type(params: dict[str, Any]) -> str:
    """Detect OAuth flow type from parameters."""
    response_type = params.get("response_type", "")

    if "code" in response_type and "token" not in response_type:
        return "Authorization Code"
    if "token" in response_type:
        return "Implicit (deprecated)"
    if response_type == "code id_token":
        return "Hybrid (OIDC)"
    if "id_token" in response_type:
        return "OIDC Implicit"

    return "Unknown"
