"""Payload Encoder tool for multi-layer encoding and WAF bypass."""

from __future__ import annotations

import base64
import html
import urllib.parse
from typing import Any, Literal

from strix.tools.registry import register_tool


PayloadEncoderAction = Literal["encode", "decode", "multi_encode", "generate_bypass"]


def _url_encode(payload: str, double: bool = False) -> str:
    """URL encode a payload."""
    encoded = urllib.parse.quote(payload, safe="")
    if double:
        encoded = urllib.parse.quote(encoded, safe="")
    return encoded


def _url_decode(payload: str) -> str:
    """URL decode a payload."""
    return urllib.parse.unquote(payload)


def _html_encode(payload: str, mode: str = "decimal") -> str:
    """HTML encode a payload."""
    if mode == "named":
        return html.escape(payload)
    if mode == "decimal":
        return "".join(f"&#{ord(c)};" for c in payload)
    if mode == "hex":
        return "".join(f"&#x{ord(c):x};" for c in payload)
    return html.escape(payload)


def _html_decode(payload: str) -> str:
    """HTML decode a payload."""
    return html.unescape(payload)


def _base64_encode(payload: str) -> str:
    """Base64 encode a payload."""
    return base64.b64encode(payload.encode()).decode()


def _base64_decode(payload: str) -> str:
    """Base64 decode a payload."""
    # Add padding if needed
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    return base64.b64decode(payload).decode()


def _unicode_encode(payload: str, mode: str = "standard") -> str:
    """Unicode encode a payload."""
    if mode == "standard":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    if mode == "wide":
        return "".join(f"%u{ord(c):04X}" for c in payload)
    if mode == "utf8":
        return "".join(f"\\x{b:02x}" for b in payload.encode("utf-8"))
    return payload


def _hex_encode(payload: str) -> str:
    """Hex encode a payload."""
    return payload.encode().hex()


def _hex_decode(payload: str) -> str:
    """Hex decode a payload."""
    return bytes.fromhex(payload).decode()


def _octal_encode(payload: str) -> str:
    """Octal encode a payload."""
    return "".join(f"\\{ord(c):03o}" for c in payload)


def _generate_bypass_variants(payload: str) -> list[dict[str, str]]:
    """Generate WAF bypass variants of a payload."""
    variants: list[dict[str, str]] = []

    # Original
    variants.append({"type": "original", "payload": payload})

    # URL encoding variants
    variants.append({"type": "url_encoded", "payload": _url_encode(payload)})
    variants.append({"type": "double_url_encoded", "payload": _url_encode(payload, double=True)})

    # HTML encoding variants
    variants.append({"type": "html_decimal", "payload": _html_encode(payload, "decimal")})
    variants.append({"type": "html_hex", "payload": _html_encode(payload, "hex")})

    # Unicode variants
    variants.append({"type": "unicode", "payload": _unicode_encode(payload)})
    variants.append({"type": "unicode_wide", "payload": _unicode_encode(payload, "wide")})

    # Mixed case for keyword bypasses
    if any(c.isalpha() for c in payload):
        mixed = "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )
        variants.append({"type": "mixed_case", "payload": mixed})

    # Null byte injection
    variants.append({"type": "null_byte", "payload": payload.replace(" ", "%00")})

    # Tab/newline bypass
    for tag in ["script", "img", "svg", "body", "iframe"]:
        if tag in payload.lower():
            # Insert newlines/tabs within tags
            bypassed = payload.replace(f"<{tag}", f"<{tag}\n")
            variants.append({"type": "newline_injection", "payload": bypassed})
            bypassed = payload.replace(f"<{tag}", f"<{tag}\t")
            variants.append({"type": "tab_injection", "payload": bypassed})
            break

    # Comment injection for SQL
    if "select" in payload.lower() or "union" in payload.lower():
        # Inline comments
        variants.append({
            "type": "sql_comment",
            "payload": payload.replace(" ", "/**/"),
        })

    # Base64 for eval-based contexts
    b64_payload = _base64_encode(payload)
    variants.append({
        "type": "base64",
        "payload": f"eval(atob('{b64_payload}'))",
    })

    # Concatenation bypass
    if "alert" in payload.lower():
        variants.append({
            "type": "concatenation",
            "payload": payload.replace("alert", "al"+"ert").replace("'", "'+'"),
        })

    return variants


ENCODING_FUNCTIONS: dict[str, tuple[Any, Any]] = {
    "url": (_url_encode, _url_decode),
    "html": (_html_encode, _html_decode),
    "base64": (_base64_encode, _base64_decode),
    "hex": (_hex_encode, _hex_decode),
    "unicode": (_unicode_encode, None),
    "octal": (_octal_encode, None),
}


@register_tool
def payload_encoder(
    action: PayloadEncoderAction,
    payload: str,
    encoding: str | None = None,
    encodings: list[str] | None = None,
    decode: bool = False,
) -> dict[str, Any]:
    """Multi-layer encoding with WAF bypass transformations.

    This tool provides various encoding methods for payloads,
    useful for bypassing WAFs and security filters.

    Args:
        action: The encoding action to perform:
            - encode: Apply single encoding
            - decode: Decode a payload
            - multi_encode: Apply multiple encodings in sequence
            - generate_bypass: Generate WAF bypass variants
        payload: The payload to encode/decode
        encoding: Encoding type (url, html, base64, hex, unicode, octal)
        encodings: List of encodings for multi_encode (applied in order)
        decode: Whether to decode instead of encode (for single encoding)

    Returns:
        Encoded payload(s) and transformation details
    """
    try:
        if action == "encode":
            if not encoding:
                return {"error": "encoding parameter required"}

            if encoding not in ENCODING_FUNCTIONS:
                return {
                    "error": f"Unknown encoding: {encoding}",
                    "available": list(ENCODING_FUNCTIONS.keys()),
                }

            encode_fn, decode_fn = ENCODING_FUNCTIONS[encoding]

            if decode:
                if decode_fn is None:
                    return {"error": f"Decoding not supported for {encoding}"}
                result = decode_fn(payload)
            else:
                result = encode_fn(payload)

            return {
                "original": payload,
                "encoded": result,
                "encoding": encoding,
                "operation": "decode" if decode else "encode",
            }

        if action == "decode":
            if not encoding:
                # Try to auto-detect encoding
                results: dict[str, str] = {}
                for enc_name, (_, decode_fn) in ENCODING_FUNCTIONS.items():
                    if decode_fn:
                        try:
                            results[enc_name] = decode_fn(payload)
                        except (ValueError, UnicodeDecodeError, base64.binascii.Error):
                            # Expected: not all encodings will decode a given payload successfully.
                            # Silently skip failed decodings and continue trying other formats.
                            pass

                return {
                    "original": payload,
                    "decoded_attempts": results,
                    "note": "Multiple decodings attempted, verify correct result",
                }

            if encoding not in ENCODING_FUNCTIONS:
                return {"error": f"Unknown encoding: {encoding}"}

            _, decode_fn = ENCODING_FUNCTIONS[encoding]
            if decode_fn is None:
                return {"error": f"Decoding not supported for {encoding}"}

            result = decode_fn(payload)
            return {
                "original": payload,
                "decoded": result,
                "encoding": encoding,
            }

        if action == "multi_encode":
            if not encodings:
                return {"error": "encodings list required"}

            current = payload
            chain: list[dict[str, str]] = [{"step": 0, "encoding": "original", "value": payload}]

            for i, enc in enumerate(encodings, 1):
                if enc not in ENCODING_FUNCTIONS:
                    return {"error": f"Unknown encoding at step {i}: {enc}"}

                encode_fn, _ = ENCODING_FUNCTIONS[enc]
                current = encode_fn(current)
                chain.append({"step": i, "encoding": enc, "value": current})

            return {
                "original": payload,
                "final": current,
                "encoding_chain": encodings,
                "steps": chain,
            }

        if action == "generate_bypass":
            variants = _generate_bypass_variants(payload)
            return {
                "original": payload,
                "variants": variants,
                "count": len(variants),
                "note": "Test each variant against target WAF/filter",
            }

        return {"error": f"Unknown action: {action}"}

    except (TypeError, ValueError, UnicodeDecodeError) as e:
        return {"error": f"Encoding/decoding failed: {e!s}"}
