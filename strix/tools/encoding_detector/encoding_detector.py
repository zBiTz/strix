"""Encoding detection and multi-layer decoding tool."""

import base64
import binascii
import html
import re
import urllib.parse
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "detect_encoding",
    "decode_layers",
    "identify_format",
    "decode_all",
    "encode_payload",
]


def _try_base64_decode(data: str) -> tuple[bool, str]:
    """Try to decode as base64."""
    try:
        # Standard base64
        if re.match(r'^[A-Za-z0-9+/]+=*$', data) and len(data) % 4 == 0:
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            if decoded.isprintable() or any(c.isalnum() for c in decoded):
                return True, decoded
    except Exception:
        pass

    try:
        # URL-safe base64
        if re.match(r'^[A-Za-z0-9_-]+=*$', data):
            decoded = base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='ignore')
            if decoded.isprintable() or any(c.isalnum() for c in decoded):
                return True, decoded
    except Exception:
        pass

    return False, ""


def _try_url_decode(data: str) -> tuple[bool, str]:
    """Try to URL decode."""
    try:
        if '%' in data:
            decoded = urllib.parse.unquote(data)
            if decoded != data:
                return True, decoded
    except Exception:
        pass
    return False, ""


def _try_hex_decode(data: str) -> tuple[bool, str]:
    """Try to decode as hex."""
    try:
        # Remove common prefixes
        clean = data.replace('0x', '').replace('\\x', '').replace(' ', '')
        if re.match(r'^[0-9a-fA-F]+$', clean) and len(clean) % 2 == 0:
            decoded = bytes.fromhex(clean).decode('utf-8', errors='ignore')
            if decoded.isprintable() or any(c.isalnum() for c in decoded):
                return True, decoded
    except Exception:
        pass
    return False, ""


def _try_html_decode(data: str) -> tuple[bool, str]:
    """Try to HTML decode."""
    try:
        if '&' in data and ';' in data:
            decoded = html.unescape(data)
            if decoded != data:
                return True, decoded
    except Exception:
        pass
    return False, ""


def _try_unicode_decode(data: str) -> tuple[bool, str]:
    """Try to decode unicode escapes."""
    try:
        if '\\u' in data or '\\x' in data:
            decoded = data.encode().decode('unicode_escape')
            if decoded != data:
                return True, decoded
    except Exception:
        pass
    return False, ""


@register_tool(sandbox_execution=True)
def encoding_detector(
    action: ToolAction,
    data: str | None = None,
    payload: str | None = None,
    encoding_type: str | None = None,
    max_layers: int | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Encoding detection and multi-layer decoding tool.

    Args:
        action: The action to perform
        data: Data to analyze or decode
        payload: Payload to encode
        encoding_type: Specific encoding type
        max_layers: Maximum decode layers to attempt

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "data", "payload", "encoding_type", "max_layers",
    }
    VALID_ACTIONS = [
        "detect_encoding",
        "decode_layers",
        "identify_format",
        "decode_all",
        "encode_payload",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "encoding_detector"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "encoding_detector"):
        return action_error

    if action == "detect_encoding":
        if param_error := validate_required_param(data, "data", action, "encoding_detector"):
            return param_error

        detections = []

        # Check for base64
        if re.match(r'^[A-Za-z0-9+/]+=*$', data) and len(data) >= 4:
            detections.append({
                "encoding": "base64",
                "confidence": "high" if len(data) % 4 == 0 else "medium",
                "pattern": "Standard base64 alphabet with optional padding",
            })

        # Check for URL encoding
        if re.search(r'%[0-9a-fA-F]{2}', data):
            detections.append({
                "encoding": "url",
                "confidence": "high",
                "pattern": "Contains %XX hex escapes",
            })

        # Check for hex encoding
        if re.match(r'^(0x)?[0-9a-fA-F]+$', data.replace(' ', '')):
            detections.append({
                "encoding": "hex",
                "confidence": "high" if len(data) % 2 == 0 else "medium",
                "pattern": "Hexadecimal characters",
            })

        # Check for HTML entities
        if re.search(r'&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;', data):
            detections.append({
                "encoding": "html",
                "confidence": "high",
                "pattern": "HTML entities (&xxx; or &#xxx;)",
            })

        # Check for unicode escapes
        if re.search(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}', data):
            detections.append({
                "encoding": "unicode_escape",
                "confidence": "high",
                "pattern": "Unicode escape sequences (\\uXXXX or \\xXX)",
            })

        # Check for JWT
        if re.match(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$', data):
            detections.append({
                "encoding": "jwt",
                "confidence": "high",
                "pattern": "JWT format (header.payload.signature)",
            })

        # Check for base32
        if re.match(r'^[A-Z2-7]+=*$', data) and len(data) >= 8:
            detections.append({
                "encoding": "base32",
                "confidence": "medium",
                "pattern": "Base32 alphabet (A-Z, 2-7)",
            })

        return {
            "action": "detect_encoding",
            "input_data": data[:100] + "..." if len(data) > 100 else data,
            "input_length": len(data),
            "detected_encodings": detections,
            "recommendation": detections[0]["encoding"] if detections else "unknown",
        }

    elif action == "decode_layers":
        if param_error := validate_required_param(data, "data", action, "encoding_detector"):
            return param_error

        layers_limit = max_layers or 10
        current = data
        decode_chain = []

        for layer in range(layers_limit):
            decoded = False

            # Try each decoder
            decoders = [
                ("base64", _try_base64_decode),
                ("url", _try_url_decode),
                ("hex", _try_hex_decode),
                ("html", _try_html_decode),
                ("unicode", _try_unicode_decode),
            ]

            for name, decoder in decoders:
                success, result = decoder(current)
                if success and result != current:
                    decode_chain.append({
                        "layer": layer + 1,
                        "encoding": name,
                        "input": current[:50] + "..." if len(current) > 50 else current,
                        "output": result[:50] + "..." if len(result) > 50 else result,
                    })
                    current = result
                    decoded = True
                    break

            if not decoded:
                break

        return {
            "action": "decode_layers",
            "original_data": data[:100] + "..." if len(data) > 100 else data,
            "final_result": current,
            "layers_decoded": len(decode_chain),
            "decode_chain": decode_chain,
            "fully_decoded": len(decode_chain) == 0 or (
                not any(decoder(current)[0] for _, decoder in [
                    ("base64", _try_base64_decode),
                    ("url", _try_url_decode),
                    ("hex", _try_hex_decode),
                ])
            ),
        }

    elif action == "identify_format":
        if param_error := validate_required_param(data, "data", action, "encoding_detector"):
            return param_error

        formats_detected = []

        # JWT
        if re.match(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$', data):
            formats_detected.append("JWT Token")

        # UUID
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', data, re.I):
            formats_detected.append("UUID")

        # Email
        if re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', data):
            formats_detected.append("Email Address")

        # IP Address
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', data):
            formats_detected.append("IPv4 Address")

        # Hash formats
        hash_patterns = {
            "MD5": r'^[a-f0-9]{32}$',
            "SHA1": r'^[a-f0-9]{40}$',
            "SHA256": r'^[a-f0-9]{64}$',
            "SHA512": r'^[a-f0-9]{128}$',
            "bcrypt": r'^\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}$',
            "NTLM": r'^[a-f0-9]{32}$',
        }
        for hash_name, pattern in hash_patterns.items():
            if re.match(pattern, data, re.I):
                formats_detected.append(f"{hash_name} Hash")

        # API Key patterns
        if re.match(r'^(sk|pk|api|key)[-_][a-zA-Z0-9]{20,}$', data, re.I):
            formats_detected.append("API Key")

        # AWS patterns
        if re.match(r'^AKIA[0-9A-Z]{16}$', data):
            formats_detected.append("AWS Access Key ID")

        # Credit card (basic pattern)
        if re.match(r'^[0-9]{13,19}$', data.replace(' ', '').replace('-', '')):
            formats_detected.append("Possible Credit Card Number")

        return {
            "action": "identify_format",
            "input_data": data,
            "formats_detected": formats_detected if formats_detected else ["Unknown format"],
            "is_sensitive": any(
                x in formats_detected for x in
                ["AWS Access Key ID", "API Key", "Possible Credit Card Number"]
            ),
        }

    elif action == "decode_all":
        if param_error := validate_required_param(data, "data", action, "encoding_detector"):
            return param_error

        results = {}

        # Try all decodings
        success, result = _try_base64_decode(data)
        if success:
            results["base64"] = result

        success, result = _try_url_decode(data)
        if success:
            results["url"] = result

        success, result = _try_hex_decode(data)
        if success:
            results["hex"] = result

        success, result = _try_html_decode(data)
        if success:
            results["html"] = result

        success, result = _try_unicode_decode(data)
        if success:
            results["unicode"] = result

        # Try base32
        try:
            if re.match(r'^[A-Z2-7]+=*$', data):
                result = base64.b32decode(data).decode('utf-8', errors='ignore')
                if result.isprintable():
                    results["base32"] = result
        except Exception:
            pass

        # Try ROT13
        try:
            import codecs
            rot13_result = codecs.decode(data, 'rot_13')
            if rot13_result != data:
                results["rot13"] = rot13_result
        except Exception:
            pass

        return {
            "action": "decode_all",
            "input_data": data,
            "successful_decodings": results,
            "decoding_count": len(results),
        }

    elif action == "encode_payload":
        if param_error := validate_required_param(payload, "payload", action, "encoding_detector"):
            return param_error

        enc_type = encoding_type or "all"

        encodings = {}

        # Base64
        encodings["base64"] = base64.b64encode(payload.encode()).decode()
        encodings["base64_urlsafe"] = base64.urlsafe_b64encode(payload.encode()).decode()

        # URL encoding
        encodings["url"] = urllib.parse.quote(payload)
        encodings["url_full"] = urllib.parse.quote(payload, safe='')
        encodings["url_double"] = urllib.parse.quote(urllib.parse.quote(payload))

        # Hex
        encodings["hex"] = payload.encode().hex()
        encodings["hex_0x"] = ''.join(f'\\x{ord(c):02x}' for c in payload)

        # HTML entities
        encodings["html"] = html.escape(payload)
        encodings["html_numeric"] = ''.join(f'&#{ord(c)};' for c in payload)
        encodings["html_hex"] = ''.join(f'&#x{ord(c):x};' for c in payload)

        # Unicode escapes
        encodings["unicode_escape"] = payload.encode('unicode_escape').decode()
        encodings["unicode_js"] = ''.join(f'\\u{ord(c):04x}' for c in payload)

        # Base32
        encodings["base32"] = base64.b32encode(payload.encode()).decode()

        if enc_type != "all":
            if enc_type in encodings:
                return {
                    "action": "encode_payload",
                    "original": payload,
                    "encoding": enc_type,
                    "result": encodings[enc_type],
                }
            else:
                return {"error": f"Unknown encoding type: {enc_type}"}

        return {
            "action": "encode_payload",
            "original": payload,
            "encodings": encodings,
            "waf_bypass_suggestions": [
                f"Double URL: {encodings['url_double']}",
                f"Mixed case hex: {payload.encode().hex().upper()}",
                f"Unicode: {encodings['unicode_js']}",
            ],
        }

    return generate_usage_hint("encoding_detector", VALID_ACTIONS)
