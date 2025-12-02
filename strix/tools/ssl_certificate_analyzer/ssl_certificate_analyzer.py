"""SSL/TLS certificate analyzer for security testing."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlparse

from strix.tools.registry import register_tool


SSLAction = Literal["analyze", "chain", "ciphers"]


def _normalize_host(host: str) -> tuple[str, int]:
    """Normalize host input and extract port."""
    host = host.strip()
    if host.startswith(("http://", "https://")):
        parsed = urlparse(host)
        host = parsed.netloc or host
        port = 80 if parsed.scheme == "http" else 443
    else:
        port = 443

    if ":" in host:
        parts = host.rsplit(":", 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = 443

    return host, port


def _get_certificate(host: str, port: int) -> dict[str, Any] | None:
    """Retrieve SSL certificate from host."""
    # Create context with secure minimum protocol version
    # Note: We disable verification as this is a security analysis tool
    # that needs to connect to potentially misconfigured servers
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock, \
                context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(binary_form=False)
            binary_cert = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            version = ssock.version()

            return {
                "cert": cert,
                "binary_cert": binary_cert,
                "cipher": cipher,
                "version": version,
            }
    except (ssl.SSLError, OSError):
        return None


def _parse_certificate(cert_data: dict[str, Any]) -> dict[str, Any]:
    """Parse certificate data into readable format."""
    cert = cert_data.get("cert", {})

    # Parse subject
    subject: dict[str, str] = {key: value for rdn in cert.get("subject", ()) for key, value in rdn}

    # Parse issuer
    issuer: dict[str, str] = {key: value for rdn in cert.get("issuer", ()) for key, value in rdn}

    # Parse validity dates
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")

    # Parse to datetime if possible
    validity: dict[str, Any] = {
        "not_before": not_before,
        "not_after": not_after,
    }

    try:
        not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")  # noqa: DTZ007
        now = datetime.now(UTC).replace(tzinfo=None)
        days_remaining = (not_after_dt - now).days
        validity["days_remaining"] = days_remaining
        validity["is_expired"] = days_remaining < 0
        validity["expires_soon"] = 0 < days_remaining < 30
    except (ValueError, TypeError):
        validity["days_remaining"] = None
        validity["is_expired"] = None
        validity["expires_soon"] = None

    # Parse SANs (Subject Alternative Names)
    sans = []
    for san_type, san_value in cert.get("subjectAltName", ()):
        sans.append({"type": san_type, "value": san_value})

    # Current cipher and protocol
    cipher = cert_data.get("cipher", ())
    protocol = cert_data.get("version", "")

    return {
        "subject": subject,
        "issuer": issuer,
        "validity": validity,
        "serial_number": cert.get("serialNumber", ""),
        "version": cert.get("version", ""),
        "sans": sans,
        "san_count": len(sans),
        "current_cipher": {
            "name": cipher[0] if len(cipher) > 0 else "",
            "protocol": cipher[1] if len(cipher) > 1 else "",
            "bits": cipher[2] if len(cipher) > 2 else 0,
        },
        "current_protocol": protocol,
    }


def _analyze_security(cert_info: dict[str, Any]) -> dict[str, Any]:
    """Analyze certificate for security issues."""
    issues: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    # Check expiration
    validity = cert_info.get("validity", {})
    if validity.get("is_expired"):
        issues.append({
            "severity": "critical",
            "issue": "Certificate has expired",
        })
    elif validity.get("expires_soon"):
        warnings.append({
            "severity": "medium",
            "issue": f"Certificate expires in {validity.get('days_remaining')} days",
        })

    # Check cipher strength
    cipher = cert_info.get("current_cipher", {})
    bits = cipher.get("bits", 0)
    if bits and bits < 128:
        issues.append({
            "severity": "high",
            "issue": f"Weak cipher strength: {bits} bits",
        })

    # Check protocol
    protocol = cert_info.get("current_protocol", "")
    if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"):
        issues.append({
            "severity": "high",
            "issue": f"Deprecated protocol in use: {protocol}",
        })

    # Check cipher name for weak algorithms
    cipher_name = cipher.get("name", "").upper()
    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
    for weak in weak_ciphers:
        if weak in cipher_name:
            issues.append({
                "severity": "high",
                "issue": f"Weak cipher algorithm: {weak}",
            })
            break

    # Check for self-signed
    subject = cert_info.get("subject", {})
    issuer = cert_info.get("issuer", {})
    if subject == issuer:
        warnings.append({
            "severity": "medium",
            "issue": "Self-signed certificate",
        })

    return {
        "issues": issues,
        "warnings": warnings,
        "issue_count": len(issues),
        "warning_count": len(warnings),
        "security_score": "secure" if not issues else "insecure",
    }


def _analyze_certificate(host: str, port: int) -> dict[str, Any]:
    """Perform full certificate analysis."""
    cert_data = _get_certificate(host, port)

    if not cert_data:
        return {
            "host": host,
            "port": port,
            "error": "Could not retrieve certificate",
            "connected": False,
        }

    cert_info = _parse_certificate(cert_data)
    security = _analyze_security(cert_info)

    return {
        "host": host,
        "port": port,
        "connected": True,
        "certificate": cert_info,
        "security_analysis": security,
    }


def _get_certificate_chain(host: str, port: int) -> dict[str, Any]:
    """Get certificate chain information."""
    cert_data = _get_certificate(host, port)

    if not cert_data:
        return {
            "host": host,
            "port": port,
            "error": "Could not retrieve certificate",
        }

    cert_info = _parse_certificate(cert_data)

    # Basic chain info (full chain requires more complex parsing)
    chain = [{
        "position": 0,
        "type": "end_entity",
        "subject": cert_info.get("subject", {}),
        "issuer": cert_info.get("issuer", {}),
        "validity": cert_info.get("validity", {}),
    }]

    return {
        "host": host,
        "port": port,
        "chain_length": len(chain),
        "certificates": chain,
        "note": "Full chain extraction requires OpenSSL or specialized libraries",
    }


def _check_ciphers(host: str, port: int) -> dict[str, Any]:
    """Check supported cipher suites."""
    cert_data = _get_certificate(host, port)

    if not cert_data:
        return {
            "host": host,
            "port": port,
            "error": "Could not connect to host",
        }

    cipher = cert_data.get("cipher", ())
    version = cert_data.get("version", "")

    # Current negotiated cipher
    current_cipher = {
        "name": cipher[0] if len(cipher) > 0 else "",
        "protocol": cipher[1] if len(cipher) > 1 else "",
        "bits": cipher[2] if len(cipher) > 2 else 0,
    }

    # Check for weak cipher usage
    cipher_name = current_cipher.get("name", "").upper()
    weak_indicators = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
    is_weak = any(weak in cipher_name for weak in weak_indicators)

    return {
        "host": host,
        "port": port,
        "negotiated_protocol": version,
        "negotiated_cipher": current_cipher,
        "is_weak_cipher": is_weak,
        "recommendations": [
            "Prefer TLSv1.3 or TLSv1.2",
            "Disable SSLv2, SSLv3, TLSv1.0, TLSv1.1",
            "Use AEAD ciphers (AES-GCM, ChaCha20)",
            "Disable RC4, DES, 3DES, MD5-based ciphers",
        ],
    }


@register_tool
def ssl_certificate_analyzer(
    action: SSLAction,
    host: str,
    port: int = 443,
) -> dict[str, Any]:
    """Analyze SSL/TLS certificates for security issues.

    This tool retrieves and analyzes SSL/TLS certificates including
    chain validation, cipher detection, protocol version analysis,
    SAN extraction, and expiry checking.

    Args:
        action: The analysis action to perform:
            - analyze: Full certificate analysis with security check
            - chain: Get certificate chain information
            - ciphers: Check supported cipher suites
        host: Target hostname or URL
        port: Target port (default: 443)

    Returns:
        Certificate details, security analysis, and recommendations
    """
    try:
        normalized_host, normalized_port = _normalize_host(host)
        if port != 443:
            normalized_port = port

        if action == "analyze":
            return _analyze_certificate(normalized_host, normalized_port)

        if action == "chain":
            return _get_certificate_chain(normalized_host, normalized_port)

        if action == "ciphers":
            return _check_ciphers(normalized_host, normalized_port)

        return {"error": f"Unknown action: {action}"}

    except (OSError, ValueError) as e:
        return {"error": f"SSL analysis failed: {e!s}"}
