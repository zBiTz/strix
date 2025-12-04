"""Hash Identifier tool for identifying hash types."""

from __future__ import annotations

import re
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


HashIdentifierAction = Literal["identify", "analyze", "suggest_crack"]


# Hash patterns and characteristics
HASH_PATTERNS: dict[str, dict[str, Any]] = {
    "md5": {
        "length": 32,
        "pattern": r"^[a-fA-F0-9]{32}$",
        "description": "MD5 - Message Digest 5",
        "security": "weak",
        "crackable": True,
        "tools": ["hashcat -m 0", "john --format=raw-md5"],
    },
    "md5_salted": {
        "length": 32,
        "pattern": r"^[a-fA-F0-9]{32}:[a-zA-Z0-9+/=]+$",
        "description": "MD5 with salt",
        "security": "weak",
        "crackable": True,
        "tools": ["hashcat -m 10", "john --format=md5s"],
    },
    "sha1": {
        "length": 40,
        "pattern": r"^[a-fA-F0-9]{40}$",
        "description": "SHA-1 - Secure Hash Algorithm 1",
        "security": "weak",
        "crackable": True,
        "tools": ["hashcat -m 100", "john --format=raw-sha1"],
    },
    "sha256": {
        "length": 64,
        "pattern": r"^[a-fA-F0-9]{64}$",
        "description": "SHA-256 - Secure Hash Algorithm 256",
        "security": "moderate",
        "crackable": True,
        "tools": ["hashcat -m 1400", "john --format=raw-sha256"],
    },
    "sha384": {
        "length": 96,
        "pattern": r"^[a-fA-F0-9]{96}$",
        "description": "SHA-384 - Secure Hash Algorithm 384",
        "security": "strong",
        "crackable": True,
        "tools": ["hashcat -m 10800", "john --format=raw-sha384"],
    },
    "sha512": {
        "length": 128,
        "pattern": r"^[a-fA-F0-9]{128}$",
        "description": "SHA-512 - Secure Hash Algorithm 512",
        "security": "strong",
        "crackable": True,
        "tools": ["hashcat -m 1700", "john --format=raw-sha512"],
    },
    "bcrypt": {
        "length": 60,
        "pattern": r"^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$",
        "description": "bcrypt - Blowfish-based adaptive hash",
        "security": "strong",
        "crackable": True,
        "tools": ["hashcat -m 3200", "john --format=bcrypt"],
    },
    "scrypt": {
        "pattern": r"^\$s0\$",
        "description": "scrypt - Memory-hard hash function",
        "security": "strong",
        "crackable": True,
        "tools": ["hashcat -m 8900", "john --format=scrypt"],
    },
    "argon2": {
        "pattern": r"^\$argon2(i|d|id)\$",
        "description": "Argon2 - Password Hashing Competition winner",
        "security": "very_strong",
        "crackable": True,
        "tools": ["hashcat -m 32500", "john --format=argon2"],
    },
    "pbkdf2_sha256": {
        "pattern": r"^\$pbkdf2-sha256\$",
        "description": "PBKDF2-SHA256 - Password-Based Key Derivation Function 2",
        "security": "strong",
        "crackable": True,
        "tools": ["hashcat -m 10900", "john --format=pbkdf2-hmac-sha256"],
    },
    "django_pbkdf2": {
        "pattern": r"^pbkdf2_sha256\$\d+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$",
        "description": "Django PBKDF2-SHA256",
        "security": "strong",
        "crackable": True,
        "tools": ["hashcat -m 10000", "john --format=django"],
    },
    "mysql_native": {
        "length": 41,
        "pattern": r"^\*[A-F0-9]{40}$",
        "description": "MySQL 4.1+ native password",
        "security": "weak",
        "crackable": True,
        "tools": ["hashcat -m 300", "john --format=mysql-sha1"],
    },
    "mysql_old": {
        "length": 16,
        "pattern": r"^[a-fA-F0-9]{16}$",
        "description": "MySQL < 4.1 (old password)",
        "security": "very_weak",
        "crackable": True,
        "tools": ["hashcat -m 200", "john --format=mysql"],
    },
    "mssql_2005": {
        "pattern": r"^0x0100[a-fA-F0-9]{48}$",
        "description": "MSSQL 2005",
        "security": "weak",
        "crackable": True,
        "tools": ["hashcat -m 131", "john --format=mssql05"],
    },
    "mssql_2012": {
        "pattern": r"^0x0200[a-fA-F0-9]{136}$",
        "description": "MSSQL 2012/2014",
        "security": "moderate",
        "crackable": True,
        "tools": ["hashcat -m 1731", "john --format=mssql12"],
    },
    "oracle_11g": {
        "pattern": r"^S:[A-F0-9]{60}$",
        "description": "Oracle 11g",
        "security": "moderate",
        "crackable": True,
        "tools": ["hashcat -m 112", "john --format=oracle11"],
    },
    "ntlm": {
        "length": 32,
        "pattern": r"^[a-fA-F0-9]{32}$",
        "description": "NTLM (Windows)",
        "security": "weak",
        "crackable": True,
        "tools": ["hashcat -m 1000", "john --format=nt"],
    },
    "lm": {
        "length": 32,
        "pattern": r"^[a-fA-F0-9]{32}$",
        "description": "LM Hash (Legacy Windows)",
        "security": "very_weak",
        "crackable": True,
        "tools": ["hashcat -m 3000", "john --format=lm"],
    },
    "sha256_crypt": {
        "pattern": r"^\$5\$",
        "description": "SHA-256 Unix Crypt",
        "security": "strong",
        "crackable": True,
        "tools": ["hashcat -m 7400", "john --format=sha256crypt"],
    },
    "sha512_crypt": {
        "pattern": r"^\$6\$",
        "description": "SHA-512 Unix Crypt",
        "security": "strong",
        "crackable": True,
        "tools": ["hashcat -m 1800", "john --format=sha512crypt"],
    },
    "md5_crypt": {
        "pattern": r"^\$1\$",
        "description": "MD5 Unix Crypt",
        "security": "weak",
        "crackable": True,
        "tools": ["hashcat -m 500", "john --format=md5crypt"],
    },
    "des_crypt": {
        "length": 13,
        "pattern": r"^[./A-Za-z0-9]{13}$",
        "description": "DES Unix Crypt",
        "security": "very_weak",
        "crackable": True,
        "tools": ["hashcat -m 1500", "john --format=descrypt"],
    },
    "jwt": {
        "pattern": r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$",
        "description": "JWT Token (not a hash, but identifiable)",
        "security": "varies",
        "crackable": True,
        "tools": ["hashcat -m 16500", "jwt_tool"],
    },
    "wordpress": {
        "pattern": r"^\$P\$[./A-Za-z0-9]{31}$",
        "description": "WordPress (PHPass)",
        "security": "moderate",
        "crackable": True,
        "tools": ["hashcat -m 400", "john --format=phpass"],
    },
    "drupal7": {
        "pattern": r"^\$S\$[A-Za-z0-9./]{52}$",
        "description": "Drupal 7",
        "security": "moderate",
        "crackable": True,
        "tools": ["hashcat -m 7900", "john --format=drupal7"],
    },
}


def _identify_hash(hash_value: str) -> list[dict[str, Any]]:
    """Identify possible hash types."""
    matches: list[dict[str, Any]] = []
    cleaned_hash = hash_value.strip()

    for hash_type, properties in HASH_PATTERNS.items():
        pattern = properties.get("pattern")
        length = properties.get("length")

        # Check pattern match
        if pattern and re.match(pattern, cleaned_hash):
            confidence = "high"
            matches.append({
                "type": hash_type,
                "description": properties["description"],
                "security": properties["security"],
                "confidence": confidence,
                "tools": properties.get("tools", []),
            })
        # Check length match for hex hashes without specific patterns
        elif length and len(cleaned_hash) == length and re.match(r"^[a-fA-F0-9]+$", cleaned_hash):
            # Length matches but could be multiple types
            confidence = "medium"
            matches.append({
                "type": hash_type,
                "description": properties["description"],
                "security": properties["security"],
                "confidence": confidence,
                "tools": properties.get("tools", []),
            })

    # Sort by confidence
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    matches.sort(key=lambda x: confidence_order.get(x["confidence"], 3))

    return matches


def _analyze_hash(hash_value: str) -> dict[str, Any]:
    """Analyze hash characteristics."""
    cleaned_hash = hash_value.strip()

    analysis: dict[str, Any] = {
        "original": hash_value,
        "length": len(cleaned_hash),
        "characteristics": [],
    }

    # Check character set
    if re.match(r"^[a-f0-9]+$", cleaned_hash):
        analysis["charset"] = "lowercase_hex"
    elif re.match(r"^[A-F0-9]+$", cleaned_hash):
        analysis["charset"] = "uppercase_hex"
    elif re.match(r"^[a-fA-F0-9]+$", cleaned_hash):
        analysis["charset"] = "mixed_hex"
    elif re.match(r"^[A-Za-z0-9+/=]+$", cleaned_hash):
        analysis["charset"] = "base64"
    elif re.match(r"^[A-Za-z0-9./]+$", cleaned_hash):
        analysis["charset"] = "crypt_base64"
    else:
        analysis["charset"] = "mixed"

    # Check for common prefixes
    prefixes = {
        "$1$": "MD5 Crypt",
        "$2a$": "bcrypt (2a)",
        "$2b$": "bcrypt (2b)",
        "$2y$": "bcrypt (2y)",
        "$5$": "SHA-256 Crypt",
        "$6$": "SHA-512 Crypt",
        "$argon2": "Argon2",
        "$pbkdf2": "PBKDF2",
        "$P$": "PHPass",
        "$S$": "Drupal",
        "*": "MySQL",
        "0x": "MSSQL",
    }

    for prefix, name in prefixes.items():
        if cleaned_hash.startswith(prefix):
            analysis["prefix"] = prefix
            analysis["characteristics"].append(f"Starts with {name} identifier")
            break

    # Length-based characteristics
    length_hints = {
        16: "Could be: MD5 half, MySQL old, LM half",
        32: "Could be: MD5, NTLM, LM",
        40: "Could be: SHA-1, MySQL native (with *)",
        56: "Could be: SHA-224",
        64: "Could be: SHA-256, SHA3-256",
        96: "Could be: SHA-384",
        128: "Could be: SHA-512, SHA3-512",
    }

    if analysis["length"] in length_hints:
        analysis["length_hint"] = length_hints[analysis["length"]]

    return analysis


def _get_crack_suggestions(hash_type: str, security: str) -> dict[str, Any]:
    """Get cracking suggestions for a hash type."""
    suggestions: dict[str, Any] = {
        "hash_type": hash_type,
        "security_level": security,
        "approaches": [],
    }

    if security in ["very_weak", "weak"]:
        suggestions["approaches"].append({
            "method": "dictionary_attack",
            "description": "Use common password lists (rockyou.txt)",
            "success_rate": "high",
        })
        suggestions["approaches"].append({
            "method": "brute_force",
            "description": "Feasible for passwords up to 8-10 characters",
            "success_rate": "medium",
        })
        suggestions["approaches"].append({
            "method": "rainbow_tables",
            "description": "Pre-computed tables may exist",
            "success_rate": "high",
        })

    elif security == "moderate":
        suggestions["approaches"].append({
            "method": "dictionary_attack",
            "description": "Use targeted wordlists with rules",
            "success_rate": "medium",
        })
        suggestions["approaches"].append({
            "method": "hybrid_attack",
            "description": "Dictionary + mask attacks",
            "success_rate": "medium",
        })

    elif security in ["strong", "very_strong"]:
        suggestions["approaches"].append({
            "method": "targeted_dictionary",
            "description": "Use targeted wordlist based on user info",
            "success_rate": "low",
        })
        suggestions["approaches"].append({
            "method": "rule_based",
            "description": "Dictionary with extensive rule sets",
            "success_rate": "low",
        })
        suggestions["time_estimate"] = "Hours to days for weak passwords, infeasible for strong ones"

    return suggestions


@register_tool
def hash_identifier(
    action: HashIdentifierAction,
    hash_value: str,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Identify hash types and suggest cracking approaches.

    This tool analyzes hash values to identify their type and provides
    recommendations for cracking approaches.

    Args:
        action: The identification action:
            - identify: Identify possible hash types
            - analyze: Analyze hash characteristics
            - suggest_crack: Get cracking suggestions
        hash_value: The hash value to analyze

    Returns:
        Hash identification results with type matches and cracking suggestions
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "hash_value"}
    VALID_ACTIONS = ["identify", "analyze", "suggest_crack"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "hash_identifier")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "hash_identifier",
                "identify",
                {"hash_value": "5f4dcc3b5aa765d61d8327deb882cf99"},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "hash_identifier")
    if action_error:
        action_error["usage_examples"] = {
            "identify": "hash_identifier(action='identify', hash_value='5f4dcc3b5aa765d61d8327deb882cf99')",
            "analyze": "hash_identifier(action='analyze', hash_value='$2a$10$...')",
            "suggest_crack": "hash_identifier(action='suggest_crack', hash_value='$6$...')",
        }
        return action_error

    # Validate required parameters
    hash_error = validate_required_param(hash_value, "hash_value", action, "hash_identifier")
    if hash_error:
        hash_error.update(
            generate_usage_hint(
                "hash_identifier",
                action,
                {"hash_value": "5f4dcc3b5aa765d61d8327deb882cf99"},
            )
        )
        return hash_error

    try:
        if not hash_value:
            return {"error": "hash_value parameter required"}

        if action == "identify":
            matches = _identify_hash(hash_value)

            if not matches:
                return {
                    "hash": hash_value[:50] + "..." if len(hash_value) > 50 else hash_value,
                    "matches": [],
                    "message": "No matching hash type found",
                    "analysis": _analyze_hash(hash_value),
                }

            return {
                "hash": hash_value[:50] + "..." if len(hash_value) > 50 else hash_value,
                "matches": matches,
                "most_likely": matches[0] if matches else None,
                "match_count": len(matches),
            }

        if action == "analyze":
            analysis = _analyze_hash(hash_value)
            matches = _identify_hash(hash_value)
            analysis["possible_types"] = [m["type"] for m in matches]
            return analysis

        if action == "suggest_crack":
            matches = _identify_hash(hash_value)

            if not matches:
                return {
                    "error": "Could not identify hash type",
                    "suggestion": "Manually identify hash type for cracking recommendations",
                }

            best_match = matches[0]
            crack_info = _get_crack_suggestions(
                best_match["type"],
                best_match["security"],
            )
            crack_info["tools"] = best_match.get("tools", [])

            return {
                "identified_as": best_match["type"],
                "description": best_match["description"],
                "cracking_info": crack_info,
            }

        return {"error": f"Unknown action: {action}"}

    except (TypeError, ValueError, re.error) as e:
        return {"error": f"Hash identification failed: {e!s}"}
