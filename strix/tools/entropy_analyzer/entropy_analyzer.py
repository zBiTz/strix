"""Entropy analyzer for token randomness and predictability testing."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Literal

from strix.tools.registry import register_tool


EntropyAction = Literal["analyze", "compare", "batch_analyze"]


def _calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def _calculate_min_entropy(data: str) -> float:
    """Calculate min-entropy (worst-case entropy)."""
    if not data:
        return 0.0
    
    counter = Counter(data)
    max_probability = max(counter.values()) / len(data)
    
    if max_probability == 0:
        return 0.0
    
    return -math.log2(max_probability)


def _analyze_character_distribution(data: str) -> dict[str, Any]:
    """Analyze character type distribution."""
    lowercase = sum(1 for c in data if c.islower())
    uppercase = sum(1 for c in data if c.isupper())
    digits = sum(1 for c in data if c.isdigit())
    special = sum(1 for c in data if not c.isalnum())
    
    total = len(data)
    
    return {
        "lowercase": lowercase,
        "uppercase": uppercase,
        "digits": digits,
        "special": special,
        "total": total,
        "percentages": {
            "lowercase": round(lowercase / total * 100, 2) if total else 0,
            "uppercase": round(uppercase / total * 100, 2) if total else 0,
            "digits": round(digits / total * 100, 2) if total else 0,
            "special": round(special / total * 100, 2) if total else 0
        }
    }


def _detect_patterns(data: str) -> list[dict[str, Any]]:
    """Detect common patterns that reduce entropy."""
    patterns = []
    
    # Sequential characters
    sequential = re.findall(r"(abc|bcd|cde|def|123|234|345|456|567|678|789)", data, re.IGNORECASE)
    if sequential:
        patterns.append({
            "type": "sequential",
            "count": len(sequential),
            "examples": sequential[:3],
            "impact": "Reduces effective entropy, predictable pattern"
        })
    
    # Repeated characters
    repeated = re.findall(r"(.)\1{2,}", data)
    if repeated:
        patterns.append({
            "type": "repeated_characters",
            "count": len(repeated),
            "examples": [f"{c}..." for c in set(repeated)][:3],
            "impact": "Significantly reduces entropy"
        })
    
    # Common words
    common_words = ["password", "admin", "user", "test", "demo", "key", "secret", "token"]
    found_words = [word for word in common_words if word.lower() in data.lower()]
    if found_words:
        patterns.append({
            "type": "common_words",
            "found": found_words,
            "impact": "Highly predictable, dictionary-attackable"
        })
    
    # Date patterns
    dates = re.findall(r"\d{2,4}[-/]\d{1,2}[-/]\d{1,2}|\d{8}", data)
    if dates:
        patterns.append({
            "type": "date_patterns",
            "count": len(dates),
            "examples": dates[:2],
            "impact": "Predictable, reduces search space"
        })
    
    # Hex patterns (lowercase only or uppercase only)
    if re.match(r"^[0-9a-f]+$", data) or re.match(r"^[0-9A-F]+$", data):
        patterns.append({
            "type": "hexadecimal",
            "impact": "Reduced character set (16 instead of 62+)"
        })
    
    return patterns


def _assess_randomness(entropy: float, length: int, char_set_size: int) -> dict[str, Any]:
    """Assess randomness quality and security implications."""
    # Maximum possible entropy for this length and character set
    max_entropy = math.log2(char_set_size) * length if char_set_size > 0 and length > 0 else 0
    
    # Entropy efficiency (how close to theoretical maximum)
    efficiency = (entropy / max_entropy * 100) if max_entropy > 0 else 0
    
    # Security assessment
    if entropy >= 128:
        security_level = "Excellent"
        rating = "Cryptographically secure"
    elif entropy >= 80:
        security_level = "Good"
        rating = "Secure for most purposes"
    elif entropy >= 60:
        security_level = "Adequate"
        rating = "Acceptable but could be stronger"
    elif entropy >= 40:
        security_level = "Weak"
        rating = "Vulnerable to brute force"
    else:
        security_level = "Very Weak"
        rating = "Easily predictable"
    
    # Brute force time estimates (rough estimates)
    attempts_per_second = 1_000_000_000  # 1 billion attempts/sec (GPU)
    total_combinations = 2 ** entropy
    seconds_to_crack = total_combinations / attempts_per_second
    
    if seconds_to_crack < 1:
        crack_time = "Less than 1 second"
    elif seconds_to_crack < 60:
        crack_time = f"{seconds_to_crack:.1f} seconds"
    elif seconds_to_crack < 3600:
        crack_time = f"{seconds_to_crack / 60:.1f} minutes"
    elif seconds_to_crack < 86400:
        crack_time = f"{seconds_to_crack / 3600:.1f} hours"
    elif seconds_to_crack < 31536000:
        crack_time = f"{seconds_to_crack / 86400:.1f} days"
    else:
        years = seconds_to_crack / 31536000
        if years > 1_000_000:
            crack_time = f"{years:.1e} years (effectively unbreakable)"
        else:
            crack_time = f"{years:.1f} years"
    
    return {
        "security_level": security_level,
        "rating": rating,
        "efficiency_percent": round(efficiency, 2),
        "max_possible_entropy": round(max_entropy, 2),
        "estimated_crack_time": crack_time,
        "bits_of_entropy": round(entropy, 2)
    }


@register_tool
def entropy_analyzer(
    action: EntropyAction,
    token: str | None = None,
    tokens: list[str] | None = None,
    token1: str | None = None,
    token2: str | None = None
) -> dict[str, Any]:
    """Analyze entropy and randomness of tokens, session IDs, and secrets.
    
    This tool calculates Shannon entropy, analyzes character distribution,
    detects predictable patterns, and assesses token security quality.
    Used for testing session IDs, CSRF tokens, API keys, password reset tokens,
    and any security-critical random values.
    
    Args:
        action: The analysis action:
            - analyze: Analyze single token for entropy and patterns
            - compare: Compare two tokens for similarity
            - batch_analyze: Analyze multiple tokens for patterns
        token: Single token to analyze (for analyze action)
        tokens: List of tokens to analyze (for batch_analyze action)
        token1: First token for comparison (for compare action)
        token2: Second token for comparison (for compare action)
    
    Returns:
        Entropy measurements, security assessment, pattern detection,
        and recommendations
    
    Example:
        # Analyze session token:
        entropy_analyzer(
            action="analyze",
            token="a1b2c3d4e5f6g7h8"
        )
        
        # Compare tokens:
        entropy_analyzer(
            action="compare",
            token1="abc123",
            token2="abc124"
        )
    """
    try:
        if action == "analyze":
            if not token:
                return {"error": "token parameter required for analyze action"}
            
            # Calculate entropy
            shannon_entropy = _calculate_shannon_entropy(token)
            min_entropy = _calculate_min_entropy(token)
            
            # Analyze character distribution
            char_dist = _analyze_character_distribution(token)
            
            # Detect patterns
            patterns = _detect_patterns(token)
            
            # Estimate character set size
            char_set_size = len(set(token))
            
            # Assess randomness
            assessment = _assess_randomness(shannon_entropy, len(token), char_set_size)
            
            return {
                "token_length": len(token),
                "unique_characters": char_set_size,
                "entropy": {
                    "shannon_entropy": round(shannon_entropy, 4),
                    "min_entropy": round(min_entropy, 4),
                    "per_character": round(shannon_entropy / len(token), 4) if len(token) > 0 else 0
                },
                "character_distribution": char_dist,
                "patterns_detected": patterns,
                "security_assessment": assessment,
                "recommendations": _get_entropy_recommendations(
                    shannon_entropy, patterns, char_dist
                )
            }
        
        if action == "compare":
            if not token1 or not token2:
                return {"error": "token1 and token2 parameters required for compare action"}
            
            # Calculate similarity metrics
            # Hamming distance (for same length)
            if len(token1) == len(token2):
                hamming = sum(c1 != c2 for c1, c2 in zip(token1, token2))
                hamming_percent = (hamming / len(token1)) * 100
            else:
                hamming = None
                hamming_percent = None
            
            # Common prefix/suffix
            common_prefix = 0
            for c1, c2 in zip(token1, token2):
                if c1 == c2:
                    common_prefix += 1
                else:
                    break
            
            common_suffix = 0
            for c1, c2 in zip(reversed(token1), reversed(token2)):
                if c1 == c2:
                    common_suffix += 1
                else:
                    break
            
            # Character set overlap
            set1 = set(token1)
            set2 = set(token2)
            overlap = len(set1 & set2)
            overlap_percent = (overlap / max(len(set1), len(set2))) * 100 if set1 or set2 else 0
            
            # Assess similarity concerns
            concerns = []
            if common_prefix > len(token1) * 0.3:
                concerns.append("Significant common prefix detected")
            if common_suffix > len(token1) * 0.3:
                concerns.append("Significant common suffix detected")
            if hamming_percent and hamming_percent < 50:
                concerns.append("Tokens are very similar (low Hamming distance)")
            
            return {
                "token1_length": len(token1),
                "token2_length": len(token2),
                "hamming_distance": hamming,
                "hamming_difference_percent": round(hamming_percent, 2) if hamming_percent else "N/A (different lengths)",
                "common_prefix_length": common_prefix,
                "common_suffix_length": common_suffix,
                "character_set_overlap": overlap,
                "overlap_percent": round(overlap_percent, 2),
                "similarity_concerns": concerns if concerns else ["No significant similarity concerns"],
                "recommendation": "Tokens should be completely independent" if concerns else "Tokens appear sufficiently different"
            }
        
        if action == "batch_analyze":
            if not tokens or len(tokens) < 2:
                return {"error": "tokens parameter with at least 2 tokens required for batch_analyze action"}
            
            # Analyze each token
            individual_analyses = []
            entropies = []
            
            for i, tok in enumerate(tokens):
                shannon = _calculate_shannon_entropy(tok)
                entropies.append(shannon)
                individual_analyses.append({
                    "index": i,
                    "token": tok[:10] + "..." if len(tok) > 10 else tok,
                    "length": len(tok),
                    "shannon_entropy": round(shannon, 2)
                })
            
            # Statistical analysis
            avg_entropy = sum(entropies) / len(entropies)
            min_ent = min(entropies)
            max_ent = max(entropies)
            entropy_variance = sum((e - avg_entropy) ** 2 for e in entropies) / len(entropies)
            
            # Check for patterns across tokens
            batch_concerns = []
            if entropy_variance < 0.1:
                batch_concerns.append("Very low entropy variance - tokens may be generated with same weak algorithm")
            if max_ent - min_ent < 5:
                batch_concerns.append("Small entropy range - insufficient randomness variation")
            
            # Check for sequential patterns
            sorted_tokens = sorted(tokens)
            sequential_found = False
            for i in range(len(sorted_tokens) - 1):
                if sorted_tokens[i][:5] == sorted_tokens[i+1][:5]:
                    sequential_found = True
                    break
            
            if sequential_found:
                batch_concerns.append("Sequential patterns detected in token prefixes")
            
            return {
                "total_tokens": len(tokens),
                "individual_analyses": individual_analyses[:10],  # Limit to first 10
                "statistics": {
                    "average_entropy": round(avg_entropy, 2),
                    "min_entropy": round(min_ent, 2),
                    "max_entropy": round(max_ent, 2),
                    "entropy_variance": round(entropy_variance, 4),
                    "entropy_standard_deviation": round(math.sqrt(entropy_variance), 2)
                },
                "batch_concerns": batch_concerns if batch_concerns else ["No batch-level concerns detected"],
                "recommendation": "All tokens should have high, varied entropy" if batch_concerns else "Token generation appears adequately random"
            }
        
        return {"error": f"Unknown action: {action}"}
    
    except (ValueError, TypeError) as e:
        return {"error": f"Entropy analysis failed: {e!s}"}


def _get_entropy_recommendations(
    entropy: float, patterns: list[dict[str, Any]], char_dist: dict[str, Any]
) -> list[str]:
    """Generate recommendations based on entropy analysis."""
    recommendations = []
    
    if entropy < 40:
        recommendations.append("CRITICAL: Token has very low entropy - replace with cryptographically secure random generator")
    elif entropy < 60:
        recommendations.append("WARNING: Token entropy is weak - consider using longer tokens or larger character set")
    elif entropy < 80:
        recommendations.append("Token entropy is adequate but could be improved")
    else:
        recommendations.append("Token entropy is good")
    
    if patterns:
        recommendations.append(f"Detected {len(patterns)} pattern(s) that reduce security - avoid predictable sequences")
    
    # Check character distribution
    percentages = char_dist.get("percentages", {})
    if any(p > 80 for p in percentages.values()):
        recommendations.append("Character distribution is heavily skewed - use more diverse character types")
    
    if char_dist.get("special", 0) == 0:
        recommendations.append("Consider including special characters to increase entropy")
    
    return recommendations
