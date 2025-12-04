"""Response Diff tool for comparing HTTP responses."""

from __future__ import annotations

import difflib
import hashlib
import re
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


ResponseDiffAction = Literal["compare", "diff_text", "analyze_similarity", "find_changes"]


def _normalize_response(content: str, ignore_patterns: list[str] | None = None) -> str:
    """Normalize response content by removing dynamic values."""
    normalized = content

    # Default patterns to normalize
    default_patterns = [
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",  # UUIDs
        r"\b\d{10,13}\b",  # Timestamps (10-13 digits)
        r'"[^"]*token[^"]*"\s*:\s*"[^"]*"',  # Token fields
        r'"[^"]*nonce[^"]*"\s*:\s*"[^"]*"',  # Nonce fields
        r'"[^"]*csrf[^"]*"\s*:\s*"[^"]*"',  # CSRF tokens
    ]

    patterns = default_patterns + (ignore_patterns or [])

    for pattern in patterns:
        normalized = re.sub(pattern, "[NORMALIZED]", normalized, flags=re.IGNORECASE)

    return normalized


def _compute_hash(content: str) -> str:
    """Compute MD5 hash of content."""
    return hashlib.md5(content.encode()).hexdigest()  # noqa: S324


def _compute_similarity(text1: str, text2: str) -> float:
    """Compute similarity ratio between two texts."""
    return difflib.SequenceMatcher(None, text1, text2).ratio()


def _find_differences(text1: str, text2: str) -> list[dict[str, Any]]:
    """Find detailed differences between two texts."""
    differences: list[dict[str, Any]] = []

    lines1 = text1.splitlines(keepends=True)
    lines2 = text2.splitlines(keepends=True)

    diff = difflib.unified_diff(lines1, lines2, lineterm="")
    diff_lines = list(diff)

    current_hunk: dict[str, Any] = {"additions": [], "deletions": [], "context": []}
    line_num = 0

    for line in diff_lines:
        if line.startswith("@@"):
            if current_hunk["additions"] or current_hunk["deletions"]:
                differences.append(current_hunk)
            current_hunk = {"additions": [], "deletions": [], "context": []}
            # Extract line numbers from hunk header
            match = re.search(r"@@ -(\d+)", line)
            if match:
                line_num = int(match.group(1))
        elif line.startswith("+") and not line.startswith("+++"):
            current_hunk["additions"].append({"line": line_num, "content": line[1:]})
            line_num += 1
        elif line.startswith("-") and not line.startswith("---"):
            current_hunk["deletions"].append({"line": line_num, "content": line[1:]})
        else:
            line_num += 1

    if current_hunk["additions"] or current_hunk["deletions"]:
        differences.append(current_hunk)

    return differences


def _analyze_response_structure(content: str) -> dict[str, Any]:
    """Analyze the structure of a response."""
    analysis: dict[str, Any] = {
        "length": len(content),
        "lines": content.count("\n") + 1,
        "hash": _compute_hash(content),
    }

    # Detect content type patterns
    if content.strip().startswith("{") or content.strip().startswith("["):
        analysis["likely_format"] = "json"
    elif content.strip().startswith("<"):
        analysis["likely_format"] = "html/xml"
    else:
        analysis["likely_format"] = "text"

    # Count common patterns
    analysis["patterns"] = {
        "urls": len(re.findall(r"https?://[^\s\"'<>]+", content)),
        "emails": len(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)),
        "tokens": len(re.findall(r"token|jwt|session|auth", content, re.IGNORECASE)),
    }

    return analysis


@register_tool
def response_diff(
    action: ResponseDiffAction,
    response1: str,
    response2: str | None = None,
    normalize: bool = True,
    ignore_patterns: list[str] | None = None,
    context_lines: int = 3,

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Compare HTTP responses to detect subtle differences.

    This tool helps identify behavioral changes, WAF bypasses, and security
    issues by comparing HTTP response content.

    Args:
        action: The comparison action to perform:
            - compare: Full comparison with statistics
            - diff_text: Generate unified diff output
            - analyze_similarity: Calculate similarity metrics
            - find_changes: Identify specific changes
        response1: First HTTP response body
        response2: Second HTTP response body (required for comparison actions)
        normalize: Whether to normalize dynamic values before comparison
        ignore_patterns: Additional regex patterns to ignore
        context_lines: Number of context lines in diff output

    Returns:
        Comparison results including differences, similarity scores, and analysis
    """
    try:
        if action == "compare":
            if not response2:
                return {"error": "response2 required for compare action"}

            # Normalize if requested
            text1 = _normalize_response(response1, ignore_patterns) if normalize else response1
            text2 = _normalize_response(response2, ignore_patterns) if normalize else response2

            # Basic comparison
            are_identical = text1 == text2
            similarity = _compute_similarity(text1, text2)

            # Structure analysis
            struct1 = _analyze_response_structure(response1)
            struct2 = _analyze_response_structure(response2)

            # Find differences
            differences = _find_differences(text1, text2)

            return {
                "identical": are_identical,
                "similarity": round(similarity, 4),
                "length_diff": len(response2) - len(response1),
                "response1_analysis": struct1,
                "response2_analysis": struct2,
                "difference_count": len(differences),
                "differences": differences[:10],  # Limit to first 10
                "security_implications": _assess_security_implications(differences, struct1, struct2),
            }

        if action == "diff_text":
            if not response2:
                return {"error": "response2 required for diff_text action"}

            text1 = _normalize_response(response1, ignore_patterns) if normalize else response1
            text2 = _normalize_response(response2, ignore_patterns) if normalize else response2

            lines1 = text1.splitlines(keepends=True)
            lines2 = text2.splitlines(keepends=True)

            diff = difflib.unified_diff(
                lines1,
                lines2,
                fromfile="response1",
                tofile="response2",
                n=context_lines,
            )
            diff_text = "".join(diff)

            return {
                "diff": diff_text if diff_text else "No differences found",
                "has_differences": bool(diff_text),
            }

        if action == "analyze_similarity":
            if not response2:
                return {"error": "response2 required for analyze_similarity action"}

            text1 = _normalize_response(response1, ignore_patterns) if normalize else response1
            text2 = _normalize_response(response2, ignore_patterns) if normalize else response2

            # Multiple similarity metrics
            ratio = _compute_similarity(text1, text2)
            quick_ratio = difflib.SequenceMatcher(None, text1, text2).quick_ratio()
            real_quick_ratio = difflib.SequenceMatcher(None, text1, text2).real_quick_ratio()

            # Jaccard similarity on words
            words1 = set(text1.split())
            words2 = set(text2.split())
            jaccard = len(words1 & words2) / len(words1 | words2) if words1 | words2 else 1.0

            return {
                "similarity_ratio": round(ratio, 4),
                "quick_ratio": round(quick_ratio, 4),
                "real_quick_ratio": round(real_quick_ratio, 4),
                "jaccard_similarity": round(jaccard, 4),
                "interpretation": _interpret_similarity(ratio),
            }

        if action == "find_changes":
            if not response2:
                return {"error": "response2 required for find_changes action"}

            text1 = _normalize_response(response1, ignore_patterns) if normalize else response1
            text2 = _normalize_response(response2, ignore_patterns) if normalize else response2

            differences = _find_differences(text1, text2)

            # Categorize changes
            additions = []
            deletions = []
            for diff_item in differences:
                additions.extend(diff_item.get("additions", []))
                deletions.extend(diff_item.get("deletions", []))

            return {
                "total_changes": len(additions) + len(deletions),
                "additions": len(additions),
                "deletions": len(deletions),
                "added_content": additions[:20],
                "removed_content": deletions[:20],
            }

        return {"error": f"Unknown action: {action}"}

    except (TypeError, ValueError) as e:
        return {"error": f"Comparison failed: {e!s}"}


def _assess_security_implications(
    differences: list[dict[str, Any]],
    struct1: dict[str, Any],
    struct2: dict[str, Any],
) -> list[str]:
    """Assess security implications of response differences."""
    implications: list[str] = []

    # Check for significant length differences
    length_diff = abs(struct2.get("length", 0) - struct1.get("length", 0))
    if length_diff > 1000:
        implications.append("Large content difference may indicate different code paths")

    # Check for format changes
    if struct1.get("likely_format") != struct2.get("likely_format"):
        implications.append("Response format changed - potential parsing differences")

    # Check for token/auth related changes
    tokens1 = struct1.get("patterns", {}).get("tokens", 0)
    tokens2 = struct2.get("patterns", {}).get("tokens", 0)
    if tokens1 != tokens2:
        implications.append("Authentication-related content differs")

    # Check if differences are minor (potential WAF bypass)
    if differences and len(differences) <= 3:
        implications.append("Minor differences may indicate WAF bypass or subtle behavior change")

    return implications


def _interpret_similarity(ratio: float) -> str:
    """Interpret similarity ratio."""
    if ratio >= 0.99:
        return "Nearly identical - minor cosmetic differences only"
    if ratio >= 0.95:
        return "Very similar - small differences detected"
    if ratio >= 0.80:
        return "Similar - notable differences present"
    if ratio >= 0.50:
        return "Somewhat similar - significant differences"
    return "Very different - responses vary substantially"
