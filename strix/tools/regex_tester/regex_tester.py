"""Regex pattern testing tool for ReDoS detection."""

from __future__ import annotations

import contextlib
import re
import time
from typing import Any, Literal

from strix.tools.registry import register_tool


RegexAction = Literal["test", "analyze", "benchmark"]

# Evil regex patterns known to cause ReDoS
EVIL_PATTERNS = [
    r"(a+)+",
    r"(a*)*",
    r"(a|aa)+",
    r"(a|a?)+",
    r"(.*a){10}",
    r"([a-zA-Z]+)*",
    r"(\d+)+",
    r"(\w+)+",
    r"(.*?)+",
    r"(a+?)+",
]

# Common vulnerable pattern structures
VULNERABLE_STRUCTURES = [
    ("nested_quantifiers", r"\([^)]*[+*][^)]*\)[+*]"),
    ("overlapping_alternation", r"\([^)]*\|[^)]*\)[+*]"),
    ("greedy_lazy_mix", r"\.\*\?\)?\+"),
]


def _test_regex_safety(pattern: str) -> dict[str, Any]:
    """Test if a regex pattern is potentially vulnerable to ReDoS."""
    issues: list[dict[str, str]] = []

    # Check for nested quantifiers
    if re.search(r"\([^)]*[+*][^)]*\)[+*]", pattern):
        issues.append({
            "type": "nested_quantifiers",
            "description": "Pattern contains nested quantifiers (e.g., (a+)+)",
            "severity": "high",
        })

    # Check for overlapping alternation with quantifier
    if re.search(r"\([^)]*\|[^)]*\)[+*]", pattern):
        issues.append({
            "type": "overlapping_alternation",
            "description": "Pattern has alternation with quantifier (e.g., (a|aa)+)",
            "severity": "high",
        })

    # Check for greedy inside lazy or vice versa
    if re.search(r"\.\*\?.*[+*]", pattern) or re.search(r"[+*].*\.\*\?", pattern):
        issues.append({
            "type": "greedy_lazy_mix",
            "description": "Pattern mixes greedy and lazy quantifiers",
            "severity": "medium",
        })

    # Check for unbounded repetition with wildcards
    if re.search(r"\.\*.*\.\*", pattern) and not re.search(r"\^\.\*\$", pattern):
        issues.append({
            "type": "multiple_wildcards",
            "description": "Pattern has multiple unbounded wildcards",
            "severity": "medium",
        })

    # Check for repetition of groups containing wildcards
    if re.search(r"\([^)]*\.\*[^)]*\)[+*]", pattern):
        issues.append({
            "type": "wildcard_in_repeated_group",
            "description": "Wildcard inside repeated group can cause exponential matching",
            "severity": "high",
        })

    # Check for character class with repetition of the class
    if re.search(r"\[[^\]]+\][+*].*\[[^\]]+\][+*]", pattern):
        issues.append({
            "type": "repeated_char_classes",
            "description": "Multiple repeated character classes may cause backtracking",
            "severity": "low",
        })

    is_vulnerable = len([i for i in issues if i["severity"] == "high"]) > 0

    return {
        "pattern": pattern,
        "is_vulnerable": is_vulnerable,
        "issue_count": len(issues),
        "issues": issues,
        "risk_level": "high" if is_vulnerable else (
            "medium" if issues else "low"
        ),
    }


def _generate_evil_input(pattern: str, length: int = 25) -> str:
    """Generate input designed to trigger ReDoS for a pattern."""
    # Analyze pattern to determine good attack string
    if re.search(r"a[+*]", pattern):
        return "a" * length + "!"

    if re.search(r"\d[+*]", pattern):
        return "1" * length + "x"

    if re.search(r"\w[+*]", pattern):
        return "a" * length + "!"

    if re.search(r"\s[+*]", pattern):
        return " " * length + "x"

    # Default: use 'a' characters
    return "a" * length + "X"


def _benchmark_pattern(
    pattern: str,
    test_input: str | None = None,
    max_length: int = 30,
) -> dict[str, Any]:
    """Benchmark regex pattern for ReDoS vulnerability."""
    results: list[dict[str, Any]] = []
    is_vulnerable = False
    timeout_length = None

    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return {
            "pattern": pattern,
            "error": f"Invalid regex: {e!s}",
        }

    # Test with increasing input lengths
    for length in range(5, max_length + 1, 5):
        if test_input:
            current_input = test_input[:length] if len(test_input) >= length else test_input
        else:
            current_input = _generate_evil_input(pattern, length)

        start_time = time.time()
        with contextlib.suppress(Exception):
            compiled.match(current_input)
        elapsed = time.time() - start_time

        results.append({
            "input_length": len(current_input),
            "time_seconds": round(elapsed, 4),
        })

        # Detect exponential growth
        if elapsed > 1.0:
            is_vulnerable = True
            timeout_length = length
            break

        # Check for exponential growth pattern
        if len(results) >= 2:
            prev_time = results[-2]["time_seconds"]
            if elapsed > 0.1 and prev_time > 0 and elapsed / prev_time > 5:
                is_vulnerable = True

    # Calculate growth rate if we have enough data
    growth_rate = None
    if len(results) >= 3:
        times = [r["time_seconds"] for r in results if r["time_seconds"] > 0]
        if len(times) >= 2:
            try:
                growth_rate = round(times[-1] / times[0], 2) if times[0] > 0 else None
            except (ZeroDivisionError, IndexError):
                growth_rate = None

    return {
        "pattern": pattern,
        "is_vulnerable": is_vulnerable,
        "timeout_length": timeout_length,
        "growth_rate": growth_rate,
        "benchmark_results": results,
        "conclusion": (
            "Exponential time complexity detected" if is_vulnerable else "Linear time complexity"
        ),
    }


def _analyze_pattern(pattern: str) -> dict[str, Any]:
    """Comprehensive analysis of a regex pattern."""
    # Validate pattern
    try:
        compiled = re.compile(pattern)
        is_valid = True
        compile_error = None
    except re.error as e:
        is_valid = False
        compile_error = str(e)
        compiled = None

    if not is_valid:
        return {
            "pattern": pattern,
            "is_valid": False,
            "error": compile_error,
        }

    # Get pattern info
    groups = compiled.groups if compiled else 0

    # Safety analysis
    safety = _test_regex_safety(pattern)

    # Quick benchmark
    benchmark = _benchmark_pattern(pattern, max_length=20)

    return {
        "pattern": pattern,
        "is_valid": is_valid,
        "groups": groups,
        "safety_analysis": safety,
        "benchmark": {
            "is_vulnerable": benchmark.get("is_vulnerable", False),
            "growth_rate": benchmark.get("growth_rate"),
        },
        "recommendations": _get_recommendations(safety, benchmark),
    }


def _get_recommendations(
    safety: dict[str, Any],
    benchmark: dict[str, Any],
) -> list[str]:
    """Generate recommendations based on analysis."""
    recommendations = []

    if safety.get("is_vulnerable"):
        recommendations.extend([
            "Avoid nested quantifiers like (a+)+",
            "Use atomic groups or possessive quantifiers if available",
            "Consider using RE2 or similar linear-time regex engine",
        ])

    if benchmark.get("is_vulnerable"):
        recommendations.extend([
            "Implement input length limits before regex matching",
            "Set timeout on regex operations",
            "Simplify the pattern to avoid backtracking",
        ])

    for issue in safety.get("issues", []):
        if issue["type"] == "overlapping_alternation":
            recommendations.append("Replace overlapping alternation with character class")
        elif issue["type"] == "multiple_wildcards":
            recommendations.append("Anchor pattern with ^ and $ where possible")

    if not recommendations:
        recommendations.append("Pattern appears safe, but always test with edge cases")

    return list(set(recommendations))


def _test_match(
    pattern: str,
    test_input: str,
) -> dict[str, Any]:
    """Test a regex pattern against input."""
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return {
            "pattern": pattern,
            "input": test_input,
            "error": f"Invalid regex: {e!s}",
        }

    start_time = time.time()
    match = compiled.match(test_input)
    elapsed = time.time() - start_time

    search_match = compiled.search(test_input)
    findall = compiled.findall(test_input)

    return {
        "pattern": pattern,
        "input": test_input[:100] + "..." if len(test_input) > 100 else test_input,
        "input_length": len(test_input),
        "match": bool(match),
        "match_group": match.group() if match else None,
        "search_match": bool(search_match),
        "findall_count": len(findall),
        "execution_time": round(elapsed, 4),
        "is_slow": elapsed > 0.1,
    }


@register_tool
def regex_tester(
    action: RegexAction,
    pattern: str,
    test_input: str | None = None,
    max_length: int = 30,
) -> dict[str, Any]:
    """Test regex patterns for ReDoS vulnerabilities.

    This tool analyzes regular expression patterns for potential
    denial of service vulnerabilities caused by catastrophic
    backtracking. It performs static analysis and dynamic benchmarking.

    Args:
        action: The testing action to perform:
            - test: Test pattern against input and check for issues
            - analyze: Comprehensive pattern analysis
            - benchmark: Benchmark pattern with increasing input lengths
        pattern: The regex pattern to test
        test_input: Input string to test against (optional)
        max_length: Maximum input length for benchmarking (default: 30)

    Returns:
        ReDoS vulnerability analysis and recommendations
    """
    try:
        if action == "test":
            safety = _test_regex_safety(pattern)
            if test_input:
                match_result = _test_match(pattern, test_input)
                return {
                    **match_result,
                    "safety_analysis": safety,
                }
            return safety

        if action == "analyze":
            return _analyze_pattern(pattern)

        if action == "benchmark":
            return _benchmark_pattern(pattern, test_input, max_length)

        return {"error": f"Unknown action: {action}"}

    except (re.error, ValueError) as e:
        return {"error": f"Regex testing failed: {e!s}"}
