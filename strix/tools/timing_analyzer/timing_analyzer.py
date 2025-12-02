"""Timing Analyzer tool for statistical timing analysis."""

from __future__ import annotations

import math
import statistics
from typing import Any, Literal

from strix.tools.registry import register_tool


TimingAnalyzerAction = Literal["analyze", "compare", "detect_difference", "get_statistics"]


def _calculate_statistics(times: list[float]) -> dict[str, float]:
    """Calculate comprehensive statistics for timing data."""
    if not times:
        return {}

    n = len(times)
    mean = statistics.mean(times)
    stdev = statistics.stdev(times) if n > 1 else 0.0
    variance = statistics.variance(times) if n > 1 else 0.0

    sorted_times = sorted(times)
    median = statistics.median(times)
    q1 = sorted_times[n // 4] if n >= 4 else sorted_times[0]
    q3 = sorted_times[3 * n // 4] if n >= 4 else sorted_times[-1]
    iqr = q3 - q1

    return {
        "count": n,
        "mean": round(mean, 4),
        "median": round(median, 4),
        "stdev": round(stdev, 4),
        "variance": round(variance, 6),
        "min": round(min(times), 4),
        "max": round(max(times), 4),
        "range": round(max(times) - min(times), 4),
        "q1": round(q1, 4),
        "q3": round(q3, 4),
        "iqr": round(iqr, 4),
        "coefficient_of_variation": round(stdev / mean, 4) if mean > 0 else 0.0,
    }


def _remove_outliers(times: list[float], method: str = "iqr") -> list[float]:
    """Remove outliers from timing data."""
    if len(times) < 4:
        return times

    if method == "iqr":
        sorted_times = sorted(times)
        n = len(sorted_times)
        q1 = sorted_times[n // 4]
        q3 = sorted_times[3 * n // 4]
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        return [t for t in times if lower_bound <= t <= upper_bound]

    if method == "zscore":
        mean = statistics.mean(times)
        stdev = statistics.stdev(times)
        if stdev == 0:
            return times
        return [t for t in times if abs((t - mean) / stdev) <= 3]

    return times


def _welch_t_test(times1: list[float], times2: list[float]) -> dict[str, float]:
    """Perform Welch's t-test for comparing two groups."""
    n1, n2 = len(times1), len(times2)
    if n1 < 2 or n2 < 2:
        return {"error": "Need at least 2 samples per group"}

    mean1, mean2 = statistics.mean(times1), statistics.mean(times2)
    var1, var2 = statistics.variance(times1), statistics.variance(times2)

    # Welch's t-statistic
    se = math.sqrt(var1 / n1 + var2 / n2)
    if se == 0:
        return {"t_statistic": 0.0, "significant": False}

    t_stat = (mean1 - mean2) / se

    # Degrees of freedom (Welch-Satterthwaite)
    num = (var1 / n1 + var2 / n2) ** 2
    denom = (var1 / n1) ** 2 / (n1 - 1) + (var2 / n2) ** 2 / (n2 - 1)
    df = num / denom if denom > 0 else 1

    # Approximate p-value using normal approximation for large df
    # For proper p-value, would need scipy.stats.t.sf
    p_approx = 2 * (1 - _normal_cdf(abs(t_stat)))

    return {
        "t_statistic": round(t_stat, 4),
        "degrees_of_freedom": round(df, 2),
        "p_value_approx": round(p_approx, 6),
        "significant_005": p_approx < 0.05,
        "significant_001": p_approx < 0.01,
    }


def _normal_cdf(x: float) -> float:
    """Approximate CDF of standard normal distribution."""
    return (1 + math.erf(x / math.sqrt(2))) / 2


def _effect_size(times1: list[float], times2: list[float]) -> dict[str, float]:
    """Calculate effect size (Cohen's d) between two groups."""
    n1, n2 = len(times1), len(times2)
    if n1 < 2 or n2 < 2:
        return {}

    mean1, mean2 = statistics.mean(times1), statistics.mean(times2)
    var1, var2 = statistics.variance(times1), statistics.variance(times2)

    # Pooled standard deviation
    pooled_std = math.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))

    if pooled_std == 0:
        return {"cohens_d": 0.0, "interpretation": "no difference"}

    d = (mean1 - mean2) / pooled_std

    # Interpret effect size
    abs_d = abs(d)
    if abs_d < 0.2:
        interpretation = "negligible"
    elif abs_d < 0.5:
        interpretation = "small"
    elif abs_d < 0.8:
        interpretation = "medium"
    else:
        interpretation = "large"

    return {
        "cohens_d": round(d, 4),
        "abs_effect": round(abs_d, 4),
        "interpretation": interpretation,
    }


@register_tool
def timing_analyzer(
    action: TimingAnalyzerAction,
    times1: list[float],
    times2: list[float] | None = None,
    remove_outliers: bool = True,
    outlier_method: str = "iqr",
) -> dict[str, Any]:
    """Statistical timing analysis for blind vulnerability detection.

    This tool performs statistical analysis on response times to detect
    timing-based vulnerabilities through differential analysis.

    Args:
        action: The analysis action to perform:
            - analyze: Analyze single timing dataset
            - compare: Compare two timing datasets
            - detect_difference: Determine if timing difference is significant
            - get_statistics: Get comprehensive statistics
        times1: First set of response times (in milliseconds or seconds)
        times2: Second set of response times (for comparison actions)
        remove_outliers: Whether to remove outliers before analysis
        outlier_method: Method for outlier removal (iqr or zscore)

    Returns:
        Statistical analysis results including significance tests
    """
    try:
        # Validate input
        if not times1 or len(times1) == 0:
            return {"error": "times1 must be a non-empty list of numbers"}

        # Convert to float and filter invalid values
        times1_clean = [float(t) for t in times1 if t is not None and float(t) >= 0]
        if not times1_clean:
            return {"error": "No valid timing values in times1"}

        if remove_outliers:
            times1_clean = _remove_outliers(times1_clean, outlier_method)

        if action == "analyze":
            stats = _calculate_statistics(times1_clean)

            return {
                "statistics": stats,
                "samples_used": len(times1_clean),
                "samples_original": len(times1),
                "outliers_removed": len(times1) - len(times1_clean),
                "recommendation": _get_sampling_recommendation(len(times1_clean)),
            }

        if action == "get_statistics":
            stats = _calculate_statistics(times1_clean)

            # Add percentiles
            sorted_times = sorted(times1_clean)
            n = len(sorted_times)
            percentiles = {}
            for p in [10, 25, 50, 75, 90, 95, 99]:
                idx = int(n * p / 100)
                idx = min(idx, n - 1)
                percentiles[f"p{p}"] = round(sorted_times[idx], 4)

            return {
                "statistics": stats,
                "percentiles": percentiles,
            }

        if action in ["compare", "detect_difference"]:
            if not times2:
                return {"error": "times2 required for comparison actions"}

            times2_clean = [float(t) for t in times2 if t is not None and float(t) >= 0]
            if not times2_clean:
                return {"error": "No valid timing values in times2"}

            if remove_outliers:
                times2_clean = _remove_outliers(times2_clean, outlier_method)

            stats1 = _calculate_statistics(times1_clean)
            stats2 = _calculate_statistics(times2_clean)

            t_test = _welch_t_test(times1_clean, times2_clean)
            effect = _effect_size(times1_clean, times2_clean)

            mean_diff = stats1["mean"] - stats2["mean"]
            percent_diff = (mean_diff / stats2["mean"]) * 100 if stats2["mean"] != 0 else 0

            result = {
                "group1_stats": stats1,
                "group2_stats": stats2,
                "mean_difference": round(mean_diff, 4),
                "percent_difference": round(percent_diff, 2),
                "t_test": t_test,
                "effect_size": effect,
            }

            if action == "detect_difference":
                # Determine if difference is likely due to actual timing variation
                is_significant = t_test.get("significant_005", False)
                is_meaningful = effect.get("interpretation", "negligible") in ["small", "medium", "large"]

                result["conclusion"] = {
                    "statistically_significant": is_significant,
                    "practically_meaningful": is_meaningful,
                    "likely_timing_vulnerability": is_significant and is_meaningful,
                    "confidence": _get_confidence_level(t_test, effect),
                }

                if is_significant and is_meaningful:
                    result["recommendation"] = (
                        "Timing difference detected. Increase sample size for confirmation, "
                        "then investigate potential timing-based vulnerability."
                    )
                else:
                    result["recommendation"] = (
                        "No significant timing difference detected. "
                        "Consider increasing sample size or testing different inputs."
                    )

            return result

        return {"error": f"Unknown action: {action}"}

    except (TypeError, ValueError, statistics.StatisticsError) as e:
        return {"error": f"Analysis failed: {e!s}"}


def _get_sampling_recommendation(n: int) -> str:
    """Get recommendation based on sample size."""
    if n < 10:
        return "Increase sample size to at least 30 for reliable analysis"
    if n < 30:
        return "Sample size marginal; consider collecting more samples"
    if n < 100:
        return "Sample size adequate for basic analysis"
    return "Sample size sufficient for detailed statistical analysis"


def _get_confidence_level(
    t_test: dict[str, Any],
    effect: dict[str, Any],
) -> str:
    """Determine confidence level in timing difference."""
    if t_test.get("significant_001") and effect.get("interpretation") == "large":
        return "high"
    if t_test.get("significant_005") and effect.get("interpretation") in ["medium", "large"]:
        return "medium"
    if t_test.get("significant_005"):
        return "low"
    return "very_low"
