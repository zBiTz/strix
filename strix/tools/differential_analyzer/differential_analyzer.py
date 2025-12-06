"""Differential analyzer for response comparison and bypass detection."""

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

ToolAction = Literal[
    "compare_responses",
    "detect_bypass",
    "analyze_timing",
    "track_state",
    "find_differences",
]


@register_tool(sandbox_execution=True)
def differential_analyzer(
    action: ToolAction,
    response1: dict | None = None,
    response2: dict | None = None,
    responses: list[dict] | None = None,
    baseline: dict | None = None,
    test_case: dict | None = None,
    timing_data: list[dict] | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Differential analyzer for response comparison and bypass detection.

    Args:
        action: The action to perform
        response1: First response for comparison
        response2: Second response for comparison
        responses: List of responses for analysis
        baseline: Baseline response for bypass detection
        test_case: Test response to compare against baseline
        timing_data: Timing data for analysis

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "response1", "response2", "responses",
        "baseline", "test_case", "timing_data",
    }
    VALID_ACTIONS = [
        "compare_responses",
        "detect_bypass",
        "analyze_timing",
        "track_state",
        "find_differences",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "differential_analyzer"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "differential_analyzer"):
        return action_error

    if action == "compare_responses":
        resp1 = response1 or {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"user": "test", "role": "user"}',
        }
        resp2 = response2 or {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"user": "test", "role": "admin"}',
        }

        differences = []

        # Compare status codes
        if resp1.get("status_code") != resp2.get("status_code"):
            differences.append({
                "field": "status_code",
                "value1": resp1.get("status_code"),
                "value2": resp2.get("status_code"),
                "significance": "high",
            })

        # Compare headers
        h1 = resp1.get("headers", {})
        h2 = resp2.get("headers", {})
        all_headers = set(h1.keys()) | set(h2.keys())
        for header in all_headers:
            if h1.get(header) != h2.get(header):
                differences.append({
                    "field": f"header:{header}",
                    "value1": h1.get(header),
                    "value2": h2.get(header),
                    "significance": "medium",
                })

        # Compare body length
        body1 = resp1.get("body", "")
        body2 = resp2.get("body", "")
        len_diff = abs(len(body1) - len(body2))
        if len_diff > 0:
            differences.append({
                "field": "body_length",
                "value1": len(body1),
                "value2": len(body2),
                "difference": len_diff,
                "significance": "medium" if len_diff > 100 else "low",
            })

        # Body diff
        if body1 != body2:
            diff = list(difflib.unified_diff(
                body1.splitlines(),
                body2.splitlines(),
                lineterm='',
            ))[:20]  # Limit lines
            differences.append({
                "field": "body_content",
                "diff_preview": diff,
                "significance": "high",
            })

        return {
            "action": "compare_responses",
            "differences": differences,
            "total_differences": len(differences),
            "similarity_ratio": difflib.SequenceMatcher(None, body1, body2).ratio(),
            "body1_hash": hashlib.md5(body1.encode()).hexdigest(),
            "body2_hash": hashlib.md5(body2.encode()).hexdigest(),
        }

    elif action == "detect_bypass":
        base = baseline or {
            "status_code": 403,
            "body": "Access Denied",
        }
        test = test_case or {
            "status_code": 200,
            "body": '{"data": "sensitive"}',
        }

        bypass_indicators = []

        # Status code change from error to success
        base_status = base.get("status_code", 0)
        test_status = test.get("status_code", 0)

        if base_status >= 400 and test_status < 400:
            bypass_indicators.append({
                "indicator": "status_code_bypass",
                "description": f"Status changed from {base_status} to {test_status}",
                "severity": "critical",
            })

        # Body content changed significantly
        base_body = base.get("body", "")
        test_body = test.get("body", "")

        error_keywords = ["denied", "forbidden", "unauthorized", "error", "failed"]
        success_keywords = ["data", "success", "user", "result", "id"]

        base_has_error = any(kw in base_body.lower() for kw in error_keywords)
        test_has_success = any(kw in test_body.lower() for kw in success_keywords)

        if base_has_error and test_has_success:
            bypass_indicators.append({
                "indicator": "content_bypass",
                "description": "Error response replaced with success content",
                "severity": "high",
            })

        # Length difference suggesting more data
        len_diff = len(test_body) - len(base_body)
        if len_diff > 100:
            bypass_indicators.append({
                "indicator": "data_exposure",
                "description": f"Response {len_diff} bytes larger (possible data leak)",
                "severity": "medium",
            })

        return {
            "action": "detect_bypass",
            "baseline_status": base_status,
            "test_status": test_status,
            "bypass_detected": len(bypass_indicators) > 0,
            "indicators": bypass_indicators,
            "recommendation": "Investigate bypass technique that caused this difference",
        }

    elif action == "analyze_timing":
        timing = timing_data or [
            {"payload": "valid", "time_ms": 100},
            {"payload": "invalid", "time_ms": 102},
            {"payload": "admin' AND 1=1--", "time_ms": 520},
            {"payload": "admin' AND SLEEP(5)--", "time_ms": 5100},
        ]

        # Calculate statistics
        times = [t["time_ms"] for t in timing]
        avg_time = sum(times) / len(times) if times else 0
        min_time = min(times) if times else 0
        max_time = max(times) if times else 0

        # Find outliers (times significantly higher than average)
        outliers = []
        threshold = avg_time * 2  # 2x average is suspicious

        for t in timing:
            if t["time_ms"] > threshold:
                outliers.append({
                    "payload": t["payload"],
                    "time_ms": t["time_ms"],
                    "ratio_to_avg": round(t["time_ms"] / avg_time, 2),
                })

        return {
            "action": "analyze_timing",
            "statistics": {
                "count": len(times),
                "average_ms": round(avg_time, 2),
                "min_ms": min_time,
                "max_ms": max_time,
                "range_ms": max_time - min_time,
            },
            "outliers": outliers,
            "timing_attack_detected": len(outliers) > 0,
            "potential_vulnerabilities": [
                "Time-based SQL injection" if any("sleep" in o["payload"].lower() for o in outliers) else None,
                "Time-based blind injection" if len(outliers) > 0 else None,
            ],
            "methodology": [
                "1. Establish baseline timing with normal requests",
                "2. Send payloads designed to cause delays",
                "3. Compare response times",
                "4. Significant delays indicate vulnerability",
            ],
        }

    elif action == "track_state":
        resp_list = responses or [
            {"step": "initial", "body": '{"balance": 1000}'},
            {"step": "transfer", "body": '{"balance": 900}'},
            {"step": "after_exploit", "body": '{"balance": 1900}'},
        ]

        state_changes = []
        for i in range(1, len(resp_list)):
            prev = resp_list[i - 1]
            curr = resp_list[i]

            state_changes.append({
                "from_step": prev.get("step"),
                "to_step": curr.get("step"),
                "body_changed": prev.get("body") != curr.get("body"),
                "prev_body": prev.get("body", "")[:100],
                "curr_body": curr.get("body", "")[:100],
            })

        # Detect anomalies (e.g., balance increased unexpectedly)
        anomalies = []
        for i, resp in enumerate(resp_list):
            body = resp.get("body", "")
            # Simple numeric extraction for demo
            numbers = re.findall(r'"balance":\s*(\d+)', body)
            if numbers and i > 0:
                prev_body = resp_list[i - 1].get("body", "")
                prev_numbers = re.findall(r'"balance":\s*(\d+)', prev_body)
                if prev_numbers:
                    if int(numbers[0]) > int(prev_numbers[0]):
                        anomalies.append({
                            "step": resp.get("step"),
                            "anomaly": "Balance increased unexpectedly",
                            "prev_value": prev_numbers[0],
                            "curr_value": numbers[0],
                        })

        return {
            "action": "track_state",
            "responses_analyzed": len(resp_list),
            "state_changes": state_changes,
            "anomalies": anomalies,
            "anomaly_detected": len(anomalies) > 0,
        }

    elif action == "find_differences":
        resp_list = responses or [
            {"payload": "user=1", "status": 200, "length": 500},
            {"payload": "user=2", "status": 200, "length": 498},
            {"payload": "user=admin", "status": 200, "length": 1500},
            {"payload": "user=1'", "status": 500, "length": 200},
        ]

        # Group by status
        by_status = {}
        for r in resp_list:
            status = r.get("status")
            if status not in by_status:
                by_status[status] = []
            by_status[status].append(r)

        # Find length outliers
        lengths = [r.get("length", 0) for r in resp_list]
        avg_length = sum(lengths) / len(lengths) if lengths else 0

        length_outliers = [
            r for r in resp_list
            if abs(r.get("length", 0) - avg_length) > avg_length * 0.5
        ]

        return {
            "action": "find_differences",
            "total_responses": len(resp_list),
            "status_groups": {k: len(v) for k, v in by_status.items()},
            "length_statistics": {
                "average": round(avg_length, 2),
                "min": min(lengths) if lengths else 0,
                "max": max(lengths) if lengths else 0,
            },
            "length_outliers": length_outliers,
            "interesting_responses": [
                r for r in resp_list
                if r.get("status") == 500 or r in length_outliers
            ],
            "analysis_tips": [
                "Different status codes may indicate vulnerabilities",
                "Length variations often reveal data exposure",
                "500 errors suggest injection or parsing issues",
                "Compare successful vs failed authentication responses",
            ],
        }

    return generate_usage_hint("differential_analyzer", VALID_ACTIONS)
