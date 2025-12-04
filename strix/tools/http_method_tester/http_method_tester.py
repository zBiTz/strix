"""HTTP method testing tool for security enumeration."""

from __future__ import annotations

from typing import Any, Literal

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


HTTPMethodAction = Literal["test_all", "test_method", "test_override"]


# HTTP methods to test
HTTP_METHODS = [
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "OPTIONS", "HEAD", "TRACE", "CONNECT",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"
]

# Method override headers
OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "_method",
]


def _test_http_method(url: str, method: str, timeout: int = 10) -> dict[str, Any]:
    """Test a specific HTTP method."""
    result = {
        "method": method,
        "allowed": False,
        "status_code": None,
        "response_length": 0,
        "headers": {}
    }
    
    try:
        response = requests.request(
            method,
            url,
            timeout=timeout,
            allow_redirects=False
        )
        
        result["status_code"] = response.status_code
        result["response_length"] = len(response.text)
        result["allowed"] = response.status_code != 405  # Not Method Not Allowed
        
        # Capture interesting headers
        interesting_headers = ["Allow", "Access-Control-Allow-Methods", "Server", "X-Powered-By"]
        for header in interesting_headers:
            if header in response.headers:
                result["headers"][header] = response.headers[header]
        
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
    
    return result


def _test_all_methods(url: str, timeout: int = 10) -> dict[str, Any]:
    """Test all HTTP methods."""
    results = {
        "url": url,
        "allowed_methods": [],
        "tests": []
    }
    
    for method in HTTP_METHODS:
        test_result = _test_http_method(url, method, timeout)
        results["tests"].append(test_result)
        
        if test_result["allowed"]:
            results["allowed_methods"].append(method)
    
    return results


def _test_method_override(url: str, base_method: str, target_method: str, timeout: int = 10) -> dict[str, Any]:
    """Test method override headers."""
    results = {
        "base_method": base_method,
        "target_method": target_method,
        "tests": []
    }
    
    for header_name in OVERRIDE_HEADERS:
        test_result = {
            "header": header_name,
            "success": False
        }
        
        try:
            # Test as header
            headers = {header_name: target_method}
            response = requests.request(
                base_method,
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False
            )
            
            test_result["status_code"] = response.status_code
            test_result["response_length"] = len(response.text)
            
            # Check if override was accepted (not 405)
            if response.status_code != 405:
                test_result["success"] = True
            
        except requests.exceptions.RequestException as e:
            test_result["error"] = str(e)
        
        results["tests"].append(test_result)
    
    # Also test as query parameter
    try:
        response = requests.request(
            base_method,
            f"{url}?_method={target_method}",
            timeout=timeout,
            allow_redirects=False
        )
        
        results["query_param_test"] = {
            "parameter": "_method",
            "status_code": response.status_code,
            "success": response.status_code != 405
        }
        
    except requests.exceptions.RequestException as e:
        results["query_param_test"] = {"error": str(e)}
    
    return results


@register_tool
def http_method_tester(
    action: HTTPMethodAction,
    url: str,
    method: str = "GET",
    target_method: str = "DELETE",
    timeout: int = 10,
    **kwargs: Any,  # Capture unknown parameters
) -> str | dict[str, Any]:
    """Test HTTP methods for security enumeration.
    
    Tests all HTTP methods including standard and WebDAV methods,
    and tests for method override vulnerabilities.
    
    Args:
        action: Action to perform
            - test_all: Test all HTTP methods
            - test_method: Test a specific HTTP method
            - test_override: Test method override headers
        url: Target URL for testing
        method: Specific method to test (for test_method action)
        target_method: Target method for override (for test_override)
        timeout: Request timeout in seconds
    
    Returns:
        Test results showing allowed methods and findings
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "url", "method", "target_method", "timeout"}
    VALID_ACTIONS = ["test_all", "test_method", "test_override"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "http_method_tester")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "http_method_tester",
                "test_all",
                {"url": "https://example.com/api/resource"},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "http_method_tester")
    if action_error:
        action_error["usage_examples"] = {
            "test_all": "http_method_tester(action='test_all', url='https://example.com/api/resource')",
            "test_method": "http_method_tester(action='test_method', url='https://example.com/api/resource', method='PUT')",
            "test_override": "http_method_tester(action='test_override', url='https://example.com/api/resource', target_method='DELETE')",
        }
        return action_error

    # Validate required parameters
    url_error = validate_required_param(url, "url", action, "http_method_tester")
    if url_error:
        url_error.update(
            generate_usage_hint(
                "http_method_tester",
                action,
                {"url": "https://example.com/api/resource"},
            )
        )
        return url_error

    if not url:
        return "Error: URL required for testing"
    
    if action == "test_all":
        results = _test_all_methods(url, timeout)
        
        output = ["HTTP Method Testing Results", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append("")
        
        if results["allowed_methods"]:
            output.append("Allowed Methods:")
            for method in results["allowed_methods"]:
                output.append(f"  ✓ {method}")
            output.append("")
        
        output.append("Detailed Results:")
        for test in results["tests"]:
            if "error" not in test:
                status = "ALLOWED" if test["allowed"] else "BLOCKED"
                output.append(f"\n{test['method']}: {status}")
                output.append(f"  Status Code: {test['status_code']}")
                output.append(f"  Response Length: {test['response_length']}")
                
                if test["headers"]:
                    output.append("  Headers:")
                    for header, value in test["headers"].items():
                        output.append(f"    {header}: {value}")
        
        # Security analysis
        output.append("")
        output.append("Security Analysis:")
        dangerous_methods = set(results["allowed_methods"]) & {"PUT", "DELETE", "TRACE", "CONNECT"}
        if dangerous_methods:
            output.append(f"  ⚠ Dangerous methods allowed: {', '.join(dangerous_methods)}")
        
        webdav_methods = set(results["allowed_methods"]) & {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE"}
        if webdav_methods:
            output.append(f"  ⚠ WebDAV methods enabled: {', '.join(webdav_methods)}")
        
        return "\n".join(output)
    
    elif action == "test_method":
        result = _test_http_method(url, method.upper(), timeout)
        
        output = ["HTTP Method Test", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Method: {method}")
        output.append("")
        
        if "error" in result:
            output.append(f"Error: {result['error']}")
        else:
            status = "ALLOWED" if result["allowed"] else "BLOCKED (405)"
            output.append(f"Status: {status}")
            output.append(f"Status Code: {result['status_code']}")
            output.append(f"Response Length: {result['response_length']}")
            
            if result["headers"]:
                output.append("")
                output.append("Headers:")
                for header, value in result["headers"].items():
                    output.append(f"  {header}: {value}")
        
        return "\n".join(output)
    
    elif action == "test_override":
        results = _test_method_override(url, method.upper(), target_method.upper(), timeout)
        
        output = ["HTTP Method Override Test", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Base Method: {results['base_method']}")
        output.append(f"Target Method: {results['target_method']}")
        output.append("")
        
        successful_overrides = []
        
        output.append("Header Override Tests:")
        for test in results["tests"]:
            if "error" not in test:
                status = "✓ SUCCESS" if test["success"] else "✗ BLOCKED"
                output.append(f"\n{test['header']}: {status}")
                output.append(f"  Status Code: {test['status_code']}")
                output.append(f"  Response Length: {test['response_length']}")
                
                if test["success"]:
                    successful_overrides.append(test["header"])
        
        output.append("")
        output.append("Query Parameter Test:")
        if "error" not in results["query_param_test"]:
            status = "✓ SUCCESS" if results["query_param_test"]["success"] else "✗ BLOCKED"
            output.append(f"  _method parameter: {status}")
            output.append(f"  Status Code: {results['query_param_test']['status_code']}")
            
            if results["query_param_test"]["success"]:
                successful_overrides.append("_method (query param)")
        
        if successful_overrides:
            output.append("")
            output.append("⚠ Vulnerability Found:")
            output.append("  Method override is possible via:")
            for override in successful_overrides:
                output.append(f"    • {override}")
            output.append("")
            output.append("  Impact: Attacker can use POST to perform DELETE, PUT, etc.")
            output.append("  This can bypass CSRF protection and access control.")
        
        return "\n".join(output)
    
    return "Invalid action. Use: test_all, test_method, test_override"
