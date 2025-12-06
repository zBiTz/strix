"""Evidence collection tool for penetration testing documentation."""

import datetime
import json
import os
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "save_request",
    "save_response",
    "capture_screenshot",
    "create_timeline",
    "generate_report",
]


@register_tool(sandbox_execution=True)
def evidence_collector(
    action: ToolAction,
    finding_id: str | None = None,
    title: str | None = None,
    description: str | None = None,
    severity: str | None = None,
    request_data: dict | None = None,
    response_data: dict | None = None,
    screenshot_path: str | None = None,
    timeline_events: list[dict] | None = None,
    output_format: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Evidence collection tool for penetration testing documentation.

    Args:
        action: The action to perform
        finding_id: Unique identifier for the finding
        title: Title of the finding
        description: Description of the vulnerability
        severity: Severity level (critical, high, medium, low, info)
        request_data: HTTP request data
        response_data: HTTP response data
        screenshot_path: Path to screenshot file
        timeline_events: List of timeline events
        output_format: Output format (json, markdown, html)

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "finding_id", "title", "description", "severity",
        "request_data", "response_data", "screenshot_path",
        "timeline_events", "output_format",
    }
    VALID_ACTIONS = [
        "save_request",
        "save_response",
        "capture_screenshot",
        "create_timeline",
        "generate_report",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "evidence_collector"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "evidence_collector"):
        return action_error

    timestamp = datetime.datetime.now().isoformat()

    if action == "save_request":
        if param_error := validate_required_param(request_data, "request_data", action, "evidence_collector"):
            return param_error

        finding = finding_id or f"FINDING-{timestamp[:10].replace('-', '')}"

        evidence = {
            "finding_id": finding,
            "type": "http_request",
            "timestamp": timestamp,
            "data": {
                "method": request_data.get("method", "GET"),
                "url": request_data.get("url", ""),
                "headers": request_data.get("headers", {}),
                "body": request_data.get("body", ""),
                "cookies": request_data.get("cookies", {}),
            },
        }

        # Generate curl command
        method = request_data.get("method", "GET")
        url = request_data.get("url", "")
        headers = request_data.get("headers", {})
        body = request_data.get("body", "")

        curl_parts = [f"curl -X {method}"]
        for h, v in headers.items():
            curl_parts.append(f'-H "{h}: {v}"')
        if body:
            curl_parts.append(f"-d '{body}'")
        curl_parts.append(f'"{url}"')
        curl_command = " \\\n  ".join(curl_parts)

        return {
            "action": "save_request",
            "evidence": evidence,
            "curl_command": curl_command,
            "file_suggestion": f"evidence/{finding}_request.json",
            "save_command": f'''
mkdir -p evidence
cat << 'EOF' > evidence/{finding}_request.json
{json.dumps(evidence, indent=2)}
EOF
''',
        }

    elif action == "save_response":
        if param_error := validate_required_param(response_data, "response_data", action, "evidence_collector"):
            return param_error

        finding = finding_id or f"FINDING-{timestamp[:10].replace('-', '')}"

        evidence = {
            "finding_id": finding,
            "type": "http_response",
            "timestamp": timestamp,
            "data": {
                "status_code": response_data.get("status_code", 200),
                "headers": response_data.get("headers", {}),
                "body": response_data.get("body", "")[:10000],  # Limit size
                "response_time": response_data.get("response_time", ""),
            },
        }

        return {
            "action": "save_response",
            "evidence": evidence,
            "file_suggestion": f"evidence/{finding}_response.json",
            "body_length": len(response_data.get("body", "")),
            "save_command": f'''
mkdir -p evidence
cat << 'EOF' > evidence/{finding}_response.json
{json.dumps(evidence, indent=2)}
EOF
''',
        }

    elif action == "capture_screenshot":
        finding = finding_id or f"FINDING-{timestamp[:10].replace('-', '')}"
        sev = severity or "medium"

        return {
            "action": "capture_screenshot",
            "finding_id": finding,
            "description": "Screenshot capture guidance for evidence",
            "cli_tools": {
                "linux_full": "gnome-screenshot -f screenshot.png",
                "linux_window": "gnome-screenshot -w -f screenshot.png",
                "linux_area": "gnome-screenshot -a -f screenshot.png",
                "macos": "screencapture -i screenshot.png",
                "windows": "snippingtool or Win+Shift+S",
            },
            "browser_capture": {
                "chrome_devtools": "Ctrl+Shift+P -> 'Capture full size screenshot'",
                "firefox": "Ctrl+Shift+S -> Select area or full page",
            },
            "selenium_python": '''
from selenium import webdriver

driver = webdriver.Chrome()
driver.get("https://target.com/vulnerable-page")
driver.save_screenshot(f"evidence/{finding}_screenshot.png")
''',
            "playwright_python": '''
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto("https://target.com/vulnerable-page")
    page.screenshot(path=f"evidence/{finding}_screenshot.png", full_page=True)
''',
            "naming_convention": f"evidence/{finding}_{sev}_screenshot.png",
            "annotation_tips": [
                "Highlight vulnerable area with red box",
                "Include browser address bar for URL",
                "Show timestamp if possible",
                "Include relevant error messages",
            ],
        }

    elif action == "create_timeline":
        events = timeline_events or [
            {"time": "10:00", "action": "Initial reconnaissance"},
            {"time": "10:30", "action": "Vulnerability discovered"},
            {"time": "11:00", "action": "Exploitation confirmed"},
        ]

        timeline_md = "# Attack Timeline\n\n"
        timeline_md += "| Time | Action | Details |\n"
        timeline_md += "|------|--------|--------|\n"
        for event in events:
            timeline_md += f"| {event.get('time', '')} | {event.get('action', '')} | {event.get('details', '')} |\n"

        return {
            "action": "create_timeline",
            "events": events,
            "markdown": timeline_md,
            "json_format": json.dumps(events, indent=2),
            "template": {
                "event": {
                    "time": "HH:MM",
                    "action": "Description of action",
                    "details": "Additional details",
                    "evidence": "Link to evidence file",
                }
            },
            "save_command": f'''
cat << 'EOF' > evidence/timeline.md
{timeline_md}
EOF
''',
        }

    elif action == "generate_report":
        finding = finding_id or "FINDING-001"
        finding_title = title or "Vulnerability Finding"
        finding_desc = description or "Description of the vulnerability"
        sev = severity or "medium"
        fmt = output_format or "markdown"

        severity_colors = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFCC00",
            "low": "#00CC00",
            "info": "#0066CC",
        }

        if fmt == "markdown":
            report = f'''# {finding_title}

## Finding ID: {finding}

**Severity:** {sev.upper()}

**Date:** {timestamp[:10]}

## Description

{finding_desc}

## Impact

[Describe the impact of this vulnerability]

## Steps to Reproduce

1. Navigate to the vulnerable endpoint
2. Perform the following action
3. Observe the vulnerability

## Evidence

- Request: `evidence/{finding}_request.json`
- Response: `evidence/{finding}_response.json`
- Screenshot: `evidence/{finding}_screenshot.png`

## Recommendations

1. [First remediation step]
2. [Second remediation step]

## References

- [OWASP Reference]
- [CWE Reference]
'''
        elif fmt == "json":
            report = json.dumps({
                "finding_id": finding,
                "title": finding_title,
                "severity": sev,
                "date": timestamp[:10],
                "description": finding_desc,
                "evidence": {
                    "request": f"evidence/{finding}_request.json",
                    "response": f"evidence/{finding}_response.json",
                    "screenshot": f"evidence/{finding}_screenshot.png",
                },
                "recommendations": [],
            }, indent=2)
        else:
            report = f'''<!DOCTYPE html>
<html>
<head><title>{finding_title}</title></head>
<body>
<h1>{finding_title}</h1>
<p><strong>Finding ID:</strong> {finding}</p>
<p><strong>Severity:</strong> <span style="color: {severity_colors.get(sev, '#000')}">{sev.upper()}</span></p>
<h2>Description</h2>
<p>{finding_desc}</p>
</body>
</html>'''

        return {
            "action": "generate_report",
            "finding_id": finding,
            "format": fmt,
            "report": report,
            "save_command": f'''
cat << 'EOF' > evidence/{finding}_report.{fmt if fmt != 'markdown' else 'md'}
{report}
EOF
''',
            "report_sections": [
                "Executive Summary",
                "Finding Details",
                "Technical Description",
                "Impact Assessment",
                "Proof of Concept",
                "Remediation",
                "References",
            ],
        }

    return generate_usage_hint("evidence_collector", VALID_ACTIONS)
