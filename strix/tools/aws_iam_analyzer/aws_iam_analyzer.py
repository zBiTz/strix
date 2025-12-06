"""AWS IAM policy security analyzer for privilege escalation and misconfigurations."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_unknown_params,
)


AWSIAMAction = Literal[
    "analyze_policy",
    "find_privesc_paths",
    "check_overpermissioned",
    "enumerate_roles",
    "full_audit",
]

# Dangerous IAM actions that can lead to privilege escalation
PRIVESC_ACTIONS = {
    "iam:CreateAccessKey": "Can create access keys for any user",
    "iam:CreateLoginProfile": "Can create console password for any user",
    "iam:UpdateLoginProfile": "Can change console password for any user",
    "iam:AttachUserPolicy": "Can attach any policy to any user",
    "iam:AttachGroupPolicy": "Can attach any policy to any group",
    "iam:AttachRolePolicy": "Can attach any policy to any role",
    "iam:PutUserPolicy": "Can add inline policy to any user",
    "iam:PutGroupPolicy": "Can add inline policy to any group",
    "iam:PutRolePolicy": "Can add inline policy to any role",
    "iam:CreatePolicy": "Can create new managed policies",
    "iam:CreatePolicyVersion": "Can create new version of existing policy",
    "iam:SetDefaultPolicyVersion": "Can change active policy version",
    "iam:PassRole": "Can pass roles to services (pivoting)",
    "iam:CreateRole": "Can create new roles",
    "iam:UpdateAssumeRolePolicy": "Can modify role trust policies",
    "sts:AssumeRole": "Can assume other roles",
    "lambda:CreateFunction": "Can create Lambda with any role",
    "lambda:InvokeFunction": "Can invoke Lambda functions",
    "lambda:UpdateFunctionCode": "Can update Lambda code",
    "lambda:AddPermission": "Can add Lambda permissions",
    "ec2:RunInstances": "Can launch EC2 with instance profile",
    "glue:CreateDevEndpoint": "Can create Glue endpoint with role",
    "glue:UpdateDevEndpoint": "Can update Glue endpoint",
    "cloudformation:CreateStack": "Can create stacks with any role",
    "datapipeline:CreatePipeline": "Can create pipelines with roles",
    "ssm:SendCommand": "Can execute commands on EC2 instances",
    "ssm:StartSession": "Can start SSM sessions on EC2",
}

# Actions that commonly lead to data exfiltration
DATA_EXFIL_ACTIONS = {
    "s3:GetObject": "Can read S3 objects",
    "s3:ListBucket": "Can list S3 bucket contents",
    "secretsmanager:GetSecretValue": "Can retrieve secrets",
    "ssm:GetParameter": "Can retrieve SSM parameters",
    "ssm:GetParameters": "Can retrieve multiple SSM parameters",
    "kms:Decrypt": "Can decrypt data with KMS keys",
    "rds:DownloadDBLogFilePortion": "Can download RDS logs",
    "dynamodb:Scan": "Can scan DynamoDB tables",
    "dynamodb:Query": "Can query DynamoDB tables",
    "ec2:GetPasswordData": "Can get Windows EC2 passwords",
}

# Dangerous action patterns (wildcards)
DANGEROUS_PATTERNS = {
    r".*:\*": "Full service access",
    r"\*": "Full AWS access (admin)",
    r"iam:\*": "Full IAM access",
    r"s3:\*": "Full S3 access",
    r"ec2:\*": "Full EC2 access",
    r"lambda:\*": "Full Lambda access",
    r"sts:\*": "Full STS access",
    r".*:Delete\*": "Delete permissions",
    r".*:Put\*": "Write/modify permissions",
    r".*:Create\*": "Create permissions",
}

# Known privilege escalation paths
PRIVESC_PATHS = [
    {
        "name": "CreateAccessKey",
        "required": ["iam:CreateAccessKey"],
        "description": "Create access keys for privileged user",
        "severity": "critical",
    },
    {
        "name": "CreateLoginProfile",
        "required": ["iam:CreateLoginProfile"],
        "description": "Create console password for privileged user",
        "severity": "critical",
    },
    {
        "name": "AttachUserPolicy",
        "required": ["iam:AttachUserPolicy"],
        "description": "Attach AdministratorAccess to self",
        "severity": "critical",
    },
    {
        "name": "AttachRolePolicy",
        "required": ["iam:AttachRolePolicy", "sts:AssumeRole"],
        "description": "Attach policy to role and assume it",
        "severity": "critical",
    },
    {
        "name": "PutUserPolicy",
        "required": ["iam:PutUserPolicy"],
        "description": "Add inline admin policy to self",
        "severity": "critical",
    },
    {
        "name": "CreatePolicyVersion",
        "required": ["iam:CreatePolicyVersion"],
        "description": "Create new policy version with elevated permissions",
        "severity": "critical",
    },
    {
        "name": "SetDefaultPolicyVersion",
        "required": ["iam:SetDefaultPolicyVersion"],
        "description": "Switch to policy version with more permissions",
        "severity": "high",
    },
    {
        "name": "PassRole-Lambda",
        "required": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "description": "Create Lambda with admin role and invoke it",
        "severity": "critical",
    },
    {
        "name": "PassRole-EC2",
        "required": ["iam:PassRole", "ec2:RunInstances"],
        "description": "Launch EC2 with admin instance profile",
        "severity": "critical",
    },
    {
        "name": "PassRole-CloudFormation",
        "required": ["iam:PassRole", "cloudformation:CreateStack"],
        "description": "Create CloudFormation stack with admin role",
        "severity": "critical",
    },
    {
        "name": "PassRole-Glue",
        "required": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "description": "Create Glue endpoint with admin role",
        "severity": "critical",
    },
    {
        "name": "UpdateAssumeRolePolicy",
        "required": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
        "description": "Modify trust policy to assume privileged role",
        "severity": "critical",
    },
    {
        "name": "CreateRole-AssumeRole",
        "required": ["iam:CreateRole", "iam:AttachRolePolicy", "sts:AssumeRole"],
        "description": "Create role with admin policy and assume it",
        "severity": "critical",
    },
    {
        "name": "SSM-SendCommand",
        "required": ["ssm:SendCommand"],
        "description": "Execute commands on EC2 with attached role",
        "severity": "high",
    },
    {
        "name": "SSM-StartSession",
        "required": ["ssm:StartSession"],
        "description": "Start shell session on EC2 with attached role",
        "severity": "high",
    },
    {
        "name": "Lambda-UpdateCode",
        "required": ["lambda:UpdateFunctionCode"],
        "description": "Modify Lambda code to exfiltrate role credentials",
        "severity": "high",
    },
]


def _load_policy(policy: str | None, policy_file: str | None) -> dict[str, Any] | None:
    """Load policy from string or file."""
    if policy:
        try:
            return json.loads(policy)
        except json.JSONDecodeError:
            return None
    if policy_file:
        try:
            with open(policy_file) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
    return None


def _extract_actions(policy: dict[str, Any]) -> set[str]:
    """Extract all actions from a policy document."""
    actions = set()
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        stmt_actions = statement.get("Action", [])
        if isinstance(stmt_actions, str):
            stmt_actions = [stmt_actions]
        actions.update(stmt_actions)

    return actions


def _matches_action(pattern: str, action: str) -> bool:
    """Check if an action pattern matches a specific action."""
    # Convert IAM wildcard pattern to regex
    regex_pattern = pattern.replace("*", ".*").replace("?", ".")
    return bool(re.match(f"^{regex_pattern}$", action, re.IGNORECASE))


def _expand_wildcards(actions: set[str]) -> set[str]:
    """Expand wildcard actions to known dangerous actions."""
    expanded = set()
    all_dangerous = set(PRIVESC_ACTIONS.keys()) | set(DATA_EXFIL_ACTIONS.keys())

    for action in actions:
        if "*" in action:
            for dangerous in all_dangerous:
                if _matches_action(action, dangerous):
                    expanded.add(dangerous)
        else:
            expanded.add(action)

    return expanded


def _analyze_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Analyze an IAM policy for dangerous permissions."""
    findings = []
    actions = _extract_actions(policy)
    expanded_actions = _expand_wildcards(actions)

    # Check for privilege escalation actions
    for action in expanded_actions:
        if action in PRIVESC_ACTIONS:
            findings.append({
                "type": "privilege_escalation",
                "action": action,
                "description": PRIVESC_ACTIONS[action],
                "severity": "high",
            })

    # Check for data exfiltration actions
    for action in expanded_actions:
        if action in DATA_EXFIL_ACTIONS:
            findings.append({
                "type": "data_exfiltration",
                "action": action,
                "description": DATA_EXFIL_ACTIONS[action],
                "severity": "medium",
            })

    # Check for dangerous patterns
    for action in actions:
        for pattern, description in DANGEROUS_PATTERNS.items():
            if re.match(pattern, action, re.IGNORECASE):
                findings.append({
                    "type": "dangerous_pattern",
                    "action": action,
                    "description": description,
                    "severity": "critical" if pattern in [r"\*", r"iam:\*"] else "high",
                })
                break

    return {
        "action": "analyze_policy",
        "total_actions": len(actions),
        "findings": findings,
        "critical_count": len([f for f in findings if f["severity"] == "critical"]),
        "high_count": len([f for f in findings if f["severity"] == "high"]),
        "summary": f"Found {len(findings)} security issues in policy",
    }


def _find_privesc_paths(policy: dict[str, Any]) -> dict[str, Any]:
    """Find privilege escalation paths in a policy."""
    actions = _extract_actions(policy)
    expanded_actions = _expand_wildcards(actions)

    exploitable_paths = []
    for path in PRIVESC_PATHS:
        required = set(path["required"])
        if required.issubset(expanded_actions):
            exploitable_paths.append({
                "path_name": path["name"],
                "required_actions": path["required"],
                "description": path["description"],
                "severity": path["severity"],
                "exploitable": True,
            })
        else:
            # Check partial matches
            matched = required.intersection(expanded_actions)
            if matched and len(matched) >= len(required) - 1:
                exploitable_paths.append({
                    "path_name": path["name"],
                    "required_actions": path["required"],
                    "matched_actions": list(matched),
                    "missing_actions": list(required - matched),
                    "description": path["description"],
                    "severity": "medium",
                    "exploitable": False,
                    "note": "Partial match - may be exploitable with other permissions",
                })

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2}
    exploitable_paths.sort(key=lambda x: severity_order.get(x["severity"], 3))

    critical_paths = [p for p in exploitable_paths if p.get("exploitable") and p["severity"] == "critical"]

    return {
        "action": "find_privesc_paths",
        "total_paths_checked": len(PRIVESC_PATHS),
        "exploitable_paths": len([p for p in exploitable_paths if p.get("exploitable")]),
        "partial_paths": len([p for p in exploitable_paths if not p.get("exploitable")]),
        "paths": exploitable_paths,
        "critical_escalation_possible": len(critical_paths) > 0,
        "recommendation": "Immediate remediation required" if critical_paths else "Review partial paths",
    }


def _check_overpermissioned(policy: dict[str, Any]) -> dict[str, Any]:
    """Check for overly permissive policy statements."""
    findings = []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for idx, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue

        stmt_findings = []
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        conditions = statement.get("Condition", {})

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # Check for wildcard actions
        if "*" in actions or any("*" in a for a in actions):
            stmt_findings.append({
                "issue": "wildcard_action",
                "description": "Allows all or multiple actions",
                "severity": "critical" if "*" in actions else "high",
            })

        # Check for wildcard resources
        if "*" in resources:
            stmt_findings.append({
                "issue": "wildcard_resource",
                "description": "Applies to all resources",
                "severity": "high",
            })

        # Check for missing conditions
        if not conditions and ("*" in actions or "*" in resources):
            stmt_findings.append({
                "issue": "no_conditions",
                "description": "No conditions to restrict scope",
                "severity": "medium",
            })

        # Check for NotAction (can be dangerous)
        if "NotAction" in statement:
            stmt_findings.append({
                "issue": "not_action",
                "description": "NotAction can unintentionally allow dangerous actions",
                "severity": "medium",
            })

        # Check for NotResource (can be dangerous)
        if "NotResource" in statement:
            stmt_findings.append({
                "issue": "not_resource",
                "description": "NotResource can unintentionally expose resources",
                "severity": "medium",
            })

        if stmt_findings:
            findings.append({
                "statement_index": idx,
                "actions": actions[:5] if len(actions) > 5 else actions,
                "resources": resources[:3] if len(resources) > 3 else resources,
                "issues": stmt_findings,
            })

    return {
        "action": "check_overpermissioned",
        "total_statements": len(statements),
        "overpermissioned_statements": len(findings),
        "findings": findings,
        "policy_risk_level": "critical" if any(
            any(i["severity"] == "critical" for i in f["issues"]) for f in findings
        ) else "high" if findings else "low",
    }


def _enumerate_roles(role_trust_policy: str | None) -> dict[str, Any]:
    """Analyze role trust policies for security issues."""
    if not role_trust_policy:
        return {
            "error": "role_trust_policy parameter required",
            "hint": "Provide the AssumeRolePolicyDocument of the role",
        }

    try:
        policy = json.loads(role_trust_policy)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON in role_trust_policy"}

    findings = []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for idx, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal", {})
        conditions = statement.get("Condition", {})

        # Check for overly permissive principals
        if principal == "*" or principal.get("AWS") == "*":
            findings.append({
                "statement_index": idx,
                "issue": "wildcard_principal",
                "description": "Any AWS account can assume this role",
                "severity": "critical",
                "has_conditions": bool(conditions),
            })

        # Check for federated access
        if "Federated" in principal:
            federated = principal["Federated"]
            if isinstance(federated, str):
                federated = [federated]
            for fed in federated:
                if "cognito-identity" in fed.lower() or "oidc" in fed.lower():
                    findings.append({
                        "statement_index": idx,
                        "issue": "federated_access",
                        "description": f"Federated access via {fed}",
                        "severity": "medium" if conditions else "high",
                        "provider": fed,
                    })

        # Check for cross-account access
        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for aws_principal in aws_principals:
            if ":" in str(aws_principal) and aws_principal != "*":
                # Extract account ID
                account_match = re.search(r":(\d{12}):", str(aws_principal))
                if account_match:
                    findings.append({
                        "statement_index": idx,
                        "issue": "cross_account_access",
                        "description": f"Cross-account access from {account_match.group(1)}",
                        "severity": "medium",
                        "principal": aws_principal,
                    })

        # Check for service principals
        service_principals = principal.get("Service", [])
        if isinstance(service_principals, str):
            service_principals = [service_principals]
        for service in service_principals:
            # Sensitive services
            sensitive_services = ["lambda", "ec2", "ecs-tasks", "codebuild", "glue"]
            if any(s in service.lower() for s in sensitive_services):
                findings.append({
                    "statement_index": idx,
                    "issue": "service_role",
                    "description": f"Service role for {service}",
                    "severity": "low",
                    "note": "Verify service requires these permissions",
                })

    return {
        "action": "enumerate_roles",
        "total_statements": len(statements),
        "findings": findings,
        "critical_issues": len([f for f in findings if f["severity"] == "critical"]),
        "recommendation": "Review trust relationships" if findings else "Trust policy appears restricted",
    }


def _full_audit(policy: dict[str, Any], role_trust_policy: str | None = None) -> dict[str, Any]:
    """Run all security checks on a policy."""
    results = {
        "action": "full_audit",
        "policy_analysis": _analyze_policy(policy),
        "privesc_analysis": _find_privesc_paths(policy),
        "overpermission_analysis": _check_overpermissioned(policy),
    }

    if role_trust_policy:
        results["trust_policy_analysis"] = _enumerate_roles(role_trust_policy)

    # Calculate overall risk
    critical_count = (
        results["policy_analysis"]["critical_count"] +
        len([p for p in results["privesc_analysis"]["paths"] if p.get("exploitable") and p["severity"] == "critical"])
    )
    high_count = (
        results["policy_analysis"]["high_count"] +
        len([p for p in results["privesc_analysis"]["paths"] if p.get("exploitable") and p["severity"] == "high"])
    )

    if critical_count > 0:
        risk_level = "critical"
    elif high_count > 0:
        risk_level = "high"
    elif results["overpermission_analysis"]["findings"]:
        risk_level = "medium"
    else:
        risk_level = "low"

    results["overall_risk_level"] = risk_level
    results["total_critical_findings"] = critical_count
    results["total_high_findings"] = high_count
    results["summary"] = f"Risk Level: {risk_level.upper()} - {critical_count} critical, {high_count} high severity findings"

    return results


@register_tool
def aws_iam_analyzer(
    action: AWSIAMAction,
    policy: str | None = None,
    policy_file: str | None = None,
    role_trust_policy: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Analyze AWS IAM policies for security vulnerabilities and privilege escalation paths.

    Args:
        action: The analysis action to perform:
            - analyze_policy: Analyze policy for dangerous permissions
            - find_privesc_paths: Identify privilege escalation paths
            - check_overpermissioned: Find overly permissive statements
            - enumerate_roles: Analyze role trust policies
            - full_audit: Run all checks
        policy: IAM policy document as JSON string
        policy_file: Path to IAM policy JSON file
        role_trust_policy: Role trust policy document for enumerate_roles

    Returns:
        Analysis results with findings and recommendations
    """
    VALID_PARAMS = {"action", "policy", "policy_file", "role_trust_policy"}
    VALID_ACTIONS = ["analyze_policy", "find_privesc_paths", "check_overpermissioned", "enumerate_roles", "full_audit"]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "aws_iam_analyzer"):
        unknown_error.update(
            generate_usage_hint("aws_iam_analyzer", "analyze_policy", {"policy": '{"Version": "2012-10-17", "Statement": [...]}'})
        )
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "aws_iam_analyzer"):
        action_error["usage_examples"] = {
            "analyze_policy": 'aws_iam_analyzer(action="analyze_policy", policy=\'{"Version": "2012-10-17", "Statement": [...]}\')',
            "find_privesc_paths": 'aws_iam_analyzer(action="find_privesc_paths", policy_file="policy.json")',
            "full_audit": 'aws_iam_analyzer(action="full_audit", policy_file="policy.json")',
        }
        return action_error

    # Handle enumerate_roles separately (doesn't need policy)
    if action == "enumerate_roles":
        return _enumerate_roles(role_trust_policy)

    # Load policy for other actions
    policy_doc = _load_policy(policy, policy_file)
    if not policy_doc:
        return {
            "error": "Could not load policy",
            "hint": "Provide valid JSON via 'policy' parameter or valid file path via 'policy_file'",
            "tool_name": "aws_iam_analyzer",
        }

    if action == "analyze_policy":
        return _analyze_policy(policy_doc)
    elif action == "find_privesc_paths":
        return _find_privesc_paths(policy_doc)
    elif action == "check_overpermissioned":
        return _check_overpermissioned(policy_doc)
    elif action == "full_audit":
        return _full_audit(policy_doc, role_trust_policy)

    return {"error": "Unknown action", "tool_name": "aws_iam_analyzer"}
