"""Terraform configuration scanner for security misconfigurations."""

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
    "scan_misconfigs",
    "check_state_exposure",
    "audit_providers",
    "check_secrets",
    "analyze_permissions",
]


@register_tool(sandbox_execution=True)
def terraform_scanner(
    action: ToolAction,
    tf_content: str | None = None,
    state_content: str | None = None,
    directory: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Terraform configuration scanner for security misconfigurations.

    Args:
        action: The action to perform
        tf_content: Terraform HCL content
        state_content: Terraform state file content
        directory: Directory containing TF files

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "tf_content", "state_content", "directory",
    }
    VALID_ACTIONS = [
        "scan_misconfigs",
        "check_state_exposure",
        "audit_providers",
        "check_secrets",
        "analyze_permissions",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "terraform_scanner"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "terraform_scanner"):
        return action_error

    if action == "scan_misconfigs":
        content = tf_content or '''
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "allow_all" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''

        findings = []

        # Check for public S3
        if re.search(r'acl\s*=\s*"public', content):
            findings.append({
                "severity": "critical",
                "resource_type": "aws_s3_bucket",
                "issue": "Public ACL configured on S3 bucket",
                "recommendation": "Use private ACL and specific bucket policies",
            })

        # Check for open security groups
        if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', content):
            findings.append({
                "severity": "high",
                "resource_type": "aws_security_group",
                "issue": "Security group allows traffic from 0.0.0.0/0",
                "recommendation": "Restrict to specific IP ranges",
            })

        # Check for unencrypted resources
        if 'aws_rds_instance' in content and 'storage_encrypted' not in content:
            findings.append({
                "severity": "high",
                "resource_type": "aws_rds_instance",
                "issue": "RDS instance may not be encrypted",
                "recommendation": "Add storage_encrypted = true",
            })

        # Check for missing logging
        if 'aws_s3_bucket' in content and 'logging' not in content:
            findings.append({
                "severity": "medium",
                "resource_type": "aws_s3_bucket",
                "issue": "S3 bucket logging not configured",
                "recommendation": "Enable access logging",
            })

        return {
            "action": "scan_misconfigs",
            "content_scanned": len(content),
            "findings": findings,
            "total_issues": len(findings),
            "severity_breakdown": {
                "critical": len([f for f in findings if f["severity"] == "critical"]),
                "high": len([f for f in findings if f["severity"] == "high"]),
                "medium": len([f for f in findings if f["severity"] == "medium"]),
            },
            "recommended_tools": [
                "tfsec - Static analysis for Terraform",
                "checkov - IaC security scanner",
                "terrascan - Security and compliance scanner",
                "tfplan-validator - Custom policy validation",
            ],
            "tfsec_command": "tfsec . --format json",
            "checkov_command": "checkov -d . --output json",
        }

    elif action == "check_state_exposure":
        dir_path = directory or "."

        return {
            "action": "check_state_exposure",
            "directory": dir_path,
            "description": "Check for exposed Terraform state files",
            "exposure_risks": [
                "State files contain sensitive data (passwords, keys)",
                "Remote state may be publicly accessible",
                "Local state files in version control",
            ],
            "check_commands": {
                "find_local_state": f"find {dir_path} -name '*.tfstate' -o -name '*.tfstate.backup'",
                "check_git": f"git ls-files '{dir_path}/*.tfstate' 2>/dev/null",
                "check_remote": f"grep -r 'backend' {dir_path}/*.tf 2>/dev/null",
            },
            "common_issues": {
                "local_state": {
                    "risk": "State committed to git",
                    "check": "Look for .tfstate in git history",
                    "fix": "Add *.tfstate to .gitignore, use remote state",
                },
                "s3_public": {
                    "risk": "S3 backend bucket publicly accessible",
                    "check": "Check S3 bucket ACL and policy",
                    "fix": "Ensure bucket is private with versioning",
                },
                "no_encryption": {
                    "risk": "State stored without encryption",
                    "check": "Check backend encryption configuration",
                    "fix": "Enable encryption at rest",
                },
                "no_locking": {
                    "risk": "No state locking (race conditions)",
                    "check": "Check for DynamoDB lock table",
                    "fix": "Configure state locking",
                },
            },
            "secure_backend_example": '''
terraform {
  backend "s3" {
    bucket         = "my-tf-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "tf-state-lock"
  }
}
''',
            "git_check": '''
# Check git history for state files
git log --all --full-history -- "*.tfstate"
git log --all --full-history -- "*terraform.tfstate*"

# Remove from history if found
git filter-branch --force --index-filter \\
  "git rm --cached --ignore-unmatch '*.tfstate'" \\
  --prune-empty -- --all
''',
        }

    elif action == "audit_providers":
        content = tf_content or '''
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
'''

        findings = []

        # Check for hardcoded credentials
        if re.search(r'access_key\s*=\s*"[A-Z0-9]{16,}"', content):
            findings.append({
                "severity": "critical",
                "issue": "Hardcoded AWS access key in provider",
                "recommendation": "Use environment variables or instance profile",
            })

        if re.search(r'secret_key\s*=\s*".+"', content):
            findings.append({
                "severity": "critical",
                "issue": "Hardcoded AWS secret key in provider",
                "recommendation": "Use environment variables or instance profile",
            })

        if re.search(r'password\s*=\s*".+"', content):
            findings.append({
                "severity": "critical",
                "issue": "Hardcoded password in configuration",
                "recommendation": "Use variables with sensitive flag",
            })

        return {
            "action": "audit_providers",
            "findings": findings,
            "secure_provider_examples": {
                "aws_env_vars": '''
# Use environment variables
provider "aws" {
  region = var.region
  # AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from env
}
''',
                "aws_profile": '''
provider "aws" {
  region  = var.region
  profile = var.aws_profile
}
''',
                "aws_oidc": '''
# Use OIDC for CI/CD
provider "aws" {
  region = var.region
  assume_role {
    role_arn = "arn:aws:iam::ACCOUNT:role/terraform"
  }
}
''',
            },
            "provider_security_checklist": [
                "No hardcoded credentials",
                "Use assume_role for cross-account",
                "Pin provider versions",
                "Use verified providers only",
            ],
        }

    elif action == "check_secrets":
        content = tf_content or '''
resource "aws_db_instance" "default" {
  username = "admin"
  password = "SuperSecret123!"
}
'''

        secret_patterns = [
            (r'password\s*=\s*"[^"$]+"', "Hardcoded password"),
            (r'secret\s*=\s*"[^"$]+"', "Hardcoded secret"),
            (r'api_key\s*=\s*"[^"$]+"', "Hardcoded API key"),
            (r'access_key\s*=\s*"AKIA[A-Z0-9]{16}"', "AWS Access Key"),
            (r'private_key\s*=\s*"-----BEGIN', "Private key in config"),
            (r'token\s*=\s*"[^"$]+"', "Hardcoded token"),
        ]

        secrets_found = []
        for pattern, description in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                secrets_found.append({
                    "pattern": pattern,
                    "description": description,
                    "severity": "critical",
                })

        return {
            "action": "check_secrets",
            "secrets_found": secrets_found,
            "total_secrets": len(secrets_found),
            "secure_alternatives": {
                "sensitive_variable": '''
variable "db_password" {
  type      = string
  sensitive = true
}

resource "aws_db_instance" "default" {
  password = var.db_password
}
''',
                "secrets_manager": '''
data "aws_secretsmanager_secret_version" "db" {
  secret_id = "prod/db/password"
}

resource "aws_db_instance" "default" {
  password = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)["password"]
}
''',
                "vault": '''
data "vault_generic_secret" "db" {
  path = "secret/db"
}

resource "aws_db_instance" "default" {
  password = data.vault_generic_secret.db.data["password"]
}
''',
            },
            "scan_commands": {
                "trufflehog": "trufflehog filesystem --directory=. --include-paths '*.tf'",
                "gitleaks": "gitleaks detect --source=.",
                "tfsec": "tfsec . --include-passed",
            },
        }

    elif action == "analyze_permissions":
        content = tf_content or '''
resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.admin.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
'''

        findings = []

        # Check for wildcard actions
        if re.search(r'Action\s*=\s*"\*"', content) or re.search(r'"Action"\s*:\s*"\*"', content):
            findings.append({
                "severity": "critical",
                "issue": "Wildcard Action (*) in IAM policy",
                "recommendation": "Use specific actions following least privilege",
            })

        # Check for wildcard resources
        if re.search(r'Resource\s*=\s*"\*"', content) or re.search(r'"Resource"\s*:\s*"\*"', content):
            findings.append({
                "severity": "high",
                "issue": "Wildcard Resource (*) in IAM policy",
                "recommendation": "Scope resources to specific ARNs",
            })

        # Check for dangerous actions
        dangerous_actions = [
            "iam:*", "iam:CreatePolicyVersion", "iam:AttachUserPolicy",
            "sts:AssumeRole", "lambda:InvokeFunction", "ec2:*",
        ]
        for action_name in dangerous_actions:
            if action_name in content:
                findings.append({
                    "severity": "high",
                    "issue": f"Potentially dangerous action: {action_name}",
                    "recommendation": "Review if this action is necessary",
                })

        return {
            "action": "analyze_permissions",
            "findings": findings,
            "total_issues": len(findings),
            "least_privilege_example": '''
resource "aws_iam_role_policy" "app" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::my-bucket/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem"
        ]
        Resource = "arn:aws:dynamodb:*:*:table/my-table"
      }
    ]
  })
}
''',
            "policy_analyzer_tools": [
                "AWS IAM Access Analyzer",
                "Parliament - AWS IAM linter",
                "PMapper - IAM evaluation",
            ],
        }

    return generate_usage_hint("terraform_scanner", VALID_ACTIONS)
