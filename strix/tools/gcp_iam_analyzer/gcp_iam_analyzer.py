"""GCP IAM policy analyzer for security testing."""

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "analyze_policy",
    "find_privesc",
    "check_bindings",
    "enumerate_permissions",
    "check_service_accounts",
]


@register_tool(sandbox_execution=True)
def gcp_iam_analyzer(
    action: ToolAction,
    policy: dict | None = None,
    project_id: str | None = None,
    principal: str | None = None,
    permission: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """GCP IAM policy analyzer for security testing.

    Args:
        action: The action to perform
        policy: IAM policy to analyze
        project_id: GCP project ID
        principal: Principal to analyze
        permission: Permission to check

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "policy", "project_id", "principal", "permission",
    }
    VALID_ACTIONS = [
        "analyze_policy",
        "find_privesc",
        "check_bindings",
        "enumerate_permissions",
        "check_service_accounts",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "gcp_iam_analyzer"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "gcp_iam_analyzer"):
        return action_error

    if action == "analyze_policy":
        sample_policy = policy or {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": ["user:admin@example.com"]
                },
                {
                    "role": "roles/editor",
                    "members": ["serviceAccount:compute@project.iam.gserviceaccount.com", "allUsers"]
                },
                {
                    "role": "roles/iam.securityAdmin",
                    "members": ["user:security@example.com"]
                },
            ]
        }

        findings = []
        high_risk_roles = [
            "roles/owner", "roles/editor", "roles/iam.admin",
            "roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin",
            "roles/compute.admin", "roles/storage.admin",
        ]

        for binding in sample_policy.get("bindings", []):
            role = binding.get("role", "")
            members = binding.get("members", [])

            # Check for public access
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                findings.append({
                    "severity": "critical",
                    "finding": f"Public access granted via {role}",
                    "members": members,
                    "recommendation": "Remove allUsers/allAuthenticatedUsers",
                })

            # Check high-risk roles
            if role in high_risk_roles:
                findings.append({
                    "severity": "high",
                    "finding": f"High-privilege role assigned: {role}",
                    "members": members,
                    "recommendation": "Review necessity of privileged access",
                })

            # Check for service account with privileged roles
            sa_members = [m for m in members if m.startswith("serviceAccount:")]
            if sa_members and role in high_risk_roles:
                findings.append({
                    "severity": "high",
                    "finding": f"Service account with privileged role: {role}",
                    "members": sa_members,
                    "recommendation": "Check for key exposure and impersonation risks",
                })

        return {
            "action": "analyze_policy",
            "policy_analyzed": sample_policy,
            "findings": findings,
            "total_bindings": len(sample_policy.get("bindings", [])),
            "risk_summary": {
                "critical": len([f for f in findings if f["severity"] == "critical"]),
                "high": len([f for f in findings if f["severity"] == "high"]),
            },
            "gcloud_commands": {
                "get_policy": f"gcloud projects get-iam-policy {project_id or 'PROJECT_ID'} --format=json",
                "list_roles": "gcloud iam roles list",
                "describe_role": "gcloud iam roles describe roles/editor",
            },
        }

    elif action == "find_privesc":
        proj = project_id or "target-project"

        privesc_paths = [
            {
                "name": "Service Account Key Creation",
                "permissions": ["iam.serviceAccountKeys.create"],
                "description": "Create keys for service accounts, impersonate them",
                "severity": "critical",
                "exploit": f"gcloud iam service-accounts keys create key.json --iam-account=SA@{proj}.iam.gserviceaccount.com",
            },
            {
                "name": "Service Account Token Creation",
                "permissions": ["iam.serviceAccounts.getAccessToken"],
                "description": "Generate access tokens for service accounts",
                "severity": "critical",
                "exploit": "Use generateAccessToken API to get SA token",
            },
            {
                "name": "IAM Policy Modification",
                "permissions": ["resourcemanager.projects.setIamPolicy"],
                "description": "Modify project IAM to grant self more permissions",
                "severity": "critical",
                "exploit": "Add owner role binding for current user",
            },
            {
                "name": "Compute Instance SA",
                "permissions": ["compute.instances.setServiceAccount", "compute.instances.create"],
                "description": "Attach privileged SA to compute instance",
                "severity": "high",
                "exploit": "Create instance with privileged SA, SSH in",
            },
            {
                "name": "Cloud Function Deploy",
                "permissions": ["cloudfunctions.functions.create"],
                "description": "Deploy function with privileged SA",
                "severity": "high",
                "exploit": "Deploy function that runs as privileged SA",
            },
            {
                "name": "Storage Bucket Escalation",
                "permissions": ["storage.buckets.setIamPolicy"],
                "description": "Modify bucket IAM, access sensitive data",
                "severity": "medium",
                "exploit": "Grant self objectViewer on bucket",
            },
        ]

        return {
            "action": "find_privesc",
            "project": proj,
            "privilege_escalation_paths": privesc_paths,
            "check_commands": {
                "test_sa_key": f"gcloud iam service-accounts keys create --iam-account=SA@{proj}.iam.gserviceaccount.com test.json",
                "test_setiam": f"gcloud projects get-iam-policy {proj} && gcloud projects set-iam-policy {proj} policy.yaml",
                "list_sas": f"gcloud iam service-accounts list --project={proj}",
            },
            "reference": "https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/",
        }

    elif action == "check_bindings":
        target_principal = principal or "user:test@example.com"
        proj = project_id or "target-project"

        return {
            "action": "check_bindings",
            "principal": target_principal,
            "project": proj,
            "description": "Find all role bindings for a specific principal",
            "gcloud_commands": {
                "project_roles": f'''
gcloud projects get-iam-policy {proj} --format=json | \\
  jq '.bindings[] | select(.members[] | contains("{target_principal}"))'
''',
                "org_roles": f'''
gcloud organizations get-iam-policy ORG_ID --format=json | \\
  jq '.bindings[] | select(.members[] | contains("{target_principal}"))'
''',
                "folder_roles": f'''
gcloud resource-manager folders get-iam-policy FOLDER_ID --format=json | \\
  jq '.bindings[] | select(.members[] | contains("{target_principal}"))'
''',
            },
            "python_check": f'''
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2

client = resourcemanager_v3.ProjectsClient()
policy = client.get_iam_policy(request={{"resource": "projects/{proj}"}})

principal = "{target_principal}"
for binding in policy.bindings:
    if principal in binding.members:
        print(f"Role: {{binding.role}}")
''',
            "inherited_roles_note": "Check org and folder level for inherited permissions",
        }

    elif action == "enumerate_permissions":
        target_perm = permission or "iam.serviceAccountKeys.create"

        dangerous_permissions = {
            "iam.serviceAccountKeys.create": {
                "risk": "Critical",
                "description": "Create service account keys for impersonation",
                "exploitation": "Generate key, authenticate as SA",
            },
            "iam.serviceAccounts.getAccessToken": {
                "risk": "Critical",
                "description": "Generate access tokens for any SA",
                "exploitation": "Direct SA impersonation",
            },
            "iam.serviceAccounts.signBlob": {
                "risk": "High",
                "description": "Sign arbitrary data as SA",
                "exploitation": "Forge signed URLs, JWTs",
            },
            "resourcemanager.projects.setIamPolicy": {
                "risk": "Critical",
                "description": "Modify project IAM policy",
                "exploitation": "Grant self any role",
            },
            "compute.instances.setMetadata": {
                "risk": "High",
                "description": "Modify instance metadata",
                "exploitation": "Add SSH keys, run startup scripts",
            },
            "cloudfunctions.functions.setIamPolicy": {
                "risk": "High",
                "description": "Modify function IAM",
                "exploitation": "Allow unauthenticated invocation",
            },
        }

        return {
            "action": "enumerate_permissions",
            "target_permission": target_perm,
            "permission_info": dangerous_permissions.get(target_perm, {
                "risk": "Unknown",
                "description": "Not in dangerous permissions database",
            }),
            "all_dangerous_permissions": list(dangerous_permissions.keys()),
            "test_permission": f'''
# Test if current user has permission
gcloud projects test-iam-permissions PROJECT_ID --permissions={target_perm}
''',
            "find_who_has": f'''
# Find who has this permission (requires analyze IAM policy)
gcloud asset analyze-iam-policy --organization=ORG_ID \\
  --full-resource-name=//cloudresourcemanager.googleapis.com/projects/PROJECT \\
  --permissions={target_perm}
''',
        }

    elif action == "check_service_accounts":
        proj = project_id or "target-project"

        return {
            "action": "check_service_accounts",
            "project": proj,
            "description": "Enumerate and analyze service accounts",
            "gcloud_commands": {
                "list_sas": f"gcloud iam service-accounts list --project={proj}",
                "list_sa_keys": f"gcloud iam service-accounts keys list --iam-account=SA@{proj}.iam.gserviceaccount.com",
                "get_sa_policy": f"gcloud iam service-accounts get-iam-policy SA@{proj}.iam.gserviceaccount.com",
                "check_impersonation": f'''
# Check who can impersonate this SA
gcloud iam service-accounts get-iam-policy SA@{proj}.iam.gserviceaccount.com | \\
  grep -A5 "roles/iam.serviceAccountTokenCreator"
''',
            },
            "security_checks": [
                "Look for user-managed keys (security risk)",
                "Check for overly permissive SA IAM policies",
                "Identify SAs with owner/editor roles",
                "Check for external SA impersonation rights",
                "Look for SAs not attached to resources (orphaned)",
            ],
            "key_risk_assessment": {
                "user_managed_keys": "High risk - keys can be exported and shared",
                "gcp_managed_keys": "Lower risk - rotated automatically",
                "key_age": "Keys > 90 days should be rotated",
            },
            "python_enumerate": f'''
from google.cloud import iam_admin_v1

client = iam_admin_v1.IAMClient()
project = "projects/{proj}"

# List all service accounts
for sa in client.list_service_accounts(name=project):
    print(f"SA: {{sa.email}}")

    # List keys for each SA
    keys = client.list_service_account_keys(name=sa.name)
    for key in keys.keys:
        print(f"  Key: {{key.name}} Valid: {{key.valid_after_time}} - {{key.valid_before_time}}")
''',
        }

    return generate_usage_hint("gcp_iam_analyzer", VALID_ACTIONS)
