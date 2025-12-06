"""Azure RBAC analyzer for security testing."""

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "analyze_assignments",
    "find_privesc",
    "check_custom_roles",
    "enumerate_principals",
    "check_managed_identities",
]


@register_tool(sandbox_execution=True)
def azure_rbac_analyzer(
    action: ToolAction,
    subscription_id: str | None = None,
    principal_id: str | None = None,
    role_name: str | None = None,
    scope: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Azure RBAC analyzer for security testing.

    Args:
        action: The action to perform
        subscription_id: Azure subscription ID
        principal_id: Principal to analyze
        role_name: Role to analyze
        scope: Resource scope

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "subscription_id", "principal_id", "role_name", "scope",
    }
    VALID_ACTIONS = [
        "analyze_assignments",
        "find_privesc",
        "check_custom_roles",
        "enumerate_principals",
        "check_managed_identities",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "azure_rbac_analyzer"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "azure_rbac_analyzer"):
        return action_error

    if action == "analyze_assignments":
        sub = subscription_id or "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

        high_risk_roles = [
            "Owner",
            "Contributor",
            "User Access Administrator",
            "Virtual Machine Contributor",
            "Storage Blob Data Owner",
            "Key Vault Administrator",
            "Automation Contributor",
        ]

        return {
            "action": "analyze_assignments",
            "subscription": sub,
            "high_risk_roles": high_risk_roles,
            "description": "Analyze Azure role assignments for security issues",
            "az_cli_commands": {
                "list_assignments": f"az role assignment list --subscription {sub} --all",
                "list_by_principal": f"az role assignment list --assignee PRINCIPAL_ID",
                "list_owners": f"az role assignment list --role Owner --subscription {sub}",
                "list_custom_roles": f"az role definition list --custom-role-only --subscription {sub}",
            },
            "powershell_commands": {
                "get_assignments": f"Get-AzRoleAssignment -Scope /subscriptions/{sub}",
                "get_privileged": "Get-AzRoleAssignment | Where-Object {$_.RoleDefinitionName -eq 'Owner'}",
            },
            "security_checks": [
                "Identify principals with Owner role",
                "Check for Contributor at subscription level",
                "Find User Access Administrator assignments",
                "Look for service principals with elevated access",
                "Check for custom roles with dangerous permissions",
            ],
            "python_analysis": f'''
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

credential = DefaultAzureCredential()
client = AuthorizationManagementClient(credential, "{sub}")

high_risk = ["Owner", "Contributor", "User Access Administrator"]

for assignment in client.role_assignments.list():
    role_def = client.role_definitions.get_by_id(assignment.role_definition_id)
    if role_def.role_name in high_risk:
        print(f"High Risk: {{assignment.principal_id}} has {{role_def.role_name}}")
''',
        }

    elif action == "find_privesc":
        sub = subscription_id or "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

        privesc_paths = [
            {
                "name": "Automation RunAs Account",
                "permissions": ["Microsoft.Automation/automationAccounts/write"],
                "description": "Create automation account with privileged RunAs identity",
                "severity": "critical",
                "exploit": "Create runbook that runs as privileged identity",
            },
            {
                "name": "VM Custom Script Extension",
                "permissions": ["Microsoft.Compute/virtualMachines/extensions/write"],
                "description": "Deploy script extension to run commands on VM",
                "severity": "high",
                "exploit": "Execute commands as SYSTEM via custom script",
            },
            {
                "name": "Key Vault Access Policy",
                "permissions": ["Microsoft.KeyVault/vaults/accessPolicies/write"],
                "description": "Modify Key Vault access to retrieve secrets",
                "severity": "critical",
                "exploit": "Grant self permission to read secrets/keys",
            },
            {
                "name": "Role Assignment",
                "permissions": ["Microsoft.Authorization/roleAssignments/write"],
                "description": "Create role assignments to escalate privileges",
                "severity": "critical",
                "exploit": "Assign Owner role to self",
            },
            {
                "name": "App Registration Credentials",
                "permissions": ["Microsoft.Authorization/*/write"],
                "description": "Add credentials to app registration",
                "severity": "high",
                "exploit": "Add secret to service principal with elevated access",
            },
            {
                "name": "Managed Identity",
                "permissions": ["Microsoft.ManagedIdentity/userAssignedIdentities/*/write"],
                "description": "Create or modify managed identities",
                "severity": "high",
                "exploit": "Attach privileged managed identity to VM",
            },
        ]

        return {
            "action": "find_privesc",
            "subscription": sub,
            "privilege_escalation_paths": privesc_paths,
            "test_commands": {
                "check_role_assignment": f'''
az role assignment create --role Owner --assignee USER_OBJECT_ID --scope /subscriptions/{sub}
# If this succeeds, user can escalate to Owner
''',
                "check_automation": f'''
az automation account list --subscription {sub}
# Look for accounts with privileged RunAs identities
''',
                "check_keyvault": f'''
az keyvault list --subscription {sub}
az keyvault show --name VAULT_NAME --query "properties.accessPolicies"
''',
            },
            "tools": [
                "azurehound - BloodHound for Azure",
                "ROADtools - Azure AD toolkit",
                "MicroBurst - Azure security framework",
                "PowerZure - Azure offensive toolkit",
            ],
        }

    elif action == "check_custom_roles":
        sub = subscription_id or "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

        dangerous_actions = [
            "*/write",
            "*/delete",
            "Microsoft.Authorization/*",
            "Microsoft.Compute/virtualMachines/*",
            "Microsoft.KeyVault/vaults/*",
            "Microsoft.Storage/storageAccounts/*",
            "Microsoft.Web/sites/*",
        ]

        return {
            "action": "check_custom_roles",
            "subscription": sub,
            "dangerous_actions_to_check": dangerous_actions,
            "description": "Analyze custom roles for overpermissive actions",
            "az_commands": {
                "list_custom": f"az role definition list --custom-role-only --subscription {sub}",
                "show_role": "az role definition list --name 'Custom Role Name'",
            },
            "analysis_query": f'''
# Find custom roles with wildcard actions
az role definition list --custom-role-only --subscription {sub} --query "[?contains(permissions[0].actions[0], '*')]"

# Find custom roles with authorization write
az role definition list --custom-role-only --query "[?contains(permissions[0].actions[], 'Microsoft.Authorization')]"
''',
            "powershell_analysis": '''
# Get all custom roles with dangerous permissions
Get-AzRoleDefinition -Custom | ForEach-Object {
    $role = $_
    $dangerous = $false

    foreach ($action in $role.Actions) {
        if ($action -match "\\*/write|\\*/delete|Microsoft.Authorization") {
            $dangerous = $true
            break
        }
    }

    if ($dangerous) {
        Write-Output "Dangerous Role: $($role.Name)"
        Write-Output "  Actions: $($role.Actions -join ', ')"
    }
}
''',
            "risk_indicators": [
                "Wildcard (*) in actions",
                "Authorization namespace access",
                "No NotActions restrictions",
                "Scope at subscription or management group level",
            ],
        }

    elif action == "enumerate_principals":
        sub = subscription_id or "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

        return {
            "action": "enumerate_principals",
            "subscription": sub,
            "description": "Enumerate principals with role assignments",
            "az_commands": {
                "list_all": f"az role assignment list --subscription {sub} --all --output table",
                "by_scope": f"az role assignment list --scope /subscriptions/{sub}",
                "service_principals": f'''
az role assignment list --subscription {sub} --query "[?principalType=='ServicePrincipal']"
''',
                "groups": f'''
az role assignment list --subscription {sub} --query "[?principalType=='Group']"
''',
            },
            "graph_api_query": '''
# Get service principal details
az ad sp show --id PRINCIPAL_ID

# List service principal app roles
az ad sp list --filter "servicePrincipalType eq 'Application'" --query "[].{Name:displayName,ID:appId}"
''',
            "analysis_steps": [
                "List all role assignments",
                "Identify service principals",
                "Check for guest users",
                "Find group-based assignments",
                "Trace effective permissions",
            ],
            "python_enumeration": f'''
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient

credential = DefaultAzureCredential()
client = AuthorizationManagementClient(credential, "{sub}")

principals = {{}}
for assignment in client.role_assignments.list():
    p_id = assignment.principal_id
    p_type = assignment.principal_type
    role = assignment.role_definition_id.split("/")[-1]

    if p_id not in principals:
        principals[p_id] = {{"type": p_type, "roles": []}}
    principals[p_id]["roles"].append(role)

# Print principals with multiple roles
for p_id, info in principals.items():
    if len(info["roles"]) > 1:
        print(f"{{p_id}} ({{info['type']}}): {{len(info['roles'])}} roles")
''',
        }

    elif action == "check_managed_identities":
        sub = subscription_id or "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

        return {
            "action": "check_managed_identities",
            "subscription": sub,
            "description": "Analyze managed identities for security issues",
            "az_commands": {
                "list_user_assigned": f"az identity list --subscription {sub}",
                "list_assignments": f'''
# Find VMs with managed identities
az vm list --subscription {sub} --query "[?identity!=null].{{name:name, identity:identity}}"

# Find App Services with managed identities
az webapp list --subscription {sub} --query "[?identity!=null].{{name:name, identity:identity}}"
''',
                "check_roles": "az role assignment list --assignee MANAGED_IDENTITY_PRINCIPAL_ID",
            },
            "security_concerns": [
                "User-assigned identities can be attached to multiple resources",
                "System-assigned identities provide resource-specific access",
                "Check for overpermissioned managed identities",
                "Managed identity credentials accessible from Azure IMDS",
            ],
            "exploitation": {
                "from_vm": '''
# Get managed identity token from VM
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
''',
                "from_function": '''
# In Azure Function, use managed identity
from azure.identity import DefaultAzureCredential
credential = DefaultAzureCredential()
# This will use the function's managed identity
''',
            },
            "mitigation_recommendations": [
                "Use system-assigned identities when possible",
                "Apply least-privilege to managed identity roles",
                "Monitor IMDS access from VMs",
                "Regularly audit managed identity usage",
            ],
        }

    return generate_usage_hint("azure_rbac_analyzer", VALID_ACTIONS)
