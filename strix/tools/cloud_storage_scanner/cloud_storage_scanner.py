"""Cloud storage security scanner for S3, GCS, and Azure Blob."""

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "scan_s3",
    "scan_gcs",
    "scan_azure_blob",
    "check_permissions",
    "find_sensitive",
]


@register_tool(sandbox_execution=True)
def cloud_storage_scanner(
    action: ToolAction,
    bucket_name: str | None = None,
    container_name: str | None = None,
    region: str | None = None,
    project_id: str | None = None,
    storage_account: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Cloud storage security scanner for S3, GCS, and Azure Blob.

    Args:
        action: The action to perform
        bucket_name: S3/GCS bucket name
        container_name: Azure blob container name
        region: AWS/Azure region
        project_id: GCP project ID
        storage_account: Azure storage account name

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "bucket_name", "container_name", "region",
        "project_id", "storage_account",
    }
    VALID_ACTIONS = [
        "scan_s3",
        "scan_gcs",
        "scan_azure_blob",
        "check_permissions",
        "find_sensitive",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "cloud_storage_scanner"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "cloud_storage_scanner"):
        return action_error

    if action == "scan_s3":
        bucket = bucket_name or "target-bucket"
        aws_region = region or "us-east-1"

        return {
            "action": "scan_s3",
            "bucket": bucket,
            "region": aws_region,
            "description": "Scan AWS S3 bucket for security misconfigurations",
            "checks": [
                "Public access settings",
                "Bucket policy permissions",
                "ACL configuration",
                "Encryption at rest",
                "Versioning status",
                "Logging configuration",
            ],
            "aws_cli_commands": {
                "check_public_access": f"aws s3api get-public-access-block --bucket {bucket}",
                "get_bucket_policy": f"aws s3api get-bucket-policy --bucket {bucket}",
                "get_bucket_acl": f"aws s3api get-bucket-acl --bucket {bucket}",
                "check_encryption": f"aws s3api get-bucket-encryption --bucket {bucket}",
                "check_versioning": f"aws s3api get-bucket-versioning --bucket {bucket}",
                "list_objects": f"aws s3 ls s3://{bucket}/ --recursive",
            },
            "anonymous_access_test": f'''
# Test anonymous read access
curl -I https://{bucket}.s3.{aws_region}.amazonaws.com/
curl -I https://{bucket}.s3.amazonaws.com/

# Test anonymous list
curl "https://{bucket}.s3.amazonaws.com/?list-type=2"
''',
            "python_scan": f'''
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client('s3', region_name='{aws_region}')
bucket = '{bucket}'

# Check public access block
try:
    pab = s3.get_public_access_block(Bucket=bucket)
    print(f"Public Access Block: {{pab['PublicAccessBlockConfiguration']}}")
except ClientError as e:
    if 'NoSuchPublicAccessBlockConfiguration' in str(e):
        print("[!] No public access block - bucket may be public!")

# Check bucket policy
try:
    policy = s3.get_bucket_policy(Bucket=bucket)
    print(f"Bucket Policy: {{policy['Policy']}}")
except ClientError:
    print("No bucket policy")

# Check ACL
acl = s3.get_bucket_acl(Bucket=bucket)
for grant in acl['Grants']:
    grantee = grant['Grantee']
    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
        print(f"[!] PUBLIC ACCESS via ACL: {{grant['Permission']}}")
''',
            "common_vulnerabilities": [
                "Public read access enabled",
                "Public write access (critical)",
                "Overly permissive bucket policy",
                "AllUsers or AuthenticatedUsers in ACL",
                "No encryption at rest",
                "Disabled versioning (ransomware risk)",
            ],
        }

    elif action == "scan_gcs":
        bucket = bucket_name or "target-bucket"
        proj = project_id or "target-project"

        return {
            "action": "scan_gcs",
            "bucket": bucket,
            "project": proj,
            "description": "Scan GCS bucket for security misconfigurations",
            "gcloud_commands": {
                "get_iam": f"gsutil iam get gs://{bucket}",
                "check_public": f"gsutil ls -L gs://{bucket}",
                "check_acl": f"gsutil acl get gs://{bucket}",
                "list_objects": f"gsutil ls -r gs://{bucket}",
            },
            "anonymous_access_test": f'''
# Test anonymous access
curl "https://storage.googleapis.com/{bucket}/"
curl "https://storage.googleapis.com/storage/v1/b/{bucket}/o"
''',
            "python_scan": f'''
from google.cloud import storage

client = storage.Client(project='{proj}')
bucket = client.bucket('{bucket}')

# Get IAM policy
policy = bucket.get_iam_policy()
for binding in policy.bindings:
    if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
        print(f"[!] PUBLIC ACCESS: {{binding['role']}}")

# Check uniform bucket-level access
bucket.reload()
if bucket.iam_configuration.uniform_bucket_level_access_enabled:
    print("[+] Uniform bucket-level access enabled")
else:
    print("[!] Legacy ACLs may be in use")
''',
            "risky_iam_bindings": [
                "allUsers with roles/storage.objectViewer",
                "allUsers with roles/storage.objectCreator",
                "allAuthenticatedUsers with any role",
            ],
        }

    elif action == "scan_azure_blob":
        account = storage_account or "targetstorageaccount"
        container = container_name or "data"

        return {
            "action": "scan_azure_blob",
            "storage_account": account,
            "container": container,
            "description": "Scan Azure Blob Storage for security misconfigurations",
            "az_commands": {
                "list_containers": f"az storage container list --account-name {account}",
                "check_public_access": f"az storage container show --name {container} --account-name {account} --query publicAccess",
                "check_account_settings": f"az storage account show --name {account}",
            },
            "anonymous_access_test": f'''
# Test anonymous blob access
curl "https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"

# Test anonymous blob read
curl "https://{account}.blob.core.windows.net/{container}/filename"
''',
            "powershell_scan": f'''
$context = New-AzStorageContext -StorageAccountName "{account}"

# Check container public access
Get-AzStorageContainer -Context $context | ForEach-Object {{
    if ($_.PublicAccess -ne "Off") {{
        Write-Host "[!] Public container: $($_.Name) - $($_.PublicAccess)"
    }}
}}

# Check for anonymous access
Get-AzStorageAccount -Name "{account}" | Select-Object AllowBlobPublicAccess
''',
            "public_access_levels": {
                "Off": "No anonymous access (secure)",
                "Blob": "Anonymous read for blobs only",
                "Container": "Anonymous read for container and blobs",
            },
            "security_recommendations": [
                "Disable public blob access at account level",
                "Use Azure AD authentication",
                "Enable soft delete for recovery",
                "Use private endpoints for network isolation",
                "Enable storage analytics logging",
            ],
        }

    elif action == "check_permissions":
        bucket = bucket_name or "target-bucket"

        return {
            "action": "check_permissions",
            "bucket": bucket,
            "description": "Check storage permissions and access controls",
            "dangerous_permissions": {
                "aws_s3": [
                    "s3:GetObject (if public)",
                    "s3:PutObject (write access)",
                    "s3:DeleteObject",
                    "s3:PutBucketPolicy",
                    "s3:PutBucketAcl",
                ],
                "gcp_gcs": [
                    "storage.objects.get (if allUsers)",
                    "storage.objects.create",
                    "storage.objects.delete",
                    "storage.buckets.setIamPolicy",
                ],
                "azure_blob": [
                    "Microsoft.Storage/storageAccounts/write",
                    "Microsoft.Storage/storageAccounts/blobServices/containers/write",
                ],
            },
            "permission_test_aws": f'''
# Test what operations you can perform
aws s3api head-bucket --bucket {bucket} 2>&1
aws s3 cp test.txt s3://{bucket}/ 2>&1
aws s3 ls s3://{bucket}/ 2>&1
''',
            "unauthenticated_tests": {
                "s3": f"curl -s https://{bucket}.s3.amazonaws.com/ | head",
                "gcs": f"curl -s https://storage.googleapis.com/{bucket}/ | head",
                "azure": f"curl -s https://{bucket}.blob.core.windows.net/?comp=list | head",
            },
        }

    elif action == "find_sensitive":
        bucket = bucket_name or "target-bucket"

        sensitive_patterns = [
            {"pattern": "*.sql", "description": "Database dumps"},
            {"pattern": "*.bak", "description": "Backup files"},
            {"pattern": "*.key", "description": "Private keys"},
            {"pattern": "*.pem", "description": "Certificates/keys"},
            {"pattern": "*.env", "description": "Environment files"},
            {"pattern": "*password*", "description": "Password files"},
            {"pattern": "*secret*", "description": "Secret files"},
            {"pattern": "*credential*", "description": "Credentials"},
            {"pattern": "*.tfstate", "description": "Terraform state"},
            {"pattern": "*.log", "description": "Log files"},
        ]

        return {
            "action": "find_sensitive",
            "bucket": bucket,
            "sensitive_patterns": sensitive_patterns,
            "search_commands": {
                "aws_s3": f'''
# Search for sensitive files
aws s3 ls s3://{bucket}/ --recursive | grep -iE "\\.(sql|bak|key|pem|env|log)$"
aws s3 ls s3://{bucket}/ --recursive | grep -iE "(password|secret|credential|backup)"
''',
                "gcs": f'''
gsutil ls -r gs://{bucket}/** | grep -iE "\\.(sql|bak|key|pem|env|log)$"
''',
                "azure": f'''
az storage blob list --container-name data --account-name {bucket} --query "[?contains(name, 'password') || contains(name, '.env')]"
''',
            },
            "trufflehog_scan": f'''
# Scan for secrets in bucket contents
trufflehog s3 --bucket={bucket}
''',
            "common_sensitive_data": [
                "Database backups with credentials",
                "Application configuration files",
                "Private keys and certificates",
                "Log files with sensitive data",
                "Terraform state (contains secrets)",
                "Docker configs and compose files",
            ],
        }

    return generate_usage_hint("cloud_storage_scanner", VALID_ACTIONS)
