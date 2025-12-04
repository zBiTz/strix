"""Cloud Enumeration Suite for discovering and testing cloud resources."""

from __future__ import annotations

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_unknown_params,
)


CloudAction = Literal["enumerate_s3", "enumerate_azure_blob", "enumerate_gcp_bucket", "generate_wordlist"]


@register_tool
def cloud_enumeration(
    action: CloudAction,
    target: str | None = None,
    company_name: str | None = None,
    region: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Cloud Enumeration Suite for discovering cloud resources.

    Helps discover and test cloud storage buckets, containers, and resources
    across AWS, Azure, and GCP.

    Args:
        action: The enumeration action:
            - enumerate_s3: Generate S3 bucket enumeration tests
            - enumerate_azure_blob: Generate Azure Blob storage tests
            - enumerate_gcp_bucket: Generate GCP bucket tests
            - generate_wordlist: Generate wordlist for bucket names
        target: Target to enumerate (bucket name, domain, etc.)
        company_name: Company name for generating bucket names
        region: Cloud region to target

    Returns:
        Enumeration results and test URLs
    """
    # Define valid parameters and actions
    VALID_PARAMS = {
        "action",
        "target",
        "company_name",
        "region",
    }
    VALID_ACTIONS = ["enumerate_s3", "enumerate_azure_blob", "enumerate_gcp_bucket", "generate_wordlist"]

    # Check for unknown parameters
    unknown_error = validate_unknown_params(kwargs, VALID_PARAMS, "cloud_enumeration")
    if unknown_error:
        unknown_error.update(
            generate_usage_hint("cloud_enumeration", "enumerate_s3", {"target": "company-data"})
        )
        return unknown_error

    # Validate action parameter
    action_error = validate_action_param(action, VALID_ACTIONS, "cloud_enumeration")
    if action_error:
        action_error["usage_examples"] = {
            "enumerate_s3": "cloud_enumeration(action='enumerate_s3', target='company-data')",
            "enumerate_azure_blob": "cloud_enumeration(action='enumerate_azure_blob', target='companydata')",
            "enumerate_gcp_bucket": "cloud_enumeration(action='enumerate_gcp_bucket', target='company-data')",
            "generate_wordlist": "cloud_enumeration(action='generate_wordlist', company_name='company')",
        }
        return action_error

    try:
        if action == "enumerate_s3":
            bucket_name = target or company_name or "example"
            region_str = region or "us-east-1"

            return {
                "bucket_name": bucket_name,
                "tests": [
                    {
                        "type": "Direct Access",
                        "url": f"https://{bucket_name}.s3.amazonaws.com",
                        "description": "Test if bucket exists and is publicly accessible",
                    },
                    {
                        "type": "Regional Endpoint",
                        "url": f"https://{bucket_name}.s3.{region_str}.amazonaws.com",
                        "description": "Test regional endpoint",
                    },
                    {
                        "type": "Path Style",
                        "url": f"https://s3.amazonaws.com/{bucket_name}",
                        "description": "Old path-style access",
                    },
                    {
                        "type": "List Objects",
                        "url": f"https://{bucket_name}.s3.amazonaws.com/?list-type=2",
                        "description": "Try to list bucket contents",
                    },
                ],
                "common_permissions_tests": [
                    {
                        "permission": "s3:ListBucket",
                        "test": "GET request to bucket URL",
                        "expected_200": "Bucket is publicly listable",
                        "expected_403": "Bucket exists but not listable",
                        "expected_404": "Bucket does not exist",
                    },
                    {
                        "permission": "s3:GetObject",
                        "test": "GET request to object URL",
                        "expected_200": "Object is publicly readable",
                    },
                    {
                        "permission": "s3:PutObject",
                        "test": "PUT request with test file",
                        "warning": "Only test on targets you own!",
                    },
                ],
                "bucket_naming_patterns": [
                    bucket_name,
                    f"{bucket_name}-prod",
                    f"{bucket_name}-dev",
                    f"{bucket_name}-backup",
                    f"{bucket_name}-files",
                    f"{bucket_name}-assets",
                    f"{bucket_name}-data",
                ],
            }

        if action == "enumerate_azure_blob":
            account_name = target or company_name or "example"

            return {
                "storage_account": account_name,
                "tests": [
                    {
                        "type": "Blob Service",
                        "url": f"https://{account_name}.blob.core.windows.net",
                        "description": "Test if storage account exists",
                    },
                    {
                        "type": "Container Listing",
                        "url": f"https://{account_name}.blob.core.windows.net/?comp=list",
                        "description": "Try to list containers",
                    },
                ],
                "common_container_names": [
                    "public",
                    "files",
                    "assets",
                    "data",
                    "backup",
                    "uploads",
                    "downloads",
                    "$web",  # Static website hosting
                    "$logs",  # Diagnostic logs
                ],
                "permissions_tests": [
                    {
                        "permission": "List Containers",
                        "test": "GET with ?comp=list",
                        "public_if": "Returns container list",
                    },
                    {
                        "permission": "List Blobs",
                        "test": "GET /<container>?restype=container&comp=list",
                        "public_if": "Returns blob list",
                    },
                ],
            }

        if action == "enumerate_gcp_bucket":
            bucket_name = target or company_name or "example"

            return {
                "bucket_name": bucket_name,
                "tests": [
                    {
                        "type": "Storage API",
                        "url": f"https://storage.googleapis.com/{bucket_name}",
                        "description": "Test if bucket exists and is accessible",
                    },
                    {
                        "type": "List Objects",
                        "url": f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o",
                        "description": "Try to list bucket objects via API",
                    },
                    {
                        "type": "Public Access",
                        "url": f"https://storage.cloud.google.com/{bucket_name}",
                        "description": "Test public access",
                    },
                ],
                "bucket_naming_patterns": [
                    bucket_name,
                    f"{bucket_name}-prod",
                    f"{bucket_name}-dev",
                    f"{bucket_name}.appspot.com",  # App Engine default
                    f"{bucket_name}-assets",
                    f"{bucket_name}-backup",
                ],
                "iam_tests": [
                    {
                        "role": "allUsers",
                        "description": "Bucket allows public access",
                        "test": "GET without authentication should succeed",
                    },
                    {
                        "role": "allAuthenticatedUsers",
                        "description": "Any authenticated user can access",
                        "test": "GET with any valid GCP auth",
                    },
                ],
            }

        if action == "generate_wordlist":
            company = company_name or "company"
            base_names = [
                company.lower(),
                company.lower().replace(" ", ""),
                company.lower().replace(" ", "-"),
                company.lower().replace(" ", "_"),
            ]

            suffixes = [
                "",
                "-prod",
                "-production",
                "-dev",
                "-development",
                "-test",
                "-staging",
                "-qa",
                "-backup",
                "-backups",
                "-files",
                "-assets",
                "-static",
                "-data",
                "-uploads",
                "-downloads",
                "-public",
                "-private",
                "-images",
                "-documents",
                "-logs",
                "-archive",
                "-storage",
            ]

            wordlist = []
            for base in base_names:
                for suffix in suffixes:
                    wordlist.append(base + suffix)

            return {
                "company_name": company,
                "wordlist_size": len(wordlist),
                "wordlist": wordlist,
                "usage": "Test each name against S3, Azure Blob, and GCP buckets",
            }

        return {"error": f"Unknown action: {action}"}

    except (ValueError, KeyError) as e:
        return {"error": f"Cloud enumeration failed: {e!s}"}
