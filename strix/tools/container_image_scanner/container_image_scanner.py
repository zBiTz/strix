"""Container image scanner for vulnerabilities and misconfigurations."""

from typing import Any, Literal

from strix.tools.registry import register_tool
from strix.tools.validation import (
    generate_usage_hint,
    validate_action_param,
    validate_required_param,
    validate_unknown_params,
)

ToolAction = Literal[
    "scan_vulnerabilities",
    "check_secrets",
    "analyze_layers",
    "check_configs",
    "scan_sbom",
]


@register_tool(sandbox_execution=True)
def container_image_scanner(
    action: ToolAction,
    image: str | None = None,
    dockerfile: str | None = None,
    registry: str | None = None,
    **kwargs: Any,
) -> dict[str, Any] | str:
    """Container image scanner for vulnerabilities and misconfigurations.

    Args:
        action: The action to perform
        image: Container image name/tag
        dockerfile: Dockerfile content
        registry: Container registry URL

    Returns:
        Results dict or error message
    """
    VALID_PARAMS = {
        "action", "image", "dockerfile", "registry",
    }
    VALID_ACTIONS = [
        "scan_vulnerabilities",
        "check_secrets",
        "analyze_layers",
        "check_configs",
        "scan_sbom",
    ]

    if unknown_error := validate_unknown_params(kwargs, VALID_PARAMS, "container_image_scanner"):
        return unknown_error

    if action_error := validate_action_param(action, VALID_ACTIONS, "container_image_scanner"):
        return action_error

    if action == "scan_vulnerabilities":
        img = image or "nginx:latest"
        reg = registry or "docker.io"

        return {
            "action": "scan_vulnerabilities",
            "image": img,
            "registry": reg,
            "description": "Scan container image for known vulnerabilities",
            "scanner_commands": {
                "trivy": f"trivy image {img} --severity HIGH,CRITICAL",
                "grype": f"grype {img}",
                "clair": f"clairctl analyze {img}",
                "snyk": f"snyk container test {img}",
            },
            "trivy_full": f'''
# Full vulnerability scan
trivy image {img} --format json --output result.json

# Scan with specific severity
trivy image {img} --severity CRITICAL

# Ignore unfixed vulnerabilities
trivy image {img} --ignore-unfixed

# Scan offline (air-gapped)
trivy image --offline-scan {img}
''',
            "grype_scan": f'''
# Scan with grype
grype {img} -o json > vulnerabilities.json

# Only show fixes available
grype {img} --only-fixed
''',
            "vulnerability_priorities": [
                "CRITICAL: Actively exploited or RCE",
                "HIGH: Exploitable with significant impact",
                "MEDIUM: Requires specific conditions",
                "LOW: Minor impact or difficult to exploit",
            ],
            "common_vulnerable_packages": [
                "OpenSSL (heartbleed, etc.)",
                "glibc (ghost, etc.)",
                "curl/libcurl",
                "Apache/nginx",
                "Python packages",
                "Node.js dependencies",
            ],
        }

    elif action == "check_secrets":
        img = image or "myapp:latest"

        return {
            "action": "check_secrets",
            "image": img,
            "description": "Check container image for embedded secrets",
            "scan_commands": {
                "trivy_secret": f"trivy image {img} --scanners secret",
                "trufflehog": f"trufflehog docker --image={img}",
                "ggshield": f"ggshield secret scan docker {img}",
            },
            "manual_inspection": f'''
# Extract and analyze layers
docker save {img} -o image.tar
tar -xf image.tar
for layer in */layer.tar; do
    tar -tf "$layer" | grep -iE "\\.(env|key|pem|p12|pfx|json|yaml|yml|conf|config)$"
done

# Look for common secret patterns
docker history {img} --no-trunc | grep -iE "(password|secret|key|token|api)"
''',
            "secrets_to_find": [
                "API keys and tokens",
                "Database credentials",
                "Private keys (.pem, .key)",
                "Environment files (.env)",
                "Cloud credentials (AWS, GCP, Azure)",
                "SSH keys",
                "Certificates with private keys",
            ],
            "layer_analysis": f'''
# Use dive to analyze layers interactively
dive {img}

# Or use docker history
docker history --no-trunc {img}
''',
            "prevention": [
                "Use multi-stage builds",
                "Never COPY secrets into image",
                "Use secrets managers at runtime",
                "Use Docker secrets or Kubernetes secrets",
                "Scan images in CI/CD pipeline",
            ],
        }

    elif action == "analyze_layers":
        img = image or "myapp:latest"

        return {
            "action": "analyze_layers",
            "image": img,
            "description": "Analyze container image layers for security issues",
            "analysis_commands": {
                "dive": f"dive {img}",
                "docker_history": f"docker history --no-trunc {img}",
                "docker_inspect": f"docker inspect {img}",
            },
            "dive_usage": f'''
# Interactive layer analysis
dive {img}

# CI mode for automated checks
CI=true dive {img} --ci-config=.dive-ci

# Export analysis
dive {img} --json > analysis.json
''',
            "things_to_look_for": [
                "Large layers (may contain build artifacts)",
                "Layers with sensitive files added then removed",
                "Unnecessary packages in final image",
                "Cache directories left in image",
                "Build tools in production image",
            ],
            "layer_extraction": f'''
# Extract image to analyze layers
docker save {img} > image.tar
mkdir -p image_layers
cd image_layers
tar -xf ../image.tar

# Each layer is a tar file
for layer in */layer.tar; do
    echo "=== $layer ==="
    tar -tf "$layer" | head -20
done
''',
            "optimization_tips": [
                "Use multi-stage builds to reduce size",
                "Combine RUN commands to reduce layers",
                "Remove package manager cache",
                "Use .dockerignore to exclude files",
                "Use distroless or alpine base images",
            ],
        }

    elif action == "check_configs":
        df = dockerfile or '''
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
COPY . /app
RUN chmod 777 /app
USER root
EXPOSE 22
CMD ["./app"]
'''

        findings = []

        # Check for root user
        if "USER root" in df or "USER" not in df:
            findings.append({
                "severity": "high",
                "issue": "Container runs as root",
                "recommendation": "Add USER directive with non-root user",
            })

        # Check for latest tag
        if ":latest" in df or "FROM" in df and ":" not in df.split("FROM")[1].split()[0]:
            findings.append({
                "severity": "medium",
                "issue": "Using 'latest' or unpinned base image tag",
                "recommendation": "Pin to specific version/digest",
            })

        # Check for SSH exposure
        if "EXPOSE 22" in df:
            findings.append({
                "severity": "high",
                "issue": "SSH port exposed",
                "recommendation": "Remove SSH from container",
            })

        # Check for overly permissive permissions
        if "chmod 777" in df:
            findings.append({
                "severity": "medium",
                "issue": "Overly permissive file permissions",
                "recommendation": "Use least privilege permissions",
            })

        # Check for package manager cleanup
        if "apt-get install" in df and "rm -rf /var/lib/apt/lists" not in df:
            findings.append({
                "severity": "low",
                "issue": "Package manager cache not cleaned",
                "recommendation": "Add cleanup to reduce image size",
            })

        return {
            "action": "check_configs",
            "dockerfile_analyzed": True,
            "findings": findings,
            "total_issues": len(findings),
            "scanner_commands": {
                "hadolint": "hadolint Dockerfile",
                "dockle": f"dockle {image or 'myimage'}",
                "trivy_config": f"trivy config --severity HIGH,CRITICAL .",
            },
            "secure_dockerfile_example": '''
# Use specific version and digest
FROM python:3.11-slim@sha256:abc123...

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Set working directory
WORKDIR /app

# Copy requirements first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

# Use exec form for CMD
CMD ["python", "app.py"]
''',
        }

    elif action == "scan_sbom":
        img = image or "myapp:latest"

        return {
            "action": "scan_sbom",
            "image": img,
            "description": "Generate and analyze Software Bill of Materials",
            "sbom_generators": {
                "syft": f"syft {img} -o spdx-json > sbom.json",
                "trivy": f"trivy image {img} --format spdx-json > sbom.json",
                "docker_sbom": f"docker sbom {img}",
            },
            "sbom_analysis": f'''
# Generate SBOM with syft
syft {img} -o spdx-json > sbom.json

# Scan SBOM for vulnerabilities
grype sbom:sbom.json

# Generate CycloneDX format
syft {img} -o cyclonedx-json > sbom-cyclonedx.json
''',
            "sbom_formats": {
                "spdx": "Standard SBOM format (ISO standard)",
                "cyclonedx": "OWASP CycloneDX format",
                "syft-json": "Anchore Syft native format",
            },
            "supply_chain_checks": [
                "Verify base image signatures",
                "Check for known vulnerable components",
                "Identify outdated dependencies",
                "Track package licenses",
                "Monitor for new CVEs",
            ],
            "cosign_verification": f'''
# Verify image signature with cosign
cosign verify {img}

# Check attestations
cosign verify-attestation {img}

# Download SBOM attestation
cosign download attestation {img} | jq -r '.payload' | base64 -d
''',
            "continuous_monitoring": [
                "Integrate SBOM generation in CI/CD",
                "Store SBOMs with image registry",
                "Monitor for new vulnerabilities",
                "Set up alerts for critical CVEs",
            ],
        }

    return generate_usage_hint("container_image_scanner", VALID_ACTIONS)
