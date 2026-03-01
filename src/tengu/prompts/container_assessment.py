"""Container and Kubernetes security assessment prompts."""

from __future__ import annotations


def container_assessment(target: str, scope: str = "image") -> str:
    """Container and Kubernetes security assessment workflow.

    Args:
        target: Docker image name, container ID, or Kubernetes cluster endpoint.
        scope: Assessment scope — image, compose, kubernetes, registry.
    """
    return f"""# Container Security Assessment: {target}

## Scope: {scope}

## Phase 1 — Image Vulnerability Scanning
1. `trivy_scan(target="{target}", scan_type="image", severity="HIGH,CRITICAL")` — CVE scan
2. `trivy_scan(target="{target}", scan_type="config")` — IaC/config misconfigurations
3. Check for secrets in image: `trivy_scan(target="{target}", scan_type="image")` — look for embedded credentials

## Phase 2 — IaC Security (Dockerfile, Compose, K8s manifests)
4. `checkov_scan(path="/path/to/Dockerfile", framework="dockerfile")` — Dockerfile best practices
5. `checkov_scan(path="/path/to/k8s/", framework="kubernetes")` — K8s manifests

## Phase 3 — Runtime Analysis
6. Check for privileged containers, mounted sensitive paths
7. Verify network policies and pod security standards
8. Check RBAC configuration for over-privileged service accounts

## Key Container Security Checks
- Running as root (should run as non-root user)
- Privileged mode enabled
- Read-only root filesystem (not set)
- Host network/PID/IPC namespaces shared
- Sensitive host paths mounted (/var/run/docker.sock, /etc, /proc)
- No resource limits (CPU/memory)
- Latest tag used (unpinned images)
- Secrets hardcoded as environment variables

## Expected Findings
- CVEs in base image and installed packages
- Dockerfile security anti-patterns
- Kubernetes RBAC misconfigurations
- Exposed secrets in image layers
- Missing security contexts"""


def cloud_assessment(provider: str, scope: str = "full", compliance: str = "") -> str:
    """Cloud security assessment workflow.

    Args:
        provider: Cloud provider — aws, azure, gcp.
        scope: Assessment scope — full, iam, network, storage, compute, serverless.
        compliance: Compliance framework — cis, pci-dss, hipaa, soc2, gdpr.
    """
    compliance_note = (
        f"\n## Compliance Framework: {compliance.upper()}\n- Map all findings to {compliance} requirements\n- Generate compliance report after assessment"
        if compliance
        else ""
    )

    return f"""# Cloud Security Assessment: {provider.upper()}

## Scope: {scope}{compliance_note}

## Phase 1 — Automated Cloud Audit
1. `scoutsuite_scan(provider="{provider}")` — comprehensive cloud configuration audit
2. Review ScoutSuite report for high/critical findings

## Phase 2 — IAM Review (Highest Priority)
3. Check for over-privileged IAM policies (AWS: AdministratorAccess, PowerUserAccess)
4. Verify MFA is enforced for all users
5. Check for inactive users and access keys older than 90 days
6. Review service account permissions

## Phase 3 — Network Security
7. Check security groups/firewall rules for 0.0.0.0/0 inbound on sensitive ports
8. Verify VPC flow logs are enabled
9. Check for publicly exposed resources (S3 buckets, databases, VMs)

## Phase 4 — Storage and Data
10. Check S3/Blob/GCS bucket permissions (public read/write)
11. Verify encryption at rest and in transit
12. Check for unencrypted snapshots

## Phase 5 — Monitoring and Logging
13. Verify CloudTrail/Activity Log/Cloud Audit is enabled
14. Check for GuardDuty/Defender/Security Command Center alerts
15. Verify log retention policies

## Provider-Specific Checks ({provider.upper()})
{"- AWS: Check for IMDSv1 (prefer IMDSv2), check Lambda permissions, check RDS public access" if provider == "aws" else ""}
{"- Azure: Check for classic resources, verify Defender for Cloud, check Azure AD conditional access" if provider == "azure" else ""}
{"- GCP: Check for OS login disabled, verify org policies, check default service account usage" if provider == "gcp" else ""}"""
