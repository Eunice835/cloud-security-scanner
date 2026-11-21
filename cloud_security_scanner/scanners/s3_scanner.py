"""S3 scanner for public exposure and encryption checks."""

from __future__ import annotations

from typing import Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloud_security_scanner.utils.severity import build_finding, load_cis_rules

SERVICE = "S3"


def _deduplicate_findings(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Remove identical findings while preserving order."""
    unique_findings: List[Dict[str, str]] = []
    seen = set()
    for finding in findings:
        key = (
            finding.get("service"),
            finding.get("resource_id"),
            finding.get("issue"),
            finding.get("severity"),
            finding.get("recommendation"),
            finding.get("cis_control_id"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)
    return unique_findings


def _list_all_buckets(s3_client) -> List[Dict]:
    """Return all S3 buckets in the account."""
    # S3 ListBuckets is account-scoped and not exposed as a paginator in boto3.
    return s3_client.list_buckets().get("Buckets", [])


def _check_bucket_public_access(s3_client, bucket_name: str, rules: Dict) -> List[Dict[str, str]]:
    """Check whether a bucket is publicly accessible via ACL or policy."""
    findings: List[Dict[str, str]] = []
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                findings.append(
                    build_finding(
                        SERVICE,
                        bucket_name,
                        "s3_public_access",
                        rules,
                        fallback_issue="S3 bucket is publicly accessible.",
                    )
                )
                break
    except (ClientError, BotoCoreError):
        findings.append(
            build_finding(
                SERVICE,
                bucket_name,
                "unable_validate_s3_public",
                rules,
                fallback_issue="Unable to validate S3 public access.",
            )
        )

    try:
        status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        if status.get("PolicyStatus", {}).get("IsPublic") is True:
            findings.append(
                build_finding(
                    SERVICE,
                    bucket_name,
                    "s3_public_access",
                    rules,
                    fallback_issue="S3 bucket policy allows public access.",
                )
            )
    except (ClientError, BotoCoreError):
        findings.append(
            build_finding(
                SERVICE,
                bucket_name,
                "unable_validate_s3_public",
                rules,
                fallback_issue="Unable to validate S3 bucket policy status.",
            )
        )
    return findings


def _check_bucket_encryption(s3_client, bucket_name: str, rules: Dict) -> List[Dict[str, str]]:
    """Check whether default bucket encryption is configured."""
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules_data = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not rules_data:
            return [
                build_finding(
                    SERVICE,
                    bucket_name,
                    "s3_encryption_disabled",
                    rules,
                    fallback_issue="S3 bucket encryption is not enabled.",
                )
            ]
        return []
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            return [
                build_finding(
                    SERVICE,
                    bucket_name,
                    "s3_encryption_disabled",
                    rules,
                    fallback_issue="S3 bucket encryption is not enabled.",
                )
            ]
        return [
            build_finding(
                SERVICE,
                bucket_name,
                "unable_validate_s3_encryption",
                rules,
                fallback_issue="Unable to validate S3 bucket encryption.",
            )
        ]
    except BotoCoreError:
        return [
            build_finding(
                SERVICE,
                bucket_name,
                "unable_validate_s3_encryption",
                rules,
                fallback_issue="Unable to validate S3 bucket encryption.",
            )
        ]


def scan_s3() -> List[Dict[str, str]]:
    """Scan all S3 buckets and return standardized findings."""
    s3_client = boto3.client("s3")
    rules = load_cis_rules()
    findings: List[Dict[str, str]] = []

    try:
        buckets = _list_all_buckets(s3_client)
    except (ClientError, BotoCoreError):
        return [
            build_finding(
                SERVICE,
                "account",
                "unable_validate_s3_list",
                rules,
                fallback_issue="Unable to list S3 buckets.",
            )
        ]

    for bucket in buckets:
        bucket_name = bucket.get("Name")
        if not bucket_name:
            continue
        findings.extend(_check_bucket_public_access(s3_client, bucket_name, rules))
        findings.extend(_check_bucket_encryption(s3_client, bucket_name, rules))
    return _deduplicate_findings(findings)

