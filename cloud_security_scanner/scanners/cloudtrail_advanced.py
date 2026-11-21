"""CloudTrail advanced scanner: multi-region, CloudWatch logs, S3 access logging."""

from __future__ import annotations

from typing import Dict, List, Set

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloud_security_scanner.utils.deduplication import deduplicate_findings
from cloud_security_scanner.utils.severity import build_finding, load_cis_rules

SERVICE = "CloudTrail"


def _list_all_trails(cloudtrail_client) -> List[Dict]:
    """List all CloudTrail trails with NextToken pagination."""
    trails: List[Dict] = []
    next_token = None
    while True:
        params: Dict = {"includeShadowTrails": False}
        if next_token:
            params["NextToken"] = next_token
        response = cloudtrail_client.describe_trails(**params)
        trails.extend(response.get("trailList", []))
        next_token = response.get("NextToken")
        if not next_token:
            break
    return trails


def _s3_client_for_bucket(bucket_name: str):
    """Create an S3 client in the bucket's region when possible."""
    s3_default = boto3.client("s3")
    try:
        location = s3_default.get_bucket_location(Bucket=bucket_name)
        constraint = location.get("LocationConstraint")
        region = constraint if constraint else "us-east-1"
        if region != s3_default.meta.region_name:
            return boto3.client("s3", region_name=region)
    except (ClientError, BotoCoreError):
        pass
    return s3_default


def scan_cloudtrail_advanced() -> List[Dict[str, str]]:
    """
    Verify multi-region coverage, CloudWatch Logs delivery, and S3 bucket access logging.

    Returns standardized findings.
    """
    cloudtrail_client = boto3.client("cloudtrail")
    rules = load_cis_rules()
    findings: List[Dict[str, str]] = []

    try:
        trails = _list_all_trails(cloudtrail_client)
    except (ClientError, BotoCoreError):
        return [
            build_finding(
                SERVICE,
                "account",
                "unable_validate_cloudtrail_advanced_list",
                rules,
                fallback_issue="Unable to list CloudTrail trails for advanced checks.",
            )
        ]

    if not trails:
        return [
            build_finding(
                SERVICE,
                "account",
                "cloudtrail_advanced_no_trails",
                rules,
                fallback_issue="No CloudTrail trails exist for advanced configuration checks.",
            )
        ]

    multi_region_ok = any(t.get("IsMultiRegionTrail") is True for t in trails)
    if not multi_region_ok:
        findings.append(
            build_finding(
                SERVICE,
                "account",
                "cloudtrail_not_multi_region",
                rules,
                fallback_issue="No multi-region CloudTrail trail is configured.",
            )
        )

    bucket_names_checked: Set[str] = set()

    for trail in trails:
        trail_name = trail.get("Name", "unknown-trail")
        bucket = trail.get("S3BucketName")

        if not trail.get("CloudWatchLogsLogGroupArn"):
            findings.append(
                build_finding(
                    SERVICE,
                    trail_name,
                    "cloudtrail_no_cloudwatch_logs",
                    rules,
                    fallback_issue="CloudTrail trail is not integrated with CloudWatch Logs.",
                )
            )

        if not bucket:
            findings.append(
                build_finding(
                    SERVICE,
                    trail_name,
                    "cloudtrail_missing_s3_bucket",
                    rules,
                    fallback_issue="CloudTrail trail has no S3 bucket configured.",
                )
            )
            continue

        if bucket in bucket_names_checked:
            continue
        bucket_names_checked.add(bucket)

        try:
            s3_client = _s3_client_for_bucket(bucket)
            logging = s3_client.get_bucket_logging(Bucket=bucket)
            if not logging.get("LoggingEnabled"):
                findings.append(
                    build_finding(
                        SERVICE,
                        bucket,
                        "cloudtrail_s3_bucket_no_access_logging",
                        rules,
                        fallback_issue=(
                            "S3 bucket used by CloudTrail has server access logging disabled."
                        ),
                    )
                )
        except (ClientError, BotoCoreError):
            findings.append(
                build_finding(
                    SERVICE,
                    bucket,
                    "unable_validate_cloudtrail_s3_logging",
                    rules,
                    fallback_issue="Unable to validate S3 access logging for CloudTrail bucket.",
                )
            )

    return deduplicate_findings(findings)
