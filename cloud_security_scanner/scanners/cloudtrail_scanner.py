"""CloudTrail scanner for trail existence and logging state."""

from __future__ import annotations

from typing import Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloud_security_scanner.utils.severity import build_finding, load_cis_rules

SERVICE = "CloudTrail"


def _deduplicate_findings(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Remove identical findings while preserving insertion order."""
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


def _list_all_trails(cloudtrail_client) -> List[Dict]:
    """List all CloudTrail trails with NextToken pagination."""
    trails: List[Dict] = []
    next_token = None
    while True:
        params = {"includeShadowTrails": False}
        if next_token:
            params["NextToken"] = next_token
        response = cloudtrail_client.describe_trails(**params)
        trails.extend(response.get("trailList", []))
        next_token = response.get("NextToken")
        if not next_token:
            break
    return trails


def scan_cloudtrail() -> List[Dict[str, str]]:
    """Scan CloudTrail configuration and return standardized findings."""
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
                "unable_validate_cloudtrail_list",
                rules,
                fallback_issue="Unable to list CloudTrail trails.",
            )
        ]

    if not trails:
        return [
            build_finding(
                SERVICE,
                "account",
                "cloudtrail_not_enabled",
                rules,
                fallback_issue="No CloudTrail trail is configured.",
            )
        ]

    for trail in trails:
        trail_name = trail.get("Name", "unknown-trail")
        try:
            status = cloudtrail_client.get_trail_status(Name=trail_name)
            if not status.get("IsLogging", False):
                findings.append(
                    build_finding(
                        SERVICE,
                        trail_name,
                        "cloudtrail_logging_disabled",
                        rules,
                        fallback_issue="CloudTrail logging is disabled.",
                    )
                )
        except (ClientError, BotoCoreError):
            findings.append(
                build_finding(
                    SERVICE,
                    trail_name,
                    "unable_validate_cloudtrail_status",
                    rules,
                    fallback_issue="Unable to validate CloudTrail trail status.",
                )
            )
    return _deduplicate_findings(findings)

