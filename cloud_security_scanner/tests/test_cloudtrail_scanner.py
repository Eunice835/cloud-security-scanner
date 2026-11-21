"""Unit tests for CloudTrail scanner."""

from moto import mock_aws
import boto3

from cloud_security_scanner.scanners.cloudtrail_scanner import scan_cloudtrail


@mock_aws
def test_cloudtrail_missing_trail_finding() -> None:
    """Scanner reports when no CloudTrail trails exist."""
    boto3.client("cloudtrail", region_name="us-east-1")
    findings = scan_cloudtrail()
    assert any("not enabled" in f["issue"].lower() for f in findings)

