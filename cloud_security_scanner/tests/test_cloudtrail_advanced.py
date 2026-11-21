"""Unit tests for CloudTrail advanced scanner."""

from unittest.mock import patch

from moto import mock_aws
import boto3

from cloud_security_scanner.scanners.cloudtrail_advanced import scan_cloudtrail_advanced


@mock_aws
@patch(
    "cloud_security_scanner.scanners.cloudtrail_advanced._list_all_trails",
    autospec=True,
)
def test_cloudtrail_advanced_flags_single_region_and_logging_gaps(mock_list_trails) -> None:
    """
    Trails missing multi-region, CloudWatch Logs, and S3 access logging yield findings.

    ``describe_trails`` behavior varies across moto versions; the trail payload is stubbed
    while S3 APIs are exercised against moto.
    """
    boto3.setup_default_session(region_name="us-east-1")
    region = "us-east-1"
    bucket = "trail-log-bucket-test"
    s3 = boto3.client("s3", region_name=region)
    s3.create_bucket(Bucket=bucket)

    mock_list_trails.return_value = [
        {
            "Name": "unit-trail",
            "S3BucketName": bucket,
            "IsMultiRegionTrail": False,
        }
    ]

    findings = scan_cloudtrail_advanced()
    issues = " ".join(f["issue"].lower() for f in findings)
    assert "multi-region" in issues
    assert "cloudwatch" in issues
    assert "access logging" in issues
