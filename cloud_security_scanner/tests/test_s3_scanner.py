"""Unit tests for S3 scanner."""

from moto import mock_aws
import boto3

from cloud_security_scanner.scanners.s3_scanner import scan_s3


@mock_aws
def test_s3_encryption_finding_when_missing() -> None:
    """Scanner reports missing S3 encryption."""
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket = "scanner-test-bucket"
    s3.create_bucket(Bucket=bucket)

    findings = scan_s3()
    assert any(
        f["resource_id"] == bucket and "encryption" in f["issue"].lower() for f in findings
    )

