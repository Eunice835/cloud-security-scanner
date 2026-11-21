"""Unit tests for IAM scanner."""

from moto import mock_aws
import boto3

from cloud_security_scanner.scanners.iam_scanner import scan_iam


@mock_aws
def test_iam_over_permissive_user_policy_finding() -> None:
    """Scanner reports wildcard IAM policy findings."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="bad-user")
    iam.put_user_policy(
        UserName="bad-user",
        PolicyName="wildcard-policy",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )

    findings = scan_iam()
    assert any(
        f["resource_id"] == "bad-user" and "over-permissive" in f["issue"].lower()
        for f in findings
    )

