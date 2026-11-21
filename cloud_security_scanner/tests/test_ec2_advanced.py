"""Unit tests for EC2 advanced scanner."""

from moto import mock_aws
import boto3

from cloud_security_scanner.scanners.ec2_advanced import scan_ec2_advanced


def _vpc_and_subnet(ec2):
    """Create a minimal VPC and subnet so instances retain security group metadata in moto."""
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.0.0.0/24",
        AvailabilityZone="us-east-1a",
    )["Subnet"]["SubnetId"]
    return vpc, subnet


@mock_aws
def test_ec2_advanced_detects_nonstandard_public_port() -> None:
    """Public TCP port outside standard set raises a finding."""
    boto3.setup_default_session(region_name="us-east-1")
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id, subnet_id = _vpc_and_subnet(ec2)
    sg = ec2.create_security_group(
        GroupName="pub-8080",
        Description="public 8080",
        VpcId=vpc_id,
    )
    gid = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 8080,
                "ToPort": 8080,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    resp = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[gid],
        SubnetId=subnet_id,
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    findings = scan_ec2_advanced()
    assert any(
        f["resource_id"] == instance_id and "non-standard" in f["issue"].lower()
        for f in findings
    )


@mock_aws
def test_ec2_advanced_detects_unencrypted_volume() -> None:
    """Unencrypted EBS volume triggers encryption finding."""
    boto3.setup_default_session(region_name="us-east-1")
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vol = ec2.create_volume(Size=8, AvailabilityZone="us-east-1a", Encrypted=False)
    vid = vol["VolumeId"]

    findings = scan_ec2_advanced()
    assert any(
        f["resource_id"] == vid and "not encrypted" in f["issue"].lower() for f in findings
    )
