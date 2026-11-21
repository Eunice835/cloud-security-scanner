"""Unit tests for EC2 scanner."""

from moto import mock_aws
import boto3

from cloud_security_scanner.scanners.ec2_scanner import scan_ec2


def _vpc_and_subnet(ec2):
    """Create VPC + subnet so moto attaches security groups to instances reliably."""
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(
        VpcId=vpc,
        CidrBlock="10.0.1.0/24",
        AvailabilityZone="us-east-1a",
    )["Subnet"]["SubnetId"]
    return vpc, subnet


@mock_aws
def test_ec2_open_ssh_finding() -> None:
    """Scanner reports open SSH security group rule."""
    boto3.setup_default_session(region_name="us-east-1")
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id, subnet_id = _vpc_and_subnet(ec2)
    group_id = ec2.create_security_group(
        GroupName="open-ssh-sg",
        Description="Open SSH",
        VpcId=vpc_id,
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    instance = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[group_id],
        SubnetId=subnet_id,
    )["Instances"][0]

    findings = scan_ec2()
    assert any(
        f["resource_id"] == instance["InstanceId"] and "critical ports" in f["issue"].lower()
        for f in findings
    )
