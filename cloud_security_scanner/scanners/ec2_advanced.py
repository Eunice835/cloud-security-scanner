"""EC2 advanced scanner: extra public ports, EBS encryption, instance IAM roles."""

from __future__ import annotations

from typing import Dict, List, Set

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloud_security_scanner.utils.deduplication import deduplicate_findings
from cloud_security_scanner.utils.severity import build_finding, load_cis_rules

SERVICE = "EC2"
STANDARD_PUBLIC_PORTS = {22, 80, 443, 3389}
SECURITY_GROUP_BATCH_SIZE = 100


def _chunked(values: List[str], size: int) -> List[List[str]]:
    """Split a list into fixed-size chunks."""
    return [values[idx : idx + size] for idx in range(0, len(values), size)]


def _paginate_instances(ec2_client) -> List[Dict]:
    """Paginate through all EC2 instance reservation pages."""
    paginator = ec2_client.get_paginator("describe_instances")
    reservations: List[Dict] = []
    for page in paginator.paginate():
        reservations.extend(page.get("Reservations", []))
    return reservations


def _paginate_volumes(ec2_client) -> List[Dict]:
    """Paginate describe_volumes for all volumes in the region."""
    paginator = ec2_client.get_paginator("describe_volumes")
    volumes: List[Dict] = []
    for page in paginator.paginate():
        volumes.extend(page.get("Volumes", []))
    return volumes


def _is_public_ipv4_permission(permission: Dict) -> bool:
    """Return True if rule allows 0.0.0.0/0 from IPv4 ranges."""
    for ip_range in permission.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            return True
    return False


def _nonstandard_exposed_ports(permission: Dict) -> List[int]:
    """
    Return TCP ports (from public 0.0.0.0/0 rule) outside the standard set.

    Does not include UDP-only rules. All-protocols (-1) public is treated separately.
    """
    if not _is_public_ipv4_permission(permission):
        return []

    protocol = permission.get("IpProtocol")
    if protocol == "-1" or protocol is None:
        return []
    proto_norm = str(protocol).lower()
    if proto_norm not in {"tcp", "6"}:
        return []

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return []

    exposed: List[int] = []
    for port in range(int(from_port), int(to_port) + 1):
        if port not in STANDARD_PUBLIC_PORTS:
            exposed.append(port)
    return exposed


def _has_all_protocols_public(ip_permissions: List[Dict]) -> bool:
    """Return True if a rule allows all protocols from 0.0.0.0/0."""
    for permission in ip_permissions:
        if permission.get("IpProtocol") == "-1" and _is_public_ipv4_permission(permission):
            return True
    return False


def _collect_nonstandard_public_ports(ip_permissions: List[Dict]) -> Set[int]:
    """Unique set of publicly exposed TCP ports outside the standard list."""
    ports: Set[int] = set()
    for permission in ip_permissions:
        for port in _nonstandard_exposed_ports(permission):
            ports.add(port)
    return ports


def scan_ec2_advanced() -> List[Dict[str, str]]:
    """
    Run advanced EC2 checks: non-standard public ports, unencrypted EBS, no IAM role.

    Returns a list of standardized findings.
    """
    ec2_client = boto3.client("ec2")
    rules = load_cis_rules()
    findings: List[Dict[str, str]] = []

    try:
        reservations = _paginate_instances(ec2_client)
    except (ClientError, BotoCoreError):
        return [
            build_finding(
                SERVICE,
                "account",
                "unable_validate_ec2_advanced_list",
                rules,
                fallback_issue="Unable to list EC2 instances for advanced checks.",
            )
        ]

    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            state = instance.get("State", {}).get("Name", "")
            if state in {"terminated", "shutting-down"}:
                continue

            instance_id = instance.get("InstanceId", "unknown-instance")

            if not instance.get("IamInstanceProfile"):
                findings.append(
                    build_finding(
                        SERVICE,
                        instance_id,
                        "ec2_no_iam_instance_profile",
                        rules,
                        fallback_issue="EC2 instance has no IAM instance profile attached.",
                    )
                )

            security_group_ids = sorted(
                {
                    sg.get("GroupId")
                    for sg in instance.get("SecurityGroups", [])
                    if sg.get("GroupId")
                }
            )

            if security_group_ids:
                try:
                    for group_batch in _chunked(security_group_ids, SECURITY_GROUP_BATCH_SIZE):
                        groups = ec2_client.describe_security_groups(
                            GroupIds=group_batch
                        ).get("SecurityGroups", [])
                        for group in groups:
                            ip_permissions = group.get("IpPermissions", [])
                            if _has_all_protocols_public(ip_permissions):
                                findings.append(
                                    build_finding(
                                        SERVICE,
                                        instance_id,
                                        "ec2_sg_all_protocols_public",
                                        rules,
                                        fallback_issue=(
                                            "EC2 security group allows all protocols from the internet."
                                        ),
                                    )
                                )
                            extra_ports = _collect_nonstandard_public_ports(ip_permissions)
                            if extra_ports:
                                port_list = ",".join(str(p) for p in sorted(extra_ports)[:20])
                                if len(extra_ports) > 20:
                                    port_list += ",…"
                                sg_id = group.get("GroupId", "")
                                findings.append(
                                    build_finding(
                                        SERVICE,
                                        instance_id,
                                        "ec2_sg_nonstandard_ports_public",
                                        rules,
                                        fallback_issue=(
                                            f"EC2 security group {sg_id} exposes non-standard "
                                            f"TCP ports to the internet: {port_list}."
                                        ),
                                    )
                                )
                except (ClientError, BotoCoreError):
                    findings.append(
                        build_finding(
                            SERVICE,
                            instance_id,
                            "unable_validate_ec2_advanced_sg",
                            rules,
                            fallback_issue="Unable to validate EC2 security groups (advanced).",
                        )
                    )

    try:
        volumes = _paginate_volumes(ec2_client)
        for vol in volumes:
            if vol.get("Encrypted") is True:
                continue
            vid = vol.get("VolumeId", "unknown-volume")
            findings.append(
                build_finding(
                    SERVICE,
                    vid,
                    "ec2_ebs_unencrypted",
                    rules,
                    fallback_issue="EBS volume is not encrypted.",
                )
            )
    except (ClientError, BotoCoreError):
        findings.append(
            build_finding(
                SERVICE,
                "account",
                "unable_validate_ec2_volumes",
                rules,
                fallback_issue="Unable to list EBS volumes for encryption check.",
            )
        )

    return deduplicate_findings(findings)
